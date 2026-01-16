// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FWX Security Alert Module
 * Copyright(c) 2026 FanchMWRT <www.fanchmwrt.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include <libubus.h>

#include "fwx_alert.h"
#include "fwx.h"
#include "fwx_common.h"

static pthread_mutex_t alert_mutex = PTHREAD_MUTEX_INITIALIZER;
static int alert_count = 0;
static int alert_count_by_type[16] = {0};

/* 告警去重配置 */
#define DEDUP_WINDOW_SEC    60      /* 去重时间窗口�?0�?*/
#define DEDUP_HASH_SIZE     256     /* 哈希表大�?*/
#define MAX_DEDUP_ENTRIES   1024    /* 最大去重条�?*/

/* 去重条目 */
typedef struct dedup_entry {
    char key[128];              /* 去重�? src_ip + type */
    time_t first_seen;          /* 首次出现时间 */
    time_t last_seen;           /* 最后出现时�?*/
    int count;                  /* 重复次数 */
    alert_level_t max_level;    /* 最高告警级�?*/
    struct dedup_entry *next;   /* 链表下一�?*/
} dedup_entry_t;

/* 去重哈希�?*/
static dedup_entry_t *dedup_table[DEDUP_HASH_SIZE] = {0};
static int dedup_entry_count = 0;

/* 简单哈希函�?*/
static unsigned int hash_key(const char *key)
{
    unsigned int hash = 5381;
    int c;
    while ((c = *key++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % DEDUP_HASH_SIZE;
}

/* 生成去重�?*/
static void make_dedup_key(char *key, size_t len, const char *src_ip, alert_type_t type)
{
    snprintf(key, len, "%s:%d", src_ip, type);
}

/* 查找去重条目 */
static dedup_entry_t *find_dedup_entry(const char *key, unsigned int hash)
{
    dedup_entry_t *entry = dedup_table[hash];
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

/* 清理过期的去重条�?*/
static void cleanup_dedup_entries(time_t now)
{
    for (int i = 0; i < DEDUP_HASH_SIZE; i++) {
        dedup_entry_t **pp = &dedup_table[i];
        while (*pp) {
            if (now - (*pp)->last_seen > DEDUP_WINDOW_SEC * 2) {
                dedup_entry_t *old = *pp;
                *pp = old->next;
                free(old);
                dedup_entry_count--;
            } else {
                pp = &(*pp)->next;
            }
        }
    }
}

/* 检查是否重复告警，返回: 0=新告�? 1=重复(已更新计�?, 2=聚合告警(需要发送汇�? */
static int check_dedup(fwx_alert_t *alert, int *dup_count)
{
    char key[128];
    make_dedup_key(key, sizeof(key), alert->src_ip, alert->type);
    unsigned int hash = hash_key(key);
    time_t now = time(NULL);
    
    /* 定期清理 */
    static time_t last_cleanup = 0;
    if (now - last_cleanup > 300) {
        cleanup_dedup_entries(now);
        last_cleanup = now;
    }
    
    dedup_entry_t *entry = find_dedup_entry(key, hash);
    
    if (entry) {
        /* 检查是否在时间窗口�?*/
        if (now - entry->first_seen <= DEDUP_WINDOW_SEC) {
            entry->count++;
            entry->last_seen = now;
            if (alert->level > entry->max_level) {
                entry->max_level = alert->level;
            }
            *dup_count = entry->count;
            
            /* �?0次重复发送一次聚合告�?*/
            if (entry->count % 10 == 0) {
                return 2;  /* 发送聚合告�?*/
            }
            return 1;  /* 重复，静�?*/
        } else {
            /* 时间窗口已过，重�?*/
            entry->first_seen = now;
            entry->last_seen = now;
            entry->count = 1;
            entry->max_level = alert->level;
            *dup_count = 1;
            return 0;  /* 新告�?*/
        }
    }
    
    /* 新条�?*/
    if (dedup_entry_count >= MAX_DEDUP_ENTRIES) {
        cleanup_dedup_entries(now);
    }
    
    entry = calloc(1, sizeof(dedup_entry_t));
    if (!entry) {
        *dup_count = 1;
        return 0;
    }
    
    strncpy(entry->key, key, sizeof(entry->key) - 1);
    entry->first_seen = now;
    entry->last_seen = now;
    entry->count = 1;
    entry->max_level = alert->level;
    entry->next = dedup_table[hash];
    dedup_table[hash] = entry;
    dedup_entry_count++;
    
    *dup_count = 1;
    return 0;  /* 新告�?*/
}

static const char *alert_type_str[] = {
    "unknown",
    "threat_ip",
    "threat_domain", 
    "portscan",
    "synflood",
    "bruteforce",
    "malware",
    "ids",
    "system"
};

static const char *alert_level_str[] = {
    "info",
    "warning",
    "critical",
    "emergency"
};

int fwx_alert_init(void)
{
    LOG_INFO("Alert system initialized");
    return 0;
}

void fwx_alert_cleanup(void)
{
    pthread_mutex_lock(&alert_mutex);
    
    /* 释放去重�?*/
    for (int i = 0; i < DEDUP_HASH_SIZE; i++) {
        dedup_entry_t *entry = dedup_table[i];
        while (entry) {
            dedup_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
        dedup_table[i] = NULL;
    }
    dedup_entry_count = 0;
    
    pthread_mutex_unlock(&alert_mutex);
    
    LOG_INFO("Alert system cleanup");
}

int fwx_alert_log(fwx_alert_t *alert)
{
    FILE *fp;
    struct stat st;
    char time_str[32];
    struct tm *tm_info;
    
    if (!alert) return -1;
    
    pthread_mutex_lock(&alert_mutex);
    
    // Check log file size, rotate if needed
    if (stat(FWX_ALERT_LOG_PATH, &st) == 0) {
        if (st.st_size > FWX_ALERT_MAX_SIZE) {
            char backup[256];
            snprintf(backup, sizeof(backup), "%s.1", FWX_ALERT_LOG_PATH);
            rename(FWX_ALERT_LOG_PATH, backup);
        }
    }
    
    fp = fopen(FWX_ALERT_LOG_PATH, "a");
    if (!fp) {
        pthread_mutex_unlock(&alert_mutex);
        return -1;
    }
    
    tm_info = localtime(&alert->timestamp);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(fp, "[%s] [%s] [%s] src=%s:%d dst=%s:%d %s\n",
            time_str,
            alert_level_str[alert->level],
            alert_type_str[alert->type],
            alert->src_ip,
            alert->src_port,
            alert->dst_ip,
            alert->dst_port,
            alert->detail);
    
    fclose(fp);
    
    alert_count++;
    if (alert->type < 16) {
        alert_count_by_type[alert->type]++;
    }
    
    pthread_mutex_unlock(&alert_mutex);
    
    return 0;
}

int fwx_alert_send(fwx_alert_t *alert)
{
    if (!alert) return -1;
    
    alert->timestamp = time(NULL);
    
    pthread_mutex_lock(&alert_mutex);
    
    /* 去重检�?*/
    int dup_count = 0;
    int dedup_result = check_dedup(alert, &dup_count);
    
    if (dedup_result == 1) {
        /* 重复告警，静默处理，只更新计�?*/
        pthread_mutex_unlock(&alert_mutex);
        LOG_DEBUG("Suppressed duplicate alert: %s from %s (count: %d)",
                  alert_type_str[alert->type], alert->src_ip, dup_count);
        return 0;
    }
    
    /* 如果是聚合告警，修改详情 */
    char original_detail[256];
    if (dedup_result == 2) {
        strncpy(original_detail, alert->detail, sizeof(original_detail) - 1);
        snprintf(alert->detail, sizeof(alert->detail), 
                 "[AGGREGATED x%d] %s", dup_count, original_detail);
    }
    
    pthread_mutex_unlock(&alert_mutex);
    
    /* 记录到日�?*/
    fwx_alert_log(alert);
    
    /* 记录到系统日�?*/
    LOG_WARN("Security Alert: type=%s level=%s src=%s detail=%s",
             alert_type_str[alert->type],
             alert_level_str[alert->level],
             alert->src_ip,
             alert->detail);
    
    /* 触发通知（如果配置了�?*/
    if (dedup_result == 0 || dedup_result == 2) {
        /* 只有新告警或聚合告警才发送通知 */
        char cmd[512];
        snprintf(cmd, sizeof(cmd), 
                 "/usr/bin/fwx-notify send %s %s %s %s \"%s\" &",
                 alert_level_str[alert->level],
                 alert_type_str[alert->type],
                 alert->src_ip,
                 alert->dst_ip[0] ? alert->dst_ip : "-",
                 alert->detail);
        system(cmd);
    }
    
    return 0;
}

struct json_object *fwx_alert_get_recent(int count)
{
    struct json_object *arr = json_object_new_array();
    FILE *fp;
    char line[512];
    char *lines[100];
    int total = 0;
    int i;
    
    if (count > 100) count = 100;
    
    fp = fopen(FWX_ALERT_LOG_PATH, "r");
    if (!fp) return arr;
    
    while (fgets(line, sizeof(line), fp) && total < 100) {
        lines[total] = strdup(line);
        total++;
    }
    fclose(fp);
    
    int start = (total > count) ? (total - count) : 0;
    for (i = start; i < total; i++) {
        struct json_object *obj = json_object_new_object();
        JSON_ADD_STR(obj, "raw", lines[i]);
        json_object_array_add(arr, obj);
    }
    
    for (i = 0; i < total; i++) {
        free(lines[i]);
    }
    
    return arr;
}

struct json_object *fwx_alert_stats(void)
{
    struct json_object *obj = json_object_new_object();
    struct json_object *by_type = json_object_new_object();
    int i;
    
    pthread_mutex_lock(&alert_mutex);
    
    JSON_ADD_INT(obj, "total", alert_count);
    
    for (i = 1; i < 9; i++) {
        JSON_ADD_INT(by_type, alert_type_str[i], alert_count_by_type[i]);
    }
    JSON_ADD_OBJ(obj, "by_type", by_type);
    
    pthread_mutex_unlock(&alert_mutex);
    
    return obj;
}

int fwx_alert_clear(void)
{
    pthread_mutex_lock(&alert_mutex);
    
    unlink(FWX_ALERT_LOG_PATH);
    alert_count = 0;
    memset(alert_count_by_type, 0, sizeof(alert_count_by_type));
    
    pthread_mutex_unlock(&alert_mutex);
    
    LOG_INFO("Alerts cleared");
    return 0;
}
