// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FWX Security UBUS Interface
 * Provides unified security module communication
 * Copyright(c) 2026 FanchMWRT <www.fanchmwrt.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "fwx.h"
#include "fwx_alert.h"
#include "fwx_security_ubus.h"
#include "fwx_hardware.h"
#include "fwx_common.h"

static struct blob_buf b;

/*
 * Handle security alert from other modules
 * Called by: fwx-ids, fwx-threat, fwx-av
 */
static int handle_alert(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg)
{
    char *msg_str = blobmsg_format_json(msg, true);
    if (!msg_str) {
        LOG_ERROR("Failed to parse alert message");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    
    struct json_object *req_obj = json_tokener_parse(msg_str);
    free(msg_str);
    
    if (!req_obj) {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    
    fwx_alert_t alert = {0};
    alert.timestamp = time(NULL);
    
    // Parse type
    struct json_object *type_obj = json_object_object_get(req_obj, "type");
    if (type_obj) {
        const char *type_str = json_object_get_string(type_obj);
        if (strcmp(type_str, "threat_ip") == 0) alert.type = ALERT_TYPE_THREAT_IP;
        else if (strcmp(type_str, "threat_domain") == 0) alert.type = ALERT_TYPE_THREAT_DOMAIN;
        else if (strcmp(type_str, "portscan") == 0) alert.type = ALERT_TYPE_PORTSCAN;
        else if (strcmp(type_str, "synflood") == 0) alert.type = ALERT_TYPE_SYNFLOOD;
        else if (strcmp(type_str, "bruteforce") == 0) alert.type = ALERT_TYPE_BRUTEFORCE;
        else if (strcmp(type_str, "malware") == 0) alert.type = ALERT_TYPE_MALWARE;
        else if (strcmp(type_str, "ids") == 0) alert.type = ALERT_TYPE_IDS;
        else alert.type = ALERT_TYPE_SYSTEM;
    }
    
    // Parse level
    struct json_object *level_obj = json_object_object_get(req_obj, "level");
    if (level_obj) {
        const char *level_str = json_object_get_string(level_obj);
        if (strcmp(level_str, "info") == 0) alert.level = ALERT_LEVEL_INFO;
        else if (strcmp(level_str, "warning") == 0) alert.level = ALERT_LEVEL_WARNING;
        else if (strcmp(level_str, "critical") == 0) alert.level = ALERT_LEVEL_CRITICAL;
        else if (strcmp(level_str, "emergency") == 0) alert.level = ALERT_LEVEL_EMERGENCY;
        else alert.level = ALERT_LEVEL_WARNING;
    } else {
        alert.level = ALERT_LEVEL_WARNING;
    }
    
    // Parse source
    struct json_object *src_obj = json_object_object_get(req_obj, "src");
    if (src_obj) {
        strncpy(alert.src_ip, json_object_get_string(src_obj), sizeof(alert.src_ip) - 1);
    }
    
    // Parse destination
    struct json_object *dst_obj = json_object_object_get(req_obj, "dst");
    if (dst_obj) {
        strncpy(alert.dst_ip, json_object_get_string(dst_obj), sizeof(alert.dst_ip) - 1);
    }
    
    // Parse detail
    struct json_object *detail_obj = json_object_object_get(req_obj, "detail");
    if (detail_obj) {
        strncpy(alert.detail, json_object_get_string(detail_obj), sizeof(alert.detail) - 1);
    }
    
    // Send alert
    fwx_alert_send(&alert);
    
    json_object_put(req_obj);
    
    // Response
    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "code", 0);
    blobmsg_add_string(&b, "message", "ok");
    ubus_send_reply(ctx, req, b.head);
    
    return 0;
}

/*
 * Get security status
 */
static int handle_security_status(struct ubus_context *ctx, struct ubus_object *obj,
                                  struct ubus_request_data *req, const char *method,
                                  struct blob_attr *msg)
{
    struct json_object *resp = json_object_new_object();
    
    // Check threat module
    int threat_running = (system("nft list table inet fwx_threat >/dev/null 2>&1") == 0);
    json_object_object_add(resp, "threat_intel", json_object_new_boolean(threat_running));
    
    // Check IDS module
    int ids_running = (system("nft list table inet fwx_ids >/dev/null 2>&1") == 0);
    json_object_object_add(resp, "ids", json_object_new_boolean(ids_running));
    
    // Check Suricata
    int suricata_running = (system("pidof suricata >/dev/null 2>&1") == 0);
    json_object_object_add(resp, "suricata", json_object_new_boolean(suricata_running));
    
    // Check ClamAV
    int clamav_installed = (access("/usr/bin/clamscan", X_OK) == 0);
    json_object_object_add(resp, "clamav_installed", json_object_new_boolean(clamav_installed));
    
    // Get alert stats
    struct json_object *stats = fwx_alert_stats();
    json_object_object_add(resp, "alert_stats", stats);
    
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, resp);
    ubus_send_reply(ctx, req, b.head);
    json_object_put(resp);
    
    return 0;
}

/*
 * Get recent alerts
 */
static int handle_get_alerts(struct ubus_context *ctx, struct ubus_object *obj,
                             struct ubus_request_data *req, const char *method,
                             struct blob_attr *msg)
{
    int count = 50;
    
    char *msg_str = blobmsg_format_json(msg, true);
    if (msg_str) {
        struct json_object *req_obj = json_tokener_parse(msg_str);
        if (req_obj) {
            struct json_object *count_obj = json_object_object_get(req_obj, "count");
            if (count_obj) {
                count = json_object_get_int(count_obj);
                if (count < 1) count = 50;
                if (count > 500) count = 500;
            }
            json_object_put(req_obj);
        }
        free(msg_str);
    }
    
    struct json_object *resp = json_object_new_object();
    struct json_object *alerts = fwx_alert_get_recent(count);
    json_object_object_add(resp, "alerts", alerts);
    
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, resp);
    ubus_send_reply(ctx, req, b.head);
    json_object_put(resp);
    
    return 0;
}

/*
 * Clear alerts
 */
static int handle_clear_alerts(struct ubus_context *ctx, struct ubus_object *obj,
                               struct ubus_request_data *req, const char *method,
                               struct blob_attr *msg)
{
    fwx_alert_clear();
    
    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "code", 0);
    blobmsg_add_string(&b, "message", "alerts cleared");
    ubus_send_reply(ctx, req, b.head);
    
    return 0;
}

/*
 * Trigger threat intel update
 */
static int handle_threat_update(struct ubus_context *ctx, struct ubus_object *obj,
                                struct ubus_request_data *req, const char *method,
                                struct blob_attr *msg)
{
    int ret = system("/usr/bin/fwx-threat-update update &");
    
    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "code", ret == 0 ? 0 : 1);
    blobmsg_add_string(&b, "message", ret == 0 ? "update started" : "update failed");
    ubus_send_reply(ctx, req, b.head);
    
    return 0;
}

/*
 * Get threat stats
 */
static int handle_threat_stats(struct ubus_context *ctx, struct ubus_object *obj,
                               struct ubus_request_data *req, const char *method,
                               struct blob_attr *msg)
{
    struct json_object *resp = json_object_new_object();
    
    // Count IP blacklist
    FILE *fp = fopen("/etc/fwx/threat/ip_blacklist.txt", "r");
    int ip_count = 0;
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (line[0] != '#' && line[0] != '\n') ip_count++;
        }
        fclose(fp);
    }
    json_object_object_add(resp, "ip_blacklist_count", json_object_new_int(ip_count));
    
    // Count domain blacklist
    fp = fopen("/etc/fwx/threat/domain_blacklist.txt", "r");
    int domain_count = 0;
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (line[0] != '#' && line[0] != '\n') domain_count++;
        }
        fclose(fp);
    }
    json_object_object_add(resp, "domain_blacklist_count", json_object_new_int(domain_count));
    
    // Get last update time
    struct stat st;
    if (stat("/etc/fwx/threat/ip_blacklist.txt", &st) == 0) {
        json_object_object_add(resp, "last_update", json_object_new_int64(st.st_mtime));
    }
    
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, resp);
    ubus_send_reply(ctx, req, b.head);
    json_object_put(resp);
    
    return 0;
}

/*
 * IDS control
 */
static int handle_ids_control(struct ubus_context *ctx, struct ubus_object *obj,
                              struct ubus_request_data *req, const char *method,
                              struct blob_attr *msg)
{
    char *msg_str = blobmsg_format_json(msg, true);
    if (!msg_str) {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    
    struct json_object *req_obj = json_tokener_parse(msg_str);
    free(msg_str);
    
    if (!req_obj) {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    
    int ret = -1;
    struct json_object *action_obj = json_object_object_get(req_obj, "action");
    if (action_obj) {
        const char *action = json_object_get_string(action_obj);
        
        if (strcmp(action, "start") == 0) {
            ret = system("/usr/bin/fwx-ids start");
        } else if (strcmp(action, "stop") == 0) {
            ret = system("/usr/bin/fwx-ids stop");
        } else if (strcmp(action, "restart") == 0) {
            ret = system("/usr/bin/fwx-ids restart");
        } else if (strcmp(action, "unblock") == 0) {
            struct json_object *ip_obj = json_object_object_get(req_obj, "ip");
            if (ip_obj) {
                char cmd[128];
                snprintf(cmd, sizeof(cmd), "/usr/bin/fwx-ids unblock %s", 
                         json_object_get_string(ip_obj));
                ret = system(cmd);
            }
        }
    }
    
    json_object_put(req_obj);
    
    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "code", ret == 0 ? 0 : 1);
    blobmsg_add_string(&b, "message", ret == 0 ? "ok" : "failed");
    ubus_send_reply(ctx, req, b.head);
    
    return 0;
}

/*
 * AV scan
 */
static int handle_av_scan(struct ubus_context *ctx, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg)
{
    char *msg_str = blobmsg_format_json(msg, true);
    if (!msg_str) {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    
    struct json_object *req_obj = json_tokener_parse(msg_str);
    free(msg_str);
    
    if (!req_obj) {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    
    int ret = -1;
    struct json_object *path_obj = json_object_object_get(req_obj, "path");
    if (path_obj) {
        const char *path = json_object_get_string(path_obj);
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "/usr/bin/fwx-av scan \"%s\" &", path);
        ret = system(cmd);
    }
    
    json_object_put(req_obj);
    
    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "code", ret == 0 ? 0 : 1);
    blobmsg_add_string(&b, "message", ret == 0 ? "scan started" : "scan failed");
    ubus_send_reply(ctx, req, b.head);
    
    return 0;
}

/*
 * AV status
 */
static int handle_av_status(struct ubus_context *ctx, struct ubus_object *obj,
                            struct ubus_request_data *req, const char *method,
                            struct blob_attr *msg)
{
    struct json_object *resp = json_object_new_object();
    
    // Check ClamAV installed
    int installed = (access("/usr/bin/clamscan", X_OK) == 0);
    json_object_object_add(resp, "installed", json_object_new_boolean(installed));
    
    // Check realtime monitoring
    int realtime = (access("/tmp/fwx-av-realtime.pids", F_OK) == 0);
    json_object_object_add(resp, "realtime_running", json_object_new_boolean(realtime));
    
    // Count quarantined files
    int quarantine_count = 0;
    FILE *fp = popen("ls -1 /etc/fwx/av/quarantine/*.infected 2>/dev/null | wc -l", "r");
    if (fp) {
        fscanf(fp, "%d", &quarantine_count);
        pclose(fp);
    }
    json_object_object_add(resp, "quarantine_count", json_object_new_int(quarantine_count));
    
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, resp);
    ubus_send_reply(ctx, req, b.head);
    json_object_put(resp);
    
    return 0;
}

/*
 * Get hardware info and recommended security profile
 */
static int handle_hardware_profile(struct ubus_context *ctx, struct ubus_object *obj,
                                   struct ubus_request_data *req, const char *method,
                                   struct blob_attr *msg)
{
    struct json_object *resp = fwx_hardware_profile_response();
    
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, resp);
    ubus_send_reply(ctx, req, b.head);
    json_object_put(resp);
    
    return 0;
}

/*
 * Apply security profile
 */
static int handle_apply_profile(struct ubus_context *ctx, struct ubus_object *obj,
                                struct ubus_request_data *req, const char *method,
                                struct blob_attr *msg)
{
    char *msg_str = blobmsg_format_json(msg, true);
    if (!msg_str) {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    
    struct json_object *req_obj = json_tokener_parse(msg_str);
    free(msg_str);
    
    if (!req_obj) {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    
    int level = -1;
    struct json_object *level_obj = json_object_object_get(req_obj, "level");
    if (level_obj) {
        level = json_object_get_int(level_obj);
    }
    
    json_object_put(req_obj);
    
    if (level < 0 || level >= SECURITY_PROFILE_MAX) {
        blob_buf_init(&b, 0);
        blobmsg_add_u32(&b, "code", 1);
        blobmsg_add_string(&b, "message", "invalid profile level");
        ubus_send_reply(ctx, req, b.head);
        return 0;
    }
    
    const fwx_security_profile_t *profile = fwx_get_security_profile(level);
    if (!profile) {
        blob_buf_init(&b, 0);
        blobmsg_add_u32(&b, "code", 1);
        blobmsg_add_string(&b, "message", "profile not found");
        ubus_send_reply(ctx, req, b.head);
        return 0;
    }
    
    /* 应用配置 */
    char cmd[512];
    
    /* 威胁情报 */
    snprintf(cmd, sizeof(cmd), "uci set threat_intel.global.enable=%d && uci commit threat_intel",
             profile->features.threat_intel);
    system(cmd);
    
    /* 基础IDS */
    snprintf(cmd, sizeof(cmd), "uci set fwx_ids.global.enable=%d && uci commit fwx_ids",
             profile->features.ids_basic);
    system(cmd);
    
    /* Suricata */
    snprintf(cmd, sizeof(cmd), "uci set fwx_suricata.global.enable=%d && uci commit fwx_suricata",
             profile->features.ids_suricata > 0 ? 1 : 0);
    system(cmd);
    
    /* 根据Suricata模式调整规则 */
    if (profile->features.ids_suricata == 1) {
        /* 精简模式：只启用关键规则 */
        system("uci set fwx_suricata.categories.policy=0");
        system("uci set fwx_suricata.performance.stream_memcap=16");
        system("uci set fwx_suricata.performance.flow_memcap=16");
        system("uci commit fwx_suricata");
    } else if (profile->features.ids_suricata == 2) {
        /* 完整模式 */
        system("uci set fwx_suricata.categories.policy=1");
        system("uci set fwx_suricata.performance.stream_memcap=64");
        system("uci set fwx_suricata.performance.flow_memcap=64");
        system("uci commit fwx_suricata");
    }
    
    /* 病毒扫描 */
    snprintf(cmd, sizeof(cmd), "uci set fwx_av.global.enable=%d && uci commit fwx_av",
             profile->features.av_scan);
    system(cmd);
    
    /* 流量分析 */
    snprintf(cmd, sizeof(cmd), "uci set fwx_traffic.global.enable=%d && uci commit fwx_traffic",
             profile->features.traffic_analysis);
    system(cmd);
    
    /* 保存当前档位 */
    snprintf(cmd, sizeof(cmd), "uci set fwx.security.profile=%s && uci commit fwx",
             profile->name);
    system(cmd);
    
    LOG_INFO("Applied security profile: %s", profile->name);
    
    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "code", 0);
    blobmsg_add_string(&b, "message", "profile applied");
    blobmsg_add_string(&b, "profile", profile->name);
    ubus_send_reply(ctx, req, b.head);
    
    return 0;
}

/* UBUS method definitions */
static const struct ubus_method fwx_security_methods[] = {
    UBUS_METHOD_NOARG("status", handle_security_status),
    UBUS_METHOD("alert", handle_alert, NULL),
    UBUS_METHOD("get_alerts", handle_get_alerts, NULL),
    UBUS_METHOD_NOARG("clear_alerts", handle_clear_alerts),
    UBUS_METHOD_NOARG("threat_update", handle_threat_update),
    UBUS_METHOD_NOARG("threat_stats", handle_threat_stats),
    UBUS_METHOD("ids_control", handle_ids_control, NULL),
    UBUS_METHOD("av_scan", handle_av_scan, NULL),
    UBUS_METHOD_NOARG("av_status", handle_av_status),
    UBUS_METHOD_NOARG("hardware_profile", handle_hardware_profile),
    UBUS_METHOD("apply_profile", handle_apply_profile, NULL),
};

static struct ubus_object_type fwx_security_object_type =
    UBUS_OBJECT_TYPE("fwx.security", fwx_security_methods);

static struct ubus_object fwx_security_object = {
    .name = "fwx.security",
    .type = &fwx_security_object_type,
    .methods = fwx_security_methods,
    .n_methods = ARRAY_SIZE(fwx_security_methods),
};

int fwx_security_ubus_init(struct ubus_context *ctx)
{
    int ret;
    
    ret = ubus_add_object(ctx, &fwx_security_object);
    if (ret) {
        LOG_ERROR("Failed to add fwx.security ubus object: %s", ubus_strerror(ret));
        return ret;
    }
    
    LOG_INFO("fwx.security ubus interface initialized");
    return 0;
}

void fwx_security_ubus_cleanup(void)
{
    LOG_INFO("fwx.security ubus interface cleanup");
}
