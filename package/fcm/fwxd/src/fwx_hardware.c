// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FWX Hardware Detection & Security Profile
 * Auto-detect hardware capabilities and recommend security level
 * Copyright(c) 2026 FanchMWRT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <json-c/json.h>

#include "fwx_hardware.h"
#include "fwx.h"
#include "fwx_common.h"

/* 硬件信息缓存 */
static fwx_hardware_info_t hw_info = {0};
static int hw_info_cached = 0;

/* 安全档位定义 */
static const fwx_security_profile_t security_profiles[] = {
    [SECURITY_PROFILE_MINIMAL] = {
        .name = "minimal",
        .display_name = "最小防�?,
        .description = "仅基础防火墙，适合低端设备",
        .min_memory_mb = 64,
        .min_cpu_cores = 1,
        .features = {
            .threat_intel = 0,
            .ids_basic = 0,
            .ids_suricata = 0,
            .av_scan = 0,
            .traffic_analysis = 0
        }
    },
    [SECURITY_PROFILE_BASIC] = {
        .name = "basic",
        .display_name = "基础防护",
        .description = "威胁情报 + 轻量IDS",
        .min_memory_mb = 128,
        .min_cpu_cores = 1,
        .features = {
            .threat_intel = 1,
            .ids_basic = 1,
            .ids_suricata = 0,
            .av_scan = 0,
            .traffic_analysis = 0
        }
    },
    [SECURITY_PROFILE_STANDARD] = {
        .name = "standard",
        .display_name = "标准防护",
        .description = "威胁情报 + IDS + 流量分析",
        .min_memory_mb = 256,
        .min_cpu_cores = 2,
        .features = {
            .threat_intel = 1,
            .ids_basic = 1,
            .ids_suricata = 0,
            .av_scan = 0,
            .traffic_analysis = 1
        }
    },
    [SECURITY_PROFILE_ADVANCED] = {
        .name = "advanced",
        .display_name = "高级防护",
        .description = "全部功能 + 精简Suricata规则",
        .min_memory_mb = 512,
        .min_cpu_cores = 2,
        .features = {
            .threat_intel = 1,
            .ids_basic = 1,
            .ids_suricata = 1,  /* 精简规则模式 */
            .av_scan = 1,
            .traffic_analysis = 1
        }
    },
    [SECURITY_PROFILE_MAXIMUM] = {
        .name = "maximum",
        .display_name = "最大防�?,
        .description = "完整Suricata + 全部规则",
        .min_memory_mb = 1024,
        .min_cpu_cores = 4,
        .features = {
            .threat_intel = 1,
            .ids_basic = 1,
            .ids_suricata = 2,  /* 完整规则模式 */
            .av_scan = 1,
            .traffic_analysis = 1
        }
    }
};

/* 获取总内�?(MB) */
static int get_total_memory_mb(void)
{
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return 0;
    
    char line[128];
    int mem_kb = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "MemTotal: %d kB", &mem_kb) == 1) {
            break;
        }
    }
    fclose(fp);
    
    return mem_kb / 1024;
}

/* 获取可用内存 (MB) */
static int get_available_memory_mb(void)
{
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return 0;
    
    char line[128];
    int mem_available = 0;
    int mem_free = 0;
    int buffers = 0;
    int cached = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "MemAvailable: %d kB", &mem_available) == 1) {
            fclose(fp);
            return mem_available / 1024;
        }
        sscanf(line, "MemFree: %d kB", &mem_free);
        sscanf(line, "Buffers: %d kB", &buffers);
        sscanf(line, "Cached: %d kB", &cached);
    }
    fclose(fp);
    
    /* 旧内核没�?MemAvailable，手动计�?*/
    return (mem_free + buffers + cached) / 1024;
}

/* 获取CPU核心�?*/
static int get_cpu_cores(void)
{
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) return 1;
    
    char line[256];
    int cores = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "processor", 9) == 0) {
            cores++;
        }
    }
    fclose(fp);
    
    return cores > 0 ? cores : 1;
}

/* 获取CPU型号 */
static void get_cpu_model(char *buf, size_t len)
{
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        strncpy(buf, "Unknown", len);
        return;
    }
    
    char line[256];
    buf[0] = '\0';
    
    while (fgets(line, sizeof(line), fp)) {
        /* ARM: model name �?Hardware */
        if (strncmp(line, "model name", 10) == 0 ||
            strncmp(line, "Hardware", 8) == 0 ||
            strncmp(line, "system type", 11) == 0) {
            char *p = strchr(line, ':');
            if (p) {
                p++;
                while (*p == ' ' || *p == '\t') p++;
                strncpy(buf, p, len - 1);
                buf[len - 1] = '\0';
                /* 去掉换行 */
                char *nl = strchr(buf, '\n');
                if (nl) *nl = '\0';
                break;
            }
        }
    }
    fclose(fp);
    
    if (buf[0] == '\0') {
        strncpy(buf, "Unknown", len);
    }
}

/* 获取CPU频率 (MHz) */
static int get_cpu_freq_mhz(void)
{
    FILE *fp;
    int freq = 0;
    
    /* 尝试�?cpufreq 获取 */
    fp = fopen("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", "r");
    if (fp) {
        fscanf(fp, "%d", &freq);
        fclose(fp);
        return freq / 1000;  /* kHz -> MHz */
    }
    
    /* �?/proc/cpuinfo 获取 */
    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "cpu MHz", 7) == 0 ||
                strncmp(line, "BogoMIPS", 8) == 0) {
                char *p = strchr(line, ':');
                if (p) {
                    freq = (int)atof(p + 1);
                    break;
                }
            }
        }
        fclose(fp);
    }
    
    return freq > 0 ? freq : 0;
}

/* 检测硬件信�?*/
int fwx_hardware_detect(fwx_hardware_info_t *info)
{
    if (!info) return -1;
    
    info->memory_total_mb = get_total_memory_mb();
    info->memory_available_mb = get_available_memory_mb();
    info->cpu_cores = get_cpu_cores();
    info->cpu_freq_mhz = get_cpu_freq_mhz();
    get_cpu_model(info->cpu_model, sizeof(info->cpu_model));
    
    /* 缓存 */
    memcpy(&hw_info, info, sizeof(hw_info));
    hw_info_cached = 1;
    
    LOG_INFO("Hardware detected: %dMB RAM, %d cores, %s", 
             info->memory_total_mb, info->cpu_cores, info->cpu_model);
    
    return 0;
}

/* 获取缓存的硬件信�?*/
const fwx_hardware_info_t *fwx_hardware_get_info(void)
{
    if (!hw_info_cached) {
        fwx_hardware_detect(&hw_info);
    }
    return &hw_info;
}

/* 根据硬件推荐安全档位 */
security_profile_level_t fwx_hardware_recommend_profile(void)
{
    const fwx_hardware_info_t *hw = fwx_hardware_get_info();
    
    int mem = hw->memory_total_mb;
    int cores = hw->cpu_cores;
    
    /* 从高到低匹配 */
    if (mem >= 1024 && cores >= 4) {
        return SECURITY_PROFILE_MAXIMUM;
    }
    if (mem >= 512 && cores >= 2) {
        return SECURITY_PROFILE_ADVANCED;
    }
    if (mem >= 256 && cores >= 2) {
        return SECURITY_PROFILE_STANDARD;
    }
    if (mem >= 128) {
        return SECURITY_PROFILE_BASIC;
    }
    
    return SECURITY_PROFILE_MINIMAL;
}

/* 获取档位信息 */
const fwx_security_profile_t *fwx_get_security_profile(security_profile_level_t level)
{
    if (level < 0 || level >= SECURITY_PROFILE_MAX) {
        return NULL;
    }
    return &security_profiles[level];
}

/* 生成硬件信息JSON */
struct json_object *fwx_hardware_to_json(void)
{
    const fwx_hardware_info_t *hw = fwx_hardware_get_info();
    struct json_object *obj = json_object_new_object();
    
    JSON_ADD_INT(obj, "memory_total_mb", hw->memory_total_mb);
    JSON_ADD_INT(obj, "memory_available_mb", hw->memory_available_mb);
    JSON_ADD_INT(obj, "cpu_cores", hw->cpu_cores);
    JSON_ADD_INT(obj, "cpu_freq_mhz", hw->cpu_freq_mhz);
    JSON_ADD_STR(obj, "cpu_model", hw->cpu_model);
    
    return obj;
}

/* 生成安全档位JSON */
struct json_object *fwx_security_profile_to_json(security_profile_level_t level)
{
    const fwx_security_profile_t *profile = fwx_get_security_profile(level);
    if (!profile) return NULL;
    
    struct json_object *obj = json_object_new_object();
    
    JSON_ADD_INT(obj, "level", level);
    JSON_ADD_STR(obj, "name", profile->name);
    JSON_ADD_STR(obj, "display_name", profile->display_name);
    JSON_ADD_STR(obj, "description", profile->description);
    JSON_ADD_INT(obj, "min_memory_mb", profile->min_memory_mb);
    JSON_ADD_INT(obj, "min_cpu_cores", profile->min_cpu_cores);
    
    struct json_object *features = json_object_new_object();
    JSON_ADD_BOOL(features, "threat_intel", profile->features.threat_intel);
    JSON_ADD_BOOL(features, "ids_basic", profile->features.ids_basic);
    JSON_ADD_INT(features, "ids_suricata", profile->features.ids_suricata);
    JSON_ADD_BOOL(features, "av_scan", profile->features.av_scan);
    JSON_ADD_BOOL(features, "traffic_analysis", profile->features.traffic_analysis);
    
    JSON_ADD_OBJ(obj, "features", features);
    
    return obj;
}

/* 生成完整的档位推荐响�?*/
struct json_object *fwx_hardware_profile_response(void)
{
    struct json_object *resp = json_object_new_object();
    
    /* 硬件信息 */
    JSON_ADD_OBJ(resp, "hardware", fwx_hardware_to_json());
    
    /* 推荐档位 */
    security_profile_level_t recommended = fwx_hardware_recommend_profile();
    JSON_ADD_INT(resp, "recommended_level", recommended);
    JSON_ADD_OBJ(resp, "recommended", fwx_security_profile_to_json(recommended));
    
    /* 所有档位列�?*/
    struct json_object *profiles = json_object_new_array();
    for (int i = 0; i < SECURITY_PROFILE_MAX; i++) {
        struct json_object *p = fwx_security_profile_to_json(i);
        
        /* 标记是否满足硬件要求 */
        const fwx_hardware_info_t *hw = fwx_hardware_get_info();
        const fwx_security_profile_t *profile = fwx_get_security_profile(i);
        int meets_requirements = (hw->memory_total_mb >= profile->min_memory_mb &&
                                  hw->cpu_cores >= profile->min_cpu_cores);
        JSON_ADD_BOOL(p, "meets_requirements", meets_requirements);
        
        json_object_array_add(profiles, p);
    }
    JSON_ADD_OBJ(resp, "profiles", profiles);
    
    return resp;
}
