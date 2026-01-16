// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FWX Device Profile - Terminal Fingerprinting Implementation
 * Copyright(c) 2026 FanchMWRT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <json-c/json.h>

#include "fwx_device_profile.h"
#include "fwx_common.h"

#define MAX_DEVICE_PROFILES 256
#define OUI_HASH_SIZE 4096
#define PROFILE_SAVE_PATH "/etc/fwx/device_profiles.json"
#define OUI_DB_PATH "/etc/fwx/oui.txt"

/* OUI 数据库条�?*/
typedef struct oui_entry {
    uint32_t oui;                       /* �?字节 MAC */
    char vendor[MAX_VENDOR_NAME_LEN];
    struct oui_entry *next;
} oui_entry_t;

/* 全局数据 */
static device_profile_t *g_profiles[MAX_DEVICE_PROFILES];
static int g_profile_count = 0;
static pthread_rwlock_t g_profile_lock = PTHREAD_RWLOCK_INITIALIZER;
static oui_entry_t *g_oui_hash[OUI_HASH_SIZE];
static int g_oui_loaded = 0;

/* 设备类型字符�?*/
static const char *device_type_names[] = {
    [DEV_TYPE_UNKNOWN] = "unknown",
    [DEV_TYPE_PHONE] = "phone",
    [DEV_TYPE_TABLET] = "tablet",
    [DEV_TYPE_PC] = "pc",
    [DEV_TYPE_LAPTOP] = "laptop",
    [DEV_TYPE_TV] = "tv",
    [DEV_TYPE_IOT] = "iot",
    [DEV_TYPE_GAME_CONSOLE] = "game_console",
    [DEV_TYPE_CAMERA] = "camera",
    [DEV_TYPE_PRINTER] = "printer",
    [DEV_TYPE_ROUTER] = "router",
    [DEV_TYPE_NAS] = "nas",
    [DEV_TYPE_WEARABLE] = "wearable"
};

/* 操作系统类型字符�?*/
static const char *os_type_names[] = {
    [OS_TYPE_UNKNOWN] = "unknown",
    [OS_TYPE_WINDOWS] = "Windows",
    [OS_TYPE_MACOS] = "macOS",
    [OS_TYPE_LINUX] = "Linux",
    [OS_TYPE_ANDROID] = "Android",
    [OS_TYPE_IOS] = "iOS",
    [OS_TYPE_CHROMEOS] = "ChromeOS",
    [OS_TYPE_TVOS] = "tvOS",
    [OS_TYPE_EMBEDDED] = "Embedded"
};

const char *fwx_device_type_str(device_type_t type) {
    if (type >= DEV_TYPE_MAX) return "unknown";
    return device_type_names[type];
}

const char *fwx_os_type_str(os_type_t type) {
    if (type >= OS_TYPE_MAX) return "unknown";
    return os_type_names[type];
}

/* MAC �?OUI 整数 */
static uint32_t mac_to_oui(const char *mac) {
    unsigned int a, b, c;
    if (sscanf(mac, "%02x:%02x:%02x", &a, &b, &c) == 3 ||
        sscanf(mac, "%02X:%02X:%02X", &a, &b, &c) == 3) {
        return (a << 16) | (b << 8) | c;
    }
    return 0;
}

/* OUI 哈希函数 */
static unsigned int oui_hash(uint32_t oui) {
    return oui % OUI_HASH_SIZE;
}

/* 加载 OUI 数据�?*/
int fwx_load_oui_database(const char *path) {
    FILE *fp = fopen(path ? path : OUI_DB_PATH, "r");
    if (!fp) return -1;
    
    char line[256];
    int count = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        /* 格式: AA:BB:CC<tab>Vendor Name */
        char oui_str[16], vendor[MAX_VENDOR_NAME_LEN];
        if (sscanf(line, "%15s\t%63[^\n]", oui_str, vendor) == 2) {
            uint32_t oui = mac_to_oui(oui_str);
            if (oui == 0) continue;
            
            oui_entry_t *entry = calloc(1, sizeof(oui_entry_t));
            if (!entry) continue;
            
            entry->oui = oui;
            strncpy(entry->vendor, vendor, MAX_VENDOR_NAME_LEN - 1);
            
            unsigned int idx = oui_hash(oui);
            entry->next = g_oui_hash[idx];
            g_oui_hash[idx] = entry;
            count++;
        }
    }
    
    fclose(fp);
    g_oui_loaded = 1;
    LOG_INFO("Loaded %d OUI entries", count);
    return count;
}

/* 查询 MAC 厂商 */
int fwx_lookup_mac_vendor(const char *mac, mac_vendor_info_t *vendor) {
    if (!mac || !vendor) return -1;
    
    memset(vendor, 0, sizeof(*vendor));
    
    if (!g_oui_loaded) {
        fwx_load_oui_database(NULL);
    }
    
    uint32_t oui = mac_to_oui(mac);
    if (oui == 0) return -1;
    
    unsigned int idx = oui_hash(oui);
    oui_entry_t *entry = g_oui_hash[idx];
    
    while (entry) {
        if (entry->oui == oui) {
            strncpy(vendor->vendor_name, entry->vendor, MAX_VENDOR_NAME_LEN - 1);
            vendor->is_known = 1;
            
            /* 生成简�?*/
            char *p = vendor->vendor_name;
            int i = 0;
            while (*p && i < 15) {
                if (isupper(*p)) vendor->vendor_short[i++] = *p;
                p++;
            }
            if (i == 0) strncpy(vendor->vendor_short, vendor->vendor_name, 15);
            
            return 0;
        }
        entry = entry->next;
    }
    
    strcpy(vendor->vendor_name, "Unknown");
    vendor->is_known = 0;
    return -1;
}

/* TCP 指纹分析 - 基于 TTL 和窗口大小推�?OS */
int fwx_analyze_tcp_fingerprint(const tcp_fingerprint_t *fp,
                                 os_type_t *os, device_type_t *dev) {
    if (!fp || !os || !dev) return -1;
    
    *os = OS_TYPE_UNKNOWN;
    *dev = DEV_TYPE_UNKNOWN;
    
    /* 基于 TTL 初步判断 */
    if (fp->ttl >= 128 && fp->ttl <= 130) {
        /* Windows 默认 TTL=128 */
        *os = OS_TYPE_WINDOWS;
        *dev = DEV_TYPE_PC;
    } else if (fp->ttl >= 64 && fp->ttl <= 66) {
        /* Linux/macOS/iOS/Android 默认 TTL=64 */
        if (fp->window_size >= 65535) {
            *os = OS_TYPE_MACOS;
            *dev = DEV_TYPE_LAPTOP;
        } else if (fp->window_size >= 29200 && fp->window_size <= 29400) {
            *os = OS_TYPE_LINUX;
            *dev = DEV_TYPE_PC;
        } else if (fp->window_size >= 14600 && fp->window_size <= 14800) {
            /* Android 常见窗口大小 */
            *os = OS_TYPE_ANDROID;
            *dev = DEV_TYPE_PHONE;
        } else if (fp->window_size >= 4096 && fp->window_size <= 8192) {
            /* iOS 常见窗口大小 */
            *os = OS_TYPE_IOS;
            *dev = DEV_TYPE_PHONE;
        }
    } else if (fp->ttl >= 255) {
        /* 网络设备 */
        *os = OS_TYPE_EMBEDDED;
        *dev = DEV_TYPE_ROUTER;
    }
    
    /* 基于 MSS 细化判断 */
    if (fp->mss == 1460) {
        /* 标准以太�?MSS */
    } else if (fp->mss == 1360 || fp->mss == 1400) {
        /* 可能�?VPN 或移动网�?*/
        if (*dev == DEV_TYPE_UNKNOWN) *dev = DEV_TYPE_PHONE;
    }
    
    return (*os != OS_TYPE_UNKNOWN) ? 0 : -1;
}

/* User-Agent 解析 */
int fwx_parse_user_agent(const char *ua, ua_info_t *info) {
    if (!ua || !info) return -1;
    
    memset(info, 0, sizeof(*info));
    info->last_seen = time(NULL);
    
    /* 检测移动设�?*/
    if (strstr(ua, "Mobile") || strstr(ua, "Android") || 
        strstr(ua, "iPhone") || strstr(ua, "iPad")) {
        info->is_mobile = 1;
    }
    
    /* 检测爬�?*/
    if (strstr(ua, "bot") || strstr(ua, "Bot") || 
        strstr(ua, "spider") || strstr(ua, "crawl")) {
        info->is_bot = 1;
    }
    
    /* 操作系统识别 */
    if (strstr(ua, "Windows NT 10")) {
        info->os_type = OS_TYPE_WINDOWS;
        strcpy(info->os_version, "10/11");
        info->device_type = DEV_TYPE_PC;
    } else if (strstr(ua, "Windows NT 6.3")) {
        info->os_type = OS_TYPE_WINDOWS;
        strcpy(info->os_version, "8.1");
        info->device_type = DEV_TYPE_PC;
    } else if (strstr(ua, "Windows NT 6.1")) {
        info->os_type = OS_TYPE_WINDOWS;
        strcpy(info->os_version, "7");
        info->device_type = DEV_TYPE_PC;
    } else if (strstr(ua, "Mac OS X")) {
        info->os_type = OS_TYPE_MACOS;
        info->device_type = DEV_TYPE_LAPTOP;
        /* 提取版本 */
        const char *ver = strstr(ua, "Mac OS X ");
        if (ver) {
            sscanf(ver + 9, "%31[0-9_.]", info->os_version);
            /* 将下划线替换为点 */
            for (char *p = info->os_version; *p; p++) {
                if (*p == '_') *p = '.';
            }
        }
    } else if (strstr(ua, "Android")) {
        info->os_type = OS_TYPE_ANDROID;
        info->device_type = DEV_TYPE_PHONE;
        const char *ver = strstr(ua, "Android ");
        if (ver) sscanf(ver + 8, "%31[0-9.]", info->os_version);
        
        /* 检测平�?*/
        if (!strstr(ua, "Mobile")) {
            info->device_type = DEV_TYPE_TABLET;
        }
    } else if (strstr(ua, "iPhone") || strstr(ua, "iPad")) {
        info->os_type = OS_TYPE_IOS;
        info->device_type = strstr(ua, "iPad") ? DEV_TYPE_TABLET : DEV_TYPE_PHONE;
        const char *ver = strstr(ua, "OS ");
        if (ver) {
            sscanf(ver + 3, "%31[0-9_]", info->os_version);
            for (char *p = info->os_version; *p; p++) {
                if (*p == '_') *p = '.';
            }
        }
    } else if (strstr(ua, "Linux")) {
        info->os_type = OS_TYPE_LINUX;
        info->device_type = DEV_TYPE_PC;
    } else if (strstr(ua, "CrOS")) {
        info->os_type = OS_TYPE_CHROMEOS;
        info->device_type = DEV_TYPE_LAPTOP;
    }
    
    /* 浏览器识�?*/
    if (strstr(ua, "Edg/")) {
        strcpy(info->browser, "Edge");
    } else if (strstr(ua, "Chrome/")) {
        strcpy(info->browser, "Chrome");
    } else if (strstr(ua, "Firefox/")) {
        strcpy(info->browser, "Firefox");
    } else if (strstr(ua, "Safari/") && !strstr(ua, "Chrome")) {
        strcpy(info->browser, "Safari");
    } else if (strstr(ua, "MSIE") || strstr(ua, "Trident")) {
        strcpy(info->browser, "IE");
    }
    
    /* 设备型号提取 (Android) */
    if (info->os_type == OS_TYPE_ANDROID) {
        const char *build = strstr(ua, "Build/");
        if (build) {
            const char *model_start = build;
            while (model_start > ua && *(model_start - 1) != ';') model_start--;
            while (*model_start == ' ') model_start++;
            
            int len = build - model_start;
            if (len > 0 && len < MAX_MODEL_NAME_LEN) {
                strncpy(info->device_model, model_start, len);
                info->device_model[len] = '\0';
                /* 去除尾部空格 */
                char *end = info->device_model + strlen(info->device_model) - 1;
                while (end > info->device_model && *end == ' ') *end-- = '\0';
            }
        }
    }
    
    return 0;
}

/* DHCP 指纹分析 */
int fwx_analyze_dhcp_fingerprint(const dhcp_fingerprint_t *fp,
                                  os_type_t *os, device_type_t *dev) {
    if (!fp || !os || !dev) return -1;
    
    *os = OS_TYPE_UNKNOWN;
    *dev = DEV_TYPE_UNKNOWN;
    
    /* 基于 hostname 模式判断 */
    const char *hostname = fp->hostname_pattern;
    if (hostname[0]) {
        /* Android 设备通常�?android- 开�?*/
        if (strncasecmp(hostname, "android-", 8) == 0) {
            *os = OS_TYPE_ANDROID;
            *dev = DEV_TYPE_PHONE;
        }
        /* iPhone/iPad */
        else if (strncasecmp(hostname, "iPhone", 6) == 0 ||
                 strncasecmp(hostname, "iPad", 4) == 0) {
            *os = OS_TYPE_IOS;
            *dev = strncasecmp(hostname, "iPad", 4) == 0 ? DEV_TYPE_TABLET : DEV_TYPE_PHONE;
        }
        /* Windows 设备通常�?DESKTOP- �?LAPTOP- */
        else if (strncasecmp(hostname, "DESKTOP-", 8) == 0) {
            *os = OS_TYPE_WINDOWS;
            *dev = DEV_TYPE_PC;
        }
        else if (strncasecmp(hostname, "LAPTOP-", 7) == 0) {
            *os = OS_TYPE_WINDOWS;
            *dev = DEV_TYPE_LAPTOP;
        }
        /* MacBook */
        else if (strstr(hostname, "MacBook") || strstr(hostname, "macbook")) {
            *os = OS_TYPE_MACOS;
            *dev = DEV_TYPE_LAPTOP;
        }
        /* iMac */
        else if (strstr(hostname, "iMac") || strstr(hostname, "imac")) {
            *os = OS_TYPE_MACOS;
            *dev = DEV_TYPE_PC;
        }
    }
    
    /* 基于 Vendor Class ID 判断 */
    if (fp->vendor_class[0]) {
        if (strstr(fp->vendor_class, "MSFT")) {
            *os = OS_TYPE_WINDOWS;
            if (*dev == DEV_TYPE_UNKNOWN) *dev = DEV_TYPE_PC;
        }
        else if (strstr(fp->vendor_class, "dhcpcd")) {
            /* Linux dhcpcd 客户�?*/
            if (*os == OS_TYPE_UNKNOWN) *os = OS_TYPE_LINUX;
        }
    }
    
    return (*os != OS_TYPE_UNKNOWN) ? 0 : -1;
}

/* 查找设备画像 */
device_profile_t *fwx_get_device_profile(const char *mac) {
    if (!mac) return NULL;
    
    pthread_rwlock_rdlock(&g_profile_lock);
    
    for (int i = 0; i < g_profile_count; i++) {
        if (g_profiles[i] && strcasecmp(g_profiles[i]->mac, mac) == 0) {
            pthread_rwlock_unlock(&g_profile_lock);
            return g_profiles[i];
        }
    }
    
    pthread_rwlock_unlock(&g_profile_lock);
    return NULL;
}

/* 创建设备画像 */
device_profile_t *fwx_create_device_profile(const char *mac) {
    if (!mac) return NULL;
    
    /* 先检查是否已存在 */
    device_profile_t *existing = fwx_get_device_profile(mac);
    if (existing) return existing;
    
    pthread_rwlock_wrlock(&g_profile_lock);
    
    if (g_profile_count >= MAX_DEVICE_PROFILES) {
        pthread_rwlock_unlock(&g_profile_lock);
        LOG_WARN("Device profile limit reached");
        return NULL;
    }
    
    device_profile_t *profile = calloc(1, sizeof(device_profile_t));
    if (!profile) {
        pthread_rwlock_unlock(&g_profile_lock);
        return NULL;
    }
    
    strncpy(profile->mac, mac, sizeof(profile->mac) - 1);
    profile->created_at = time(NULL);
    profile->updated_at = profile->created_at;
    profile->behavior.first_seen = profile->created_at;
    profile->profile_version = 1;
    
    /* 查询 MAC 厂商 */
    fwx_lookup_mac_vendor(mac, &profile->vendor);
    
    g_profiles[g_profile_count++] = profile;
    
    pthread_rwlock_unlock(&g_profile_lock);
    
    LOG_DEBUG("Created device profile for %s (vendor: %s)", 
              mac, profile->vendor.vendor_name);
    
    return profile;
}

/* �?User-Agent 更新设备画像 */
int fwx_update_device_from_ua(const char *mac, const char *user_agent) {
    if (!mac || !user_agent) return -1;
    
    device_profile_t *profile = fwx_get_device_profile(mac);
    if (!profile) {
        profile = fwx_create_device_profile(mac);
        if (!profile) return -1;
    }
    
    ua_info_t ua_info;
    if (fwx_parse_user_agent(user_agent, &ua_info) != 0) {
        return -1;
    }
    
    pthread_rwlock_wrlock(&g_profile_lock);
    
    /* 更新 UA 信息 */
    memcpy(&profile->ua_info, &ua_info, sizeof(ua_info));
    
    /* 如果 UA 提供了更高置信度的信息，更新主画�?*/
    if (ua_info.os_type != OS_TYPE_UNKNOWN) {
        if (profile->os_type == OS_TYPE_UNKNOWN || 
            profile->confidence < CONFIDENCE_HIGH) {
            profile->os_type = ua_info.os_type;
            strncpy(profile->os_version, ua_info.os_version, 
                    sizeof(profile->os_version) - 1);
        }
    }
    
    if (ua_info.device_type != DEV_TYPE_UNKNOWN) {
        if (profile->device_type == DEV_TYPE_UNKNOWN ||
            profile->confidence < CONFIDENCE_HIGH) {
            profile->device_type = ua_info.device_type;
        }
    }
    
    if (ua_info.device_model[0] && !profile->device_model[0]) {
        strncpy(profile->device_model, ua_info.device_model,
                sizeof(profile->device_model) - 1);
    }
    
    /* 更新置信�?*/
    if (profile->confidence < CONFIDENCE_HIGH) {
        profile->confidence = CONFIDENCE_HIGH;
    }
    
    profile->updated_at = time(NULL);
    
    pthread_rwlock_unlock(&g_profile_lock);
    
    return 0;
}

/* �?TCP 指纹更新设备画像 */
int fwx_update_device_from_tcp(const char *mac, const tcp_fingerprint_t *fp) {
    if (!mac || !fp) return -1;
    
    device_profile_t *profile = fwx_get_device_profile(mac);
    if (!profile) {
        profile = fwx_create_device_profile(mac);
        if (!profile) return -1;
    }
    
    os_type_t os;
    device_type_t dev;
    
    if (fwx_analyze_tcp_fingerprint(fp, &os, &dev) != 0) {
        return -1;
    }
    
    pthread_rwlock_wrlock(&g_profile_lock);
    
    /* 保存 TCP 指纹 */
    memcpy(&profile->tcp_fp, fp, sizeof(*fp));
    
    /* 如果当前没有更高置信度的信息，使�?TCP 指纹结果 */
    if (profile->os_type == OS_TYPE_UNKNOWN) {
        profile->os_type = os;
        profile->confidence = CONFIDENCE_MEDIUM;
    }
    
    if (profile->device_type == DEV_TYPE_UNKNOWN) {
        profile->device_type = dev;
    }
    
    profile->updated_at = time(NULL);
    
    pthread_rwlock_unlock(&g_profile_lock);
    
    return 0;
}

/* 更新行为画像 */
int fwx_update_behavior_profile(const char *mac, int app_type, uint32_t duration) {
    if (!mac) return -1;
    
    device_profile_t *profile = fwx_get_device_profile(mac);
    if (!profile) return -1;
    
    pthread_rwlock_wrlock(&g_profile_lock);
    
    behavior_profile_t *bp = &profile->behavior;
    
    /* 更新当前小时活跃�?*/
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    bp->hourly_activity[tm->tm_hour]++;
    
    /* 更新应用类型使用时长 */
    if (app_type >= 0 && app_type < 16) {
        bp->app_type_time[app_type] += duration / 60;  /* 转换为分�?*/
    }
    
    bp->last_updated = now;
    profile->updated_at = now;
    
    pthread_rwlock_unlock(&g_profile_lock);
    
    return 0;
}

/* 计算风险评分 */
int fwx_calculate_risk_score(device_profile_t *profile) {
    if (!profile) return -1;
    
    int score = 0;
    behavior_profile_t *bp = &profile->behavior;
    
    /* 被阻止次�?*/
    if (bp->blocked_count > 100) score += 30;
    else if (bp->blocked_count > 50) score += 20;
    else if (bp->blocked_count > 10) score += 10;
    
    /* 威胁命中 */
    if (bp->threat_hits > 10) score += 40;
    else if (bp->threat_hits > 5) score += 25;
    else if (bp->threat_hits > 0) score += 10;
    
    /* 未知设备类型 */
    if (profile->device_type == DEV_TYPE_UNKNOWN) score += 10;
    
    /* 未知厂商 */
    if (!profile->vendor.is_known) score += 5;
    
    /* 异常活跃时段 (凌晨2-5点高活跃) */
    uint32_t night_activity = bp->hourly_activity[2] + bp->hourly_activity[3] + 
                              bp->hourly_activity[4] + bp->hourly_activity[5];
    uint32_t total_activity = 0;
    for (int i = 0; i < 24; i++) total_activity += bp->hourly_activity[i];
    
    if (total_activity > 0 && night_activity * 100 / total_activity > 30) {
        score += 15;
    }
    
    /* 限制�?0-100 */
    if (score > 100) score = 100;
    
    bp->risk_score = score;
    return score;
}

/* 设备画像�?JSON */
struct json_object *fwx_device_profile_to_json(const device_profile_t *profile) {
    if (!profile) return NULL;
    
    struct json_object *obj = json_object_new_object();
    
    /* 基础信息 */
    JSON_ADD_STR(obj, "mac", profile->mac);
    JSON_ADD_STR(obj, "ip", profile->ip);
    
    /* 设备识别 */
    JSON_ADD_STR(obj, "device_type", fwx_device_type_str(profile->device_type));
    JSON_ADD_STR(obj, "os_type", fwx_os_type_str(profile->os_type));
    JSON_ADD_STR(obj, "os_version", profile->os_version);
    JSON_ADD_STR(obj, "device_model", profile->device_model);
    JSON_ADD_INT(obj, "confidence", profile->confidence);
    
    /* 厂商信息 */
    struct json_object *vendor_obj = json_object_new_object();
    JSON_ADD_STR(vendor_obj, "name", profile->vendor.vendor_name);
    JSON_ADD_STR(vendor_obj, "short", profile->vendor.vendor_short);
    JSON_ADD_BOOL(vendor_obj, "known", profile->vendor.is_known);
    JSON_ADD_OBJ(obj, "vendor", vendor_obj);
    
    /* UA 信息 */
    if (profile->ua_info.browser[0]) {
        struct json_object *ua_obj = json_object_new_object();
        JSON_ADD_STR(ua_obj, "browser", profile->ua_info.browser);
        JSON_ADD_BOOL(ua_obj, "is_mobile", profile->ua_info.is_mobile);
        JSON_ADD_INT64(ua_obj, "last_seen", profile->ua_info.last_seen);
        JSON_ADD_OBJ(obj, "user_agent", ua_obj);
    }
    
    /* 行为画像 */
    struct json_object *behavior_obj = json_object_new_object();
    
    /* 活跃时段 */
    struct json_object *hourly_arr = json_object_new_array();
    for (int i = 0; i < 24; i++) {
        json_object_array_add(hourly_arr, json_object_new_int(profile->behavior.hourly_activity[i]));
    }
    JSON_ADD_OBJ(behavior_obj, "hourly_activity", hourly_arr);
    
    /* 应用使用 */
    struct json_object *app_time_arr = json_object_new_array();
    for (int i = 0; i < 16; i++) {
        json_object_array_add(app_time_arr, json_object_new_int(profile->behavior.app_type_time[i]));
    }
    JSON_ADD_OBJ(behavior_obj, "app_type_time", app_time_arr);
    
    /* 风险指标 */
    JSON_ADD_INT(behavior_obj, "blocked_count", profile->behavior.blocked_count);
    JSON_ADD_INT(behavior_obj, "threat_hits", profile->behavior.threat_hits);
    JSON_ADD_INT(behavior_obj, "risk_score", profile->behavior.risk_score);
    JSON_ADD_INT64(behavior_obj, "first_seen", profile->behavior.first_seen);
    
    JSON_ADD_OBJ(obj, "behavior", behavior_obj);
    
    /* 时间�?*/
    JSON_ADD_INT64(obj, "created_at", profile->created_at);
    JSON_ADD_INT64(obj, "updated_at", profile->updated_at);
    
    return obj;
}

/* 获取所有设备画�?JSON */
struct json_object *fwx_get_all_device_profiles_json(void) {
    struct json_object *arr = json_object_new_array();
    
    pthread_rwlock_rdlock(&g_profile_lock);
    
    for (int i = 0; i < g_profile_count; i++) {
        if (g_profiles[i]) {
            /* 计算风险评分 */
            fwx_calculate_risk_score(g_profiles[i]);
            
            struct json_object *obj = fwx_device_profile_to_json(g_profiles[i]);
            if (obj) {
                json_object_array_add(arr, obj);
            }
        }
    }
    
    pthread_rwlock_unlock(&g_profile_lock);
    
    return arr;
}

/* 保存设备画像到文�?*/
int fwx_save_device_profiles(void) {
    struct json_object *arr = fwx_get_all_device_profiles_json();
    if (!arr) return -1;
    
    const char *json_str = json_object_to_json_string_ext(arr, 
        JSON_C_TO_STRING_PRETTY);
    
    FILE *fp = fopen(PROFILE_SAVE_PATH, "w");
    if (!fp) {
        json_object_put(arr);
        return -1;
    }
    
    fputs(json_str, fp);
    fclose(fp);
    json_object_put(arr);
    
    LOG_INFO("Saved %d device profiles", g_profile_count);
    return 0;
}

/* 初始�?*/
int fwx_device_profile_init(void) {
    memset(g_profiles, 0, sizeof(g_profiles));
    memset(g_oui_hash, 0, sizeof(g_oui_hash));
    g_profile_count = 0;
    g_oui_loaded = 0;
    
    /* 加载 OUI 数据�?*/
    fwx_load_oui_database(NULL);
    
    /* 加载已保存的画像 */
    fwx_load_device_profiles();
    
    LOG_INFO("Device profile module initialized");
    return 0;
}

/* 清理 */
void fwx_device_profile_exit(void) {
    /* 保存画像 */
    fwx_save_device_profiles();
    
    /* 释放画像内存 */
    pthread_rwlock_wrlock(&g_profile_lock);
    for (int i = 0; i < g_profile_count; i++) {
        free(g_profiles[i]);
        g_profiles[i] = NULL;
    }
    g_profile_count = 0;
    pthread_rwlock_unlock(&g_profile_lock);
    
    /* 释放 OUI 数据�?*/
    for (int i = 0; i < OUI_HASH_SIZE; i++) {
        oui_entry_t *entry = g_oui_hash[i];
        while (entry) {
            oui_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
        g_oui_hash[i] = NULL;
    }
    
    LOG_INFO("Device profile module exited");
}

/* 加载设备画像 (简化实�? */
int fwx_load_device_profiles(void) {
    /* TODO: �?JSON 文件加载 */
    return 0;
}
