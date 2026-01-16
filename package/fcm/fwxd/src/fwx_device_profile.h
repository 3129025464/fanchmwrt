// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FWX Device Profile - Terminal Fingerprinting
 * Copyright(c) 2026 FanchMWRT
 */
#ifndef __FWX_DEVICE_PROFILE_H__
#define __FWX_DEVICE_PROFILE_H__

#include <stdint.h>
#include <time.h>

/* 设备类型 */
typedef enum {
    DEV_TYPE_UNKNOWN = 0,
    DEV_TYPE_PHONE,         /* 手机 */
    DEV_TYPE_TABLET,        /* 平板 */
    DEV_TYPE_PC,            /* 电脑 */
    DEV_TYPE_LAPTOP,        /* 笔记本 */
    DEV_TYPE_TV,            /* 智能电视 */
    DEV_TYPE_IOT,           /* IoT设备 */
    DEV_TYPE_GAME_CONSOLE,  /* 游戏机 */
    DEV_TYPE_CAMERA,        /* 摄像头 */
    DEV_TYPE_PRINTER,       /* 打印机 */
    DEV_TYPE_ROUTER,        /* 路由器/AP */
    DEV_TYPE_NAS,           /* NAS存储 */
    DEV_TYPE_WEARABLE,      /* 可穿戴设备 */
    DEV_TYPE_MAX
} device_type_t;

/* 操作系统类型 */
typedef enum {
    OS_TYPE_UNKNOWN = 0,
    OS_TYPE_WINDOWS,
    OS_TYPE_MACOS,
    OS_TYPE_LINUX,
    OS_TYPE_ANDROID,
    OS_TYPE_IOS,
    OS_TYPE_CHROMEOS,
    OS_TYPE_TVOS,
    OS_TYPE_EMBEDDED,       /* 嵌入式系统 */
    OS_TYPE_MAX
} os_type_t;

/* 置信度级别 */
typedef enum {
    CONFIDENCE_NONE = 0,
    CONFIDENCE_LOW = 25,
    CONFIDENCE_MEDIUM = 50,
    CONFIDENCE_HIGH = 75,
    CONFIDENCE_CERTAIN = 100
} confidence_level_t;

#define MAX_VENDOR_NAME_LEN 64
#define MAX_MODEL_NAME_LEN 64
#define MAX_OS_VERSION_LEN 32
#define MAX_BROWSER_NAME_LEN 32
#define MAX_UA_LEN 256

/* MAC OUI 厂商信息 */
typedef struct {
    char vendor_name[MAX_VENDOR_NAME_LEN];  /* 厂商名称 */
    char vendor_short[16];                   /* 厂商简称 */
    int is_known;                            /* 是否已识别 */
} mac_vendor_info_t;

/* TCP/IP 指纹 */
typedef struct {
    uint8_t ttl;                /* 初始 TTL */
    uint16_t window_size;       /* TCP 窗口大小 */
    uint16_t mss;               /* 最大段大小 */
    uint8_t window_scale;       /* 窗口缩放因子 */
    uint8_t sack_permitted;     /* SACK 支持 */
    uint8_t timestamp_present;  /* 时间戳选项 */
    uint8_t nop_count;          /* NOP 选项数量 */
    uint32_t options_hash;      /* TCP 选项哈希 */
} tcp_fingerprint_t;

/* User-Agent 解析结果 */
typedef struct {
    char browser[MAX_BROWSER_NAME_LEN];     /* 浏览器名称 */
    char browser_version[16];               /* 浏览器版本 */
    os_type_t os_type;                      /* 操作系统类型 */
    char os_version[MAX_OS_VERSION_LEN];    /* 操作系统版本 */
    device_type_t device_type;              /* 设备类型 */
    char device_model[MAX_MODEL_NAME_LEN];  /* 设备型号 */
    int is_mobile;                          /* 是否移动设备 */
    int is_bot;                             /* 是否爬虫 */
    time_t last_seen;                       /* 最后见到时间 */
} ua_info_t;

/* DHCP 指纹 */
typedef struct {
    char hostname_pattern[64];  /* 主机名模式 */
    uint8_t options[32];        /* DHCP 请求选项列表 */
    int options_count;          /* 选项数量 */
    char vendor_class[64];      /* Vendor Class ID (option 60) */
} dhcp_fingerprint_t;

/* 行为画像 */
typedef struct {
    /* 活跃时段统计 (24小时) */
    uint32_t hourly_activity[24];   /* 每小时活跃次数 */
    
    /* 应用使用偏好 */
    int top_app_types[5];           /* Top 5 应用类型 */
    uint32_t app_type_time[16];     /* 各类型应用使用时长(分钟) */
    
    /* 网络行为 */
    uint32_t avg_daily_traffic_mb;  /* 日均流量(MB) */
    uint32_t avg_session_duration;  /* 平均会话时长(秒) */
    uint32_t connection_count;      /* 连接数统计 */
    
    /* 风险指标 */
    uint16_t blocked_count;         /* 被阻止次数 */
    uint16_t threat_hits;           /* 威胁命中次数 */
    uint8_t risk_score;             /* 风险评分 0-100 */
    
    time_t first_seen;              /* 首次发现时间 */
    time_t last_updated;            /* 最后更新时间 */
} behavior_profile_t;

/* 完整设备画像 */
typedef struct {
    /* 基础标识 */
    char mac[18];
    char ip[16];
    
    /* 设备识别 */
    device_type_t device_type;
    os_type_t os_type;
    char os_version[MAX_OS_VERSION_LEN];
    char device_model[MAX_MODEL_NAME_LEN];
    uint8_t confidence;             /* 整体置信度 */
    
    /* 厂商信息 */
    mac_vendor_info_t vendor;
    
    /* 指纹数据 */
    tcp_fingerprint_t tcp_fp;
    dhcp_fingerprint_t dhcp_fp;
    ua_info_t ua_info;
    
    /* 行为画像 */
    behavior_profile_t behavior;
    
    /* 元数据 */
    time_t created_at;
    time_t updated_at;
    uint32_t profile_version;
} device_profile_t;

/* API 函数声明 */

/* 初始化/清理 */
int fwx_device_profile_init(void);
void fwx_device_profile_exit(void);

/* MAC 厂商查询 */
int fwx_lookup_mac_vendor(const char *mac, mac_vendor_info_t *vendor);
int fwx_load_oui_database(const char *path);

/* TCP 指纹识别 */
int fwx_analyze_tcp_fingerprint(const tcp_fingerprint_t *fp, 
                                 os_type_t *os, device_type_t *dev);

/* User-Agent 解析 */
int fwx_parse_user_agent(const char *ua, ua_info_t *info);

/* DHCP 指纹分析 */
int fwx_analyze_dhcp_fingerprint(const dhcp_fingerprint_t *fp,
                                  os_type_t *os, device_type_t *dev);

/* 设备画像管理 */
device_profile_t *fwx_get_device_profile(const char *mac);
device_profile_t *fwx_create_device_profile(const char *mac);
int fwx_update_device_profile(device_profile_t *profile);
int fwx_save_device_profiles(void);
int fwx_load_device_profiles(void);

/* 综合识别 */
int fwx_identify_device(const char *mac, device_profile_t *profile);
int fwx_update_device_from_ua(const char *mac, const char *user_agent);
int fwx_update_device_from_tcp(const char *mac, const tcp_fingerprint_t *fp);
int fwx_update_device_from_dhcp(const char *mac, const dhcp_fingerprint_t *fp);

/* 行为分析 */
int fwx_update_behavior_profile(const char *mac, int app_type, uint32_t duration);
int fwx_calculate_risk_score(device_profile_t *profile);

/* JSON 导出 */
struct json_object *fwx_device_profile_to_json(const device_profile_t *profile);
struct json_object *fwx_get_all_device_profiles_json(void);

/* 工具函数 */
const char *fwx_device_type_str(device_type_t type);
const char *fwx_os_type_str(os_type_t type);

#endif /* __FWX_DEVICE_PROFILE_H__ */
