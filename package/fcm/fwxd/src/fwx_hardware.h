// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FWX Hardware Detection & Security Profile
 * Copyright(c) 2026 FanchMWRT
 */
#ifndef __FWX_HARDWARE_H__
#define __FWX_HARDWARE_H__

#include <json-c/json.h>

/* 硬件信息 */
typedef struct fwx_hardware_info {
    int memory_total_mb;      /* 总内存 MB */
    int memory_available_mb;  /* 可用内存 MB */
    int cpu_cores;            /* CPU核心数 */
    int cpu_freq_mhz;         /* CPU频率 MHz */
    char cpu_model[128];      /* CPU型号 */
} fwx_hardware_info_t;

/* 安全档位级别 */
typedef enum {
    SECURITY_PROFILE_MINIMAL = 0,   /* 最小: 仅基础防火墙 */
    SECURITY_PROFILE_BASIC,         /* 基础: 威胁情报 + 轻量IDS */
    SECURITY_PROFILE_STANDARD,      /* 标准: + 流量分析 */
    SECURITY_PROFILE_ADVANCED,      /* 高级: + 精简Suricata + AV */
    SECURITY_PROFILE_MAXIMUM,       /* 最大: 完整Suricata */
    SECURITY_PROFILE_MAX
} security_profile_level_t;

/* 功能开关 */
typedef struct security_features {
    int threat_intel;      /* 威胁情报 */
    int ids_basic;         /* 基础IDS (nftables) */
    int ids_suricata;      /* Suricata: 0=关, 1=精简, 2=完整 */
    int av_scan;           /* 病毒扫描 */
    int traffic_analysis;  /* 流量分析 */
} security_features_t;

/* 安全档位定义 */
typedef struct fwx_security_profile {
    const char *name;           /* 档位名称 */
    const char *display_name;   /* 显示名称 */
    const char *description;    /* 描述 */
    int min_memory_mb;          /* 最低内存要求 */
    int min_cpu_cores;          /* 最低CPU核心要求 */
    security_features_t features;  /* 功能开关 */
} fwx_security_profile_t;

/* 检测硬件信息 */
int fwx_hardware_detect(fwx_hardware_info_t *info);

/* 获取缓存的硬件信息 */
const fwx_hardware_info_t *fwx_hardware_get_info(void);

/* 根据硬件推荐安全档位 */
security_profile_level_t fwx_hardware_recommend_profile(void);

/* 获取档位信息 */
const fwx_security_profile_t *fwx_get_security_profile(security_profile_level_t level);

/* JSON输出 */
struct json_object *fwx_hardware_to_json(void);
struct json_object *fwx_security_profile_to_json(security_profile_level_t level);
struct json_object *fwx_hardware_profile_response(void);

#endif /* __FWX_HARDWARE_H__ */
