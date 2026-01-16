// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FWX Common Utilities Header
 * Copyright(c) 2026 FanchMWRT
 */
#ifndef __FWX_COMMON_H__
#define __FWX_COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>
#include <json-c/json.h>
#include <uci.h>

/*
 * ============================================================================
 * Logging Macros
 * ============================================================================
 */

/* 日志级别控制 - 生产环境设为 0 禁用 DEBUG */
#ifndef FWX_DEBUG_LEVEL
#define FWX_DEBUG_LEVEL 0
#endif

#define LOG_ERROR(fmt, ...) \
    syslog(LOG_ERR, "[FWX][ERROR] " fmt, ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) \
    syslog(LOG_WARNING, "[FWX][WARN] " fmt, ##__VA_ARGS__)

#define LOG_INFO(fmt, ...) \
    syslog(LOG_INFO, "[FWX][INFO] " fmt, ##__VA_ARGS__)

#if FWX_DEBUG_LEVEL > 0
#define LOG_DEBUG(fmt, ...) \
    syslog(LOG_DEBUG, "[FWX][DEBUG] " fmt, ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) do {} while(0)
#endif

/*
 * ============================================================================
 * Safe String Operations
 * ============================================================================
 */

/* 安全字符串复制，保证 null 结尾 */
static inline void safe_strncpy(char *dst, const char *src, size_t size) {
    if (dst && size > 0) {
        if (src) {
            strncpy(dst, src, size - 1);
            dst[size - 1] = '\0';
        } else {
            dst[0] = '\0';
        }
    }
}

/* 安全格式化 */
#define safe_snprintf(buf, fmt, ...) \
    snprintf(buf, sizeof(buf), fmt, ##__VA_ARGS__)

/*
 * ============================================================================
 * File Operations
 * ============================================================================
 */

/* 读取文件内容到缓冲区 */
static inline int fwx_read_file(const char *path, char *buf, size_t len) {
    if (!path || !buf || len == 0) return -1;
    
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    
    size_t n = fread(buf, 1, len - 1, fp);
    fclose(fp);
    
    if (n > 0) {
        buf[n] = '\0';
        /* 去除尾部换行 */
        while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) {
            buf[--n] = '\0';
        }
        return (int)n;
    }
    
    buf[0] = '\0';
    return -1;
}

/* 读取文件整数值 */
static inline int fwx_read_file_int(const char *path, int *value) {
    char buf[32];
    if (fwx_read_file(path, buf, sizeof(buf)) > 0) {
        *value = atoi(buf);
        return 0;
    }
    return -1;
}

/* 写入文件 */
static inline int fwx_write_file(const char *path, const char *content) {
    if (!path || !content) return -1;
    
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    
    fputs(content, fp);
    fclose(fp);
    return 0;
}

/*
 * ============================================================================
 * UCI Helper Macros
 * ============================================================================
 */

/* UCI 操作封装 - 自动管理 context */
#define FWX_UCI_DO(code) do { \
    struct uci_context *_uci_ctx = uci_alloc_context(); \
    if (_uci_ctx) { \
        code; \
        uci_free_context(_uci_ctx); \
    } \
} while(0)

/* UCI 获取字符串值 */
#define FWX_UCI_GET_STR(key, buf) \
    fwx_uci_get_value(_uci_ctx, key, buf, sizeof(buf))

/* UCI 获取整数值 */
#define FWX_UCI_GET_INT(key, var, def) do { \
    char _buf[32]; \
    if (fwx_uci_get_value(_uci_ctx, key, _buf, sizeof(_buf)) == 0) \
        var = atoi(_buf); \
    else \
        var = def; \
} while(0)

/*
 * ============================================================================
 * JSON Helper Macros
 * ============================================================================
 */

/* JSON 对象添加字符串 */
#define JSON_ADD_STR(obj, key, val) \
    json_object_object_add(obj, key, json_object_new_string(val ? val : ""))

/* JSON 对象添加整数 */
#define JSON_ADD_INT(obj, key, val) \
    json_object_object_add(obj, key, json_object_new_int(val))

/* JSON 对象添加 int64 */
#define JSON_ADD_INT64(obj, key, val) \
    json_object_object_add(obj, key, json_object_new_int64(val))

/* JSON 对象添加布尔 */
#define JSON_ADD_BOOL(obj, key, val) \
    json_object_object_add(obj, key, json_object_new_boolean(val))

/* JSON 对象添加子对象 */
#define JSON_ADD_OBJ(obj, key, child) \
    json_object_object_add(obj, key, child)

/* JSON 获取字符串（带默认值） */
static inline const char *json_get_str(struct json_object *obj, 
                                        const char *key, 
                                        const char *def) {
    struct json_object *val;
    if (json_object_object_get_ex(obj, key, &val)) {
        return json_object_get_string(val);
    }
    return def;
}

/* JSON 获取整数（带默认值） */
static inline int json_get_int(struct json_object *obj, 
                                const char *key, 
                                int def) {
    struct json_object *val;
    if (json_object_object_get_ex(obj, key, &val)) {
        return json_object_get_int(val);
    }
    return def;
}

/*
 * ============================================================================
 * Common Utilities
 * ============================================================================
 */

/* 执行命令并获取输出 */
static inline int fwx_exec_cmd(const char *cmd, char *output, size_t len) {
    if (!cmd) return -1;
    
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    
    if (output && len > 0) {
        output[0] = '\0';
        if (fgets(output, len, fp)) {
            /* 去除尾部换行 */
            size_t n = strlen(output);
            while (n > 0 && (output[n-1] == '\n' || output[n-1] == '\r')) {
                output[--n] = '\0';
            }
        }
    }
    
    return pclose(fp);
}

/* 检查文件是否存在 */
static inline int fwx_file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

/* 检查进程是否运行 */
static inline int fwx_process_running(const char *name) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "pidof %s >/dev/null 2>&1", name);
    return system(cmd) == 0;
}

/*
 * ============================================================================
 * API Response Helper
 * ============================================================================
 */

/* API 响应码 */
#define API_CODE_SUCCESS 0
#define API_CODE_ERROR   1
#define API_CODE_INVALID 2

/* 生成 API 响应 */
struct json_object *fwx_gen_api_response_data(int code, struct json_object *data_obj);

/* 快速成功响应 */
#define FWX_API_OK(data) fwx_gen_api_response_data(API_CODE_SUCCESS, data)

/* 快速错误响应 */
#define FWX_API_ERR() fwx_gen_api_response_data(API_CODE_ERROR, NULL)

/*
 * ============================================================================
 * Array Size Macro
 * ============================================================================
 */

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#endif /* __FWX_COMMON_H__ */
