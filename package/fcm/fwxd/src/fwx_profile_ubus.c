// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FWX Device Profile UBUS Interface
 * Copyright(c) 2026 FanchMWRT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include "fwx_device_profile.h"
#include "fwx_common.h"

/* 获取所有设备画�?*/
static int handle_get_profiles(struct ubus_context *ctx,
                               struct ubus_object *obj,
                               struct ubus_request_data *req,
                               const char *method,
                               struct blob_attr *msg)
{
    struct json_object *profiles = fwx_get_all_device_profiles_json();
    if (!profiles) {
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    
    const char *json_str = json_object_to_json_string(profiles);
    
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_json_from_string(&b, json_str);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    
    json_object_put(profiles);
    return 0;
}

/* 获取单个设备画像 */
static int handle_get_profile(struct ubus_context *ctx,
                              struct ubus_object *obj,
                              struct ubus_request_data *req,
                              const char *method,
                              struct blob_attr *msg)
{
    struct blob_attr *tb[1];
    static const struct blobmsg_policy policy[] = {
        { .name = "mac", .type = BLOBMSG_TYPE_STRING },
    };
    
    blobmsg_parse(policy, 1, tb, blob_data(msg), blob_len(msg));
    
    if (!tb[0]) {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    
    const char *mac = blobmsg_get_string(tb[0]);
    device_profile_t *profile = fwx_get_device_profile(mac);
    
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    
    if (profile) {
        struct json_object *obj = fwx_device_profile_to_json(profile);
        if (obj) {
            const char *json_str = json_object_to_json_string(obj);
            blobmsg_add_json_from_string(&b, json_str);
            json_object_put(obj);
        }
    } else {
        blobmsg_add_string(&b, "error", "Profile not found");
    }
    
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    
    return 0;
}

/* 更新设备 User-Agent */
static int handle_update_ua(struct ubus_context *ctx,
                            struct ubus_object *obj,
                            struct ubus_request_data *req,
                            const char *method,
                            struct blob_attr *msg)
{
    struct blob_attr *tb[2];
    static const struct blobmsg_policy policy[] = {
        { .name = "mac", .type = BLOBMSG_TYPE_STRING },
        { .name = "user_agent", .type = BLOBMSG_TYPE_STRING },
    };
    
    blobmsg_parse(policy, 2, tb, blob_data(msg), blob_len(msg));
    
    if (!tb[0] || !tb[1]) {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    
    const char *mac = blobmsg_get_string(tb[0]);
    const char *ua = blobmsg_get_string(tb[1]);
    
    int ret = fwx_update_device_from_ua(mac, ua);
    
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "code", ret == 0 ? 0 : 1);
    blobmsg_add_string(&b, "message", ret == 0 ? "success" : "failed");
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    
    return 0;
}

/* 查询 MAC 厂商 */
static int handle_lookup_vendor(struct ubus_context *ctx,
                                struct ubus_object *obj,
                                struct ubus_request_data *req,
                                const char *method,
                                struct blob_attr *msg)
{
    struct blob_attr *tb[1];
    static const struct blobmsg_policy policy[] = {
        { .name = "mac", .type = BLOBMSG_TYPE_STRING },
    };
    
    blobmsg_parse(policy, 1, tb, blob_data(msg), blob_len(msg));
    
    if (!tb[0]) {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    
    const char *mac = blobmsg_get_string(tb[0]);
    mac_vendor_info_t vendor;
    
    fwx_lookup_mac_vendor(mac, &vendor);
    
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "mac", mac);
    blobmsg_add_string(&b, "vendor", vendor.vendor_name);
    blobmsg_add_string(&b, "vendor_short", vendor.vendor_short);
    blobmsg_add_u8(&b, "known", vendor.is_known);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    
    return 0;
}

/* 保存画像数据 */
static int handle_save_profiles(struct ubus_context *ctx,
                                struct ubus_object *obj,
                                struct ubus_request_data *req,
                                const char *method,
                                struct blob_attr *msg)
{
    int ret = fwx_save_device_profiles();
    
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "code", ret == 0 ? 0 : 1);
    blobmsg_add_string(&b, "message", ret == 0 ? "saved" : "failed");
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    
    return 0;
}

/* 获取设备统计 */
static int handle_profile_stats(struct ubus_context *ctx,
                                struct ubus_object *obj,
                                struct ubus_request_data *req,
                                const char *method,
                                struct blob_attr *msg)
{
    struct json_object *profiles = fwx_get_all_device_profiles_json();
    if (!profiles) {
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    
    int total = json_object_array_length(profiles);
    int by_type[DEV_TYPE_MAX] = {0};
    int by_os[OS_TYPE_MAX] = {0};
    int high_risk = 0;
    
    for (int i = 0; i < total; i++) {
        struct json_object *p = json_object_array_get_idx(profiles, i);
        
        /* 统计设备类型 */
        struct json_object *dt;
        if (json_object_object_get_ex(p, "device_type", &dt)) {
            const char *type_str = json_object_get_string(dt);
            for (int t = 0; t < DEV_TYPE_MAX; t++) {
                if (strcmp(type_str, fwx_device_type_str(t)) == 0) {
                    by_type[t]++;
                    break;
                }
            }
        }
        
        /* 统计操作系统 */
        struct json_object *os;
        if (json_object_object_get_ex(p, "os_type", &os)) {
            const char *os_str = json_object_get_string(os);
            for (int o = 0; o < OS_TYPE_MAX; o++) {
                if (strcmp(os_str, fwx_os_type_str(o)) == 0) {
                    by_os[o]++;
                    break;
                }
            }
        }
        
        /* 统计高风险设�?*/
        struct json_object *behavior, *risk;
        if (json_object_object_get_ex(p, "behavior", &behavior) &&
            json_object_object_get_ex(behavior, "risk_score", &risk)) {
            if (json_object_get_int(risk) >= 50) {
                high_risk++;
            }
        }
    }
    
    json_object_put(profiles);
    
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "total", total);
    blobmsg_add_u32(&b, "high_risk", high_risk);
    
    void *t = blobmsg_open_table(&b, "by_device_type");
    for (int i = 0; i < DEV_TYPE_MAX; i++) {
        if (by_type[i] > 0) {
            blobmsg_add_u32(&b, fwx_device_type_str(i), by_type[i]);
        }
    }
    blobmsg_close_table(&b, t);
    
    void *o = blobmsg_open_table(&b, "by_os");
    for (int i = 0; i < OS_TYPE_MAX; i++) {
        if (by_os[i] > 0) {
            blobmsg_add_u32(&b, fwx_os_type_str(i), by_os[i]);
        }
    }
    blobmsg_close_table(&b, o);
    
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    
    return 0;
}

/* UBUS method definitions */
static const struct ubus_method fwx_profile_methods[] = {
    UBUS_METHOD_NOARG("list", handle_get_profiles),
    UBUS_METHOD("get", handle_get_profile, NULL),
    UBUS_METHOD("update_ua", handle_update_ua, NULL),
    UBUS_METHOD("lookup_vendor", handle_lookup_vendor, NULL),
    UBUS_METHOD_NOARG("save", handle_save_profiles),
    UBUS_METHOD_NOARG("stats", handle_profile_stats),
};

static struct ubus_object_type fwx_profile_object_type =
    UBUS_OBJECT_TYPE("fwx.profile", fwx_profile_methods);

static struct ubus_object fwx_profile_object = {
    .name = "fwx.profile",
    .type = &fwx_profile_object_type,
    .methods = fwx_profile_methods,
    .n_methods = ARRAY_SIZE(fwx_profile_methods),
};

int fwx_profile_ubus_init(struct ubus_context *ctx)
{
    int ret;
    
    /* 初始化设备画像模�?*/
    fwx_device_profile_init();
    
    ret = ubus_add_object(ctx, &fwx_profile_object);
    if (ret) {
        LOG_ERROR("Failed to add fwx.profile ubus object: %s", ubus_strerror(ret));
        return ret;
    }
    
    LOG_INFO("fwx.profile ubus interface initialized");
    return 0;
}

void fwx_profile_ubus_cleanup(void)
{
    fwx_device_profile_exit();
    LOG_INFO("fwx.profile ubus interface cleanup");
}
