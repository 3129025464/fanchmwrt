// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FWX Security Alert Module
 * Copyright(c) 2026 FanchMWRT <www.fanchmwrt.com>
 */
#ifndef __FWX_ALERT_H__
#define __FWX_ALERT_H__

#include <json-c/json.h>

#define FWX_ALERT_LOG_PATH "/tmp/log/fwx-security.log"
#define FWX_ALERT_MAX_SIZE (1024 * 1024)  // 1MB

typedef enum {
    ALERT_LEVEL_INFO = 0,
    ALERT_LEVEL_WARNING,
    ALERT_LEVEL_CRITICAL,
    ALERT_LEVEL_EMERGENCY
} alert_level_t;

typedef enum {
    ALERT_TYPE_THREAT_IP = 1,
    ALERT_TYPE_THREAT_DOMAIN,
    ALERT_TYPE_PORTSCAN,
    ALERT_TYPE_SYNFLOOD,
    ALERT_TYPE_BRUTEFORCE,
    ALERT_TYPE_MALWARE,
    ALERT_TYPE_IDS,
    ALERT_TYPE_SYSTEM
} alert_type_t;

typedef struct fwx_alert {
    alert_type_t type;
    alert_level_t level;
    char src_ip[64];
    char dst_ip[64];
    int src_port;
    int dst_port;
    char detail[256];
    time_t timestamp;
} fwx_alert_t;

// Initialize alert system
int fwx_alert_init(void);

// Cleanup alert system
void fwx_alert_cleanup(void);

// Send alert
int fwx_alert_send(fwx_alert_t *alert);

// Log alert to file
int fwx_alert_log(fwx_alert_t *alert);

// Get recent alerts as JSON
struct json_object *fwx_alert_get_recent(int count);

// Clear alerts
int fwx_alert_clear(void);

// Alert statistics
struct json_object *fwx_alert_stats(void);

// UBUS handler for alerts
int fwx_alert_ubus_handler(struct ubus_context *ctx, struct ubus_object *obj,
                           struct ubus_request_data *req, const char *method,
                           struct blob_attr *msg);

#endif /* __FWX_ALERT_H__ */
