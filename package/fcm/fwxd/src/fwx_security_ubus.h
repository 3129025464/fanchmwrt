// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FWX Security UBUS Interface
 * Copyright(c) 2026 FanchMWRT <www.fanchmwrt.com>
 */
#ifndef __FWX_SECURITY_UBUS_H__
#define __FWX_SECURITY_UBUS_H__

#include <libubus.h>

// Initialize security ubus methods
int fwx_security_ubus_init(struct ubus_context *ctx);

// Cleanup
void fwx_security_ubus_cleanup(void);

#endif /* __FWX_SECURITY_UBUS_H__ */
