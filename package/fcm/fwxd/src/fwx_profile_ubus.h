// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FWX Device Profile UBUS Interface Header
 * Copyright(c) 2026 FanchMWRT
 */
#ifndef __FWX_PROFILE_UBUS_H__
#define __FWX_PROFILE_UBUS_H__

#include <libubus.h>

int fwx_profile_ubus_init(struct ubus_context *ctx);
void fwx_profile_ubus_cleanup(void);

#endif /* __FWX_PROFILE_UBUS_H__ */
