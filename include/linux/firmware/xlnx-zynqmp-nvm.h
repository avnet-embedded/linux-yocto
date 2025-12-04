/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Firmware layer for XilNVM APIs.
 *
 * Copyright (C), 2025 Advanced Micro Devices, Inc.
 */

#ifndef __FIRMWARE_ZYNQMP_NVM_H__
#define __FIRMWARE_ZYNQMP_NVM_H__

#if IS_REACHABLE(CONFIG_ZYNQMP_FIRMWARE)
int zynqmp_pm_efuse_access(const u64 address, u32 *out);
#else
static inline int zynqmp_pm_efuse_access(const u64 address, u32 *out)
{
	return -ENODEV;
}

#endif

#endif /* __FIRMWARE_ZYNQMP_NVM_H__ */
