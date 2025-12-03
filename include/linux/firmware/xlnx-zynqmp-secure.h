/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Firmware layer for XilSECURE APIs.
 *
 * Copyright (C), 2025 Advanced Micro Devices, Inc.
 */

#ifndef __FIRMWARE_ZYNQMP_SECURE_H__
#define __FIRMWARE_ZYNQMP_SECURE_H__

#if IS_REACHABLE(CONFIG_ZYNQMP_FIRMWARE)
int zynqmp_pm_sha_hash(const u64 address, const u32 size, const u32 flags);
int zynqmp_pm_aes_engine(const u64 address, u32 *out);
#else
static inline int zynqmp_pm_sha_hash(const u64 address, const u32 size,
				     const u32 flags)
{
	return -ENODEV;
}

static int zynqmp_pm_aes_engine(const u64 address, u32 *out)
{
	return -ENODEV;
}
#endif

#endif /* __FIRMWARE_ZYNQMP_SECURE_H__ */
