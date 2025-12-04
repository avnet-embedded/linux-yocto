/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Firmware layer for XilSECURE APIs.
 *
 * Copyright (C), 2025 Advanced Micro Devices, Inc.
 */

#ifndef __FIRMWARE_ZYNQMP_SECURE_H__
#define __FIRMWARE_ZYNQMP_SECURE_H__

/* XilPuf API commands module id + api id */
#define XPUF_API_PUF_REGISTRATION	0xc01
#define XPUF_API_PUF_REGENERATION	0xc02
#define XPUF_API_PUF_CLEAR_PUF_ID	0xc03

#if IS_REACHABLE(CONFIG_ZYNQMP_FIRMWARE)
int zynqmp_pm_secure_load(const u64 src_addr, u64 key_addr, u64 *dst);
int zynqmp_pm_sha_hash(const u64 address, const u32 size, const u32 flags);
int versal_pm_puf_registration(const u64 in_addr);
int versal_pm_puf_regeneration(const u64 in_addr);
int versal_pm_puf_clear_id(void);
int zynqmp_pm_aes_engine(const u64 address, u32 *out);
#else
static inline int zynqmp_pm_secure_load(const u64 src_addr, u64 key_addr, u64 *dst)
{
	return -ENODEV;
}

static inline int zynqmp_pm_sha_hash(const u64 address, const u32 size,
				     const u32 flags)
{
	return -ENODEV;
}

static int zynqmp_pm_aes_engine(const u64 address, u32 *out)
{
	return -ENODEV;
}

static inline int versal_pm_puf_registration(const u64 in_addr)
{
	return -ENODEV;
}

static inline int versal_pm_puf_regeneration(const u64 in_addr)
{
	return -ENODEV;
}

static inline int versal_pm_puf_clear_id(void)
{
	return -ENODEV;
}

#endif

#endif /* __FIRMWARE_ZYNQMP_SECURE_H__ */
