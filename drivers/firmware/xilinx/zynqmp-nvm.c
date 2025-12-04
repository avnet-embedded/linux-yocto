// SPDX-License-Identifier: GPL-2.0
/*
 * Firmware layer for XilNVM APIs.
 *
 * Copyright (C), 2025 Advanced Micro Devices, Inc.
 */

#include <linux/export.h>
#include <linux/firmware/xlnx-zynqmp.h>
#include <linux/kernel.h>

/**
 * zynqmp_pm_efuse_access - Provides access to efuse memory.
 * @address:	Address of the efuse params structure
 * @out:		Returned output value
 *
 * Return:	Returns status, either success or error code.
 */
int zynqmp_pm_efuse_access(const u64 address, u32 *out)
{
	u32 ret_payload[PAYLOAD_ARG_CNT];
	int ret;

	if (!out)
		return -EINVAL;

	ret = zynqmp_pm_invoke_fn(PM_EFUSE_ACCESS, ret_payload, 2,
				  upper_32_bits(address),
				  lower_32_bits(address));
	*out = ret_payload[1];

	return ret;
}
EXPORT_SYMBOL_GPL(zynqmp_pm_efuse_access);
