// SPDX-License-Identifier: GPL-2.0
/*
 * Firmware layer for XilPDI APIs.
 *
 * Copyright (C), 2025 Advanced Micro Devices, Inc.
 */

#include <linux/dma-mapping.h>
#include <linux/export.h>
#include <linux/firmware.h>
#include <linux/firmware/xlnx-zynqmp.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>

/**
 * zynqmp_pm_load_pdi - Load and process PDI
 * @src:	Source device where PDI is located
 * @address:	PDI src address
 *
 * This function provides support to load PDI from linux
 *
 * Return: Returns status, either success or error+reason
 */
int zynqmp_pm_load_pdi(const u32 src, const u64 address)
{
	u32 ret_payload[PAYLOAD_ARG_CNT];
	int ret;

	ret = zynqmp_pm_invoke_fn(PM_LOAD_PDI, ret_payload, 3, src,
				  lower_32_bits(address),
				  upper_32_bits(address));
	if (ret_payload[0])
		return ret_payload[0];

	return ret;
}
EXPORT_SYMBOL_GPL(zynqmp_pm_load_pdi);
