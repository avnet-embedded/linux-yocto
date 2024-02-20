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

/**
 * versal_pm_efuse_read - Reads efuse.
 * @address: Address of the payload
 * @offset: Efuse offset
 * @size: Size of data to be read
 *
 * This function provides support to read data from eFuse.
 *
 * Return: status, either success or error code.
 */
int versal_pm_efuse_read(const u64 address, u32 offset, u32 size)
{
	return zynqmp_pm_invoke_fn(PM_EFUSE_READ_VERSAL, NULL, 4, offset,
				   lower_32_bits(address),
				   upper_32_bits(address), size);
}
EXPORT_SYMBOL_GPL(versal_pm_efuse_read);

/**
 * versal_pm_efuse_write - Write efuse
 * @address: Address of the payload
 * @operationid: operationid which includes module and API id
 * @envdis: Environment disable variable
 *
 * This function provides support to write data into eFuse.
 *
 * Return: status, either success or error+reason
 */
int versal_pm_efuse_write(const u64 address, const u32 operationid,
			  const u8 envdis)
{
	return zynqmp_pm_invoke_fn(operationid, NULL, 3, lower_32_bits(address),
				   upper_32_bits(address), envdis);
}
EXPORT_SYMBOL_GPL(versal_pm_efuse_write);
