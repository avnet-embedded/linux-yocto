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

/* firmware required uid buff size */
#define UID_BUFF_SIZE	786
#define UID_SET_LEN	4
#define UID_LEN		4

/**
 * zynqmp_pm_get_uid_info - It is used to get image Info List
 * @address:	Buffer address
 * @size:	Number of bytes required to read from the firmware.
 * @count:	Number of bytes read from the firmware.
 *
 * This function provides support to used to get image Info List
 *
 * Return: Returns status, either success or error+reason
 */
int zynqmp_pm_get_uid_info(const u64 address, const u32 size, u32 *count)
{
	u32 ret_payload[PAYLOAD_ARG_CNT];
	int ret;

	if (!count)
		return -EINVAL;

	ret = zynqmp_pm_invoke_fn(PM_GET_UID_INFO_LIST, ret_payload, 3,
				  upper_32_bits(address),
				  lower_32_bits(address),
				  size);

	*count = ret_payload[1];

	return ret;
}
EXPORT_SYMBOL_GPL(zynqmp_pm_get_uid_info);

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

static ssize_t firmware_uid_get_data(struct file *filp, struct kobject *kobj,
				     const struct bin_attribute *attr, char *buf,
				     loff_t off, size_t count)
{
	struct device *kdev = kobj_to_dev(kobj);
	dma_addr_t dma_addr = 0;
	char *kbuf;
	u32 size;
	int ret;

	kbuf = dma_alloc_coherent(kdev, UID_BUFF_SIZE, &dma_addr, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	/* Read from the firmware memory */
	ret = zynqmp_pm_get_uid_info(dma_addr, UID_BUFF_SIZE, &size);
	if (ret) {
		dma_free_coherent(kdev, UID_BUFF_SIZE, kbuf, dma_addr);
		return ret;
	}

	size = size * UID_SET_LEN * UID_LEN;
	memcpy(buf, kbuf, size);
	dma_free_coherent(kdev, UID_BUFF_SIZE, kbuf, dma_addr);

	return size;
}

static const struct bin_attribute uid_attr = {
	.attr.name = "uid-read",
	.attr.mode = 00400,
	.size = 1,
	.read = firmware_uid_get_data,
};

int zynqmp_firmware_pdi_sysfs_entry(struct platform_device *pdev)
{
	int ret;

	ret = sysfs_create_bin_file(&pdev->dev.kobj, &uid_attr);
	if (ret) {
		pr_err("%s() Failed to create sysfs binary file for uid-read with error%d\n",
		       __func__, ret);
		return ret;
	}

	return ret;
}
