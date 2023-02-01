// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Arm Limited
 */

#define pr_fmt(fmt) "smccc: " fmt

#include <linux/init.h>
#include <linux/arm-smccc.h>
#include <linux/sched/clock.h>
#include "smccc_trace.h"

static u32 smccc_version = ARM_SMCCC_VERSION_1_0;
static enum arm_smccc_conduit smccc_conduit = SMCCC_CONDUIT_NONE;

void __init arm_smccc_version_init(u32 version, enum arm_smccc_conduit conduit)
{
	smccc_version = version;
	smccc_conduit = conduit;
}

enum arm_smccc_conduit arm_smccc_1_1_get_conduit(void)
{
	if (smccc_version < ARM_SMCCC_VERSION_1_1)
		return SMCCC_CONDUIT_NONE;

	return smccc_conduit;
}
EXPORT_SYMBOL_GPL(arm_smccc_1_1_get_conduit);

u32 arm_smccc_get_version(void)
{
	return smccc_version;
}
EXPORT_SYMBOL_GPL(arm_smccc_get_version);

void arm_smccc_smc(unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3,
		   unsigned long a4, unsigned long a5, unsigned long a6, unsigned long a7,
		   struct arm_smccc_res *res)
{
	u64 start, elapsed;

	trace_arm_smccc_smc_start(a0);
	start = local_clock();
	__arm_smccc_smc(a0, a1, a2, a3, a4, a5, a6, a7, res, NULL);
	elapsed = local_clock() - start;
	trace_arm_smccc_smc_end(a0, elapsed);
}
EXPORT_SYMBOL_GPL(arm_smccc_smc);
