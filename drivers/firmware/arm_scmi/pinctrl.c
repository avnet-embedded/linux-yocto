// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Pinctrl Protocol
 *
 * Copyright (C) 2024 EPAM
 * Copyright 2024 NXP
 */

#define pr_fmt(fmt) "SCMI pinctrl - " fmt

#include <asm/byteorder.h>
#include <linux/bits.h>
#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/scmi_protocol.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/sort.h>

#include <linux/pinctrl/pinconf-generic.h>

#include "common.h"
#include "protocols.h"
#include "notify.h"

/* Updated only after ALL the mandatory features for that version are merged */
#define SCMI_PROTOCOL_SUPPORTED_VERSION		0x10000

#define GET_GROUPS_NR(x)	le32_get_bits((x), GENMASK(31, 16))
#define GET_PINS_NR(x)		le32_get_bits((x), GENMASK(15, 0))
#define GET_FUNCTIONS_NR(x)	le32_get_bits((x), GENMASK(15, 0))

#define EXT_NAME_FLAG(x)	le32_get_bits((x), BIT(31))
#define NUM_ELEMS(x)		le32_get_bits((x), GENMASK(15, 0))

#define REMAINING(x)		le32_get_bits((x), GENMASK(31, 16))
#define RETURNED(x)		le32_get_bits((x), GENMASK(11, 0))

#define CONFIG_FLAG_MASK	GENMASK(19, 18)
#define SELECTOR_MASK		GENMASK(17, 16)
#define SKIP_CONFIGS_MASK	GENMASK(15, 8)
#define CONFIG_TYPE_MASK	GENMASK(7, 0)

#define PINMUX_MAX_PINS 24

enum scmi_pinctrl_protocol_cmd {
	PINCTRL_ATTRIBUTES = 0x3,
	PINCTRL_LIST_ASSOCIATIONS = 0x4,
	PINCTRL_SETTINGS_GET = 0x5,
	PINCTRL_SETTINGS_CONFIGURE = 0x6,
	PINCTRL_REQUEST = 0x7,
	PINCTRL_RELEASE = 0x8,
	PINCTRL_NAME_GET = 0x9,
	PINCTRL_SET_PERMISSIONS = 0xa,
	PINCTRL_DESCRIBE = 0x13,
	PINCTRL_PINMUX_GET = 0x14,
	PINCTRL_PINMUX_SET = 0x15,
	PINCTRL_PINCONF_GET = 0x16,
	PINCTRL_PINCONF_SET_OVERRIDE = 0x17,
	PINCTRL_PINCONF_SET_APPEND = 0x18,

	PINCTRL_NO_COMMANDS
};

struct scmi_msg_settings_conf {
	__le32 identifier;
	__le32 function_id;
	__le32 attributes;
	__le32 configs[];
};

struct scmi_msg_settings_get {
	__le32 identifier;
	__le32 attributes;
};

struct scmi_resp_settings_get {
	__le32 function_selected;
	__le32 num_configs;
	__le32 configs[];
};

struct scmi_msg_pinctrl_protocol_attributes {
	__le32 attributes_low;
	__le32 attributes_high;
	__le16 no_ranges;
};

struct scmi_msg_pinctrl_attributes {
	__le32 identifier;
	__le32 flags;
};

struct scmi_resp_pinctrl_attributes {
	__le32 attributes;
	u8 name[SCMI_SHORT_NAME_MAX_SIZE];
};

struct scmi_msg_pinctrl_list_assoc {
	__le32 identifier;
	__le32 flags;
	__le32 index;
};

struct scmi_resp_pinctrl_list_assoc {
	__le32 flags;
	__le16 array[];
};

struct scmi_msg_request {
	__le32 identifier;
	__le32 flags;
};

struct scmi_group_info {
	char name[SCMI_MAX_STR_SIZE];
	bool present;
	u32 *group_pins;
	u32 nr_pins;
};

struct scmi_function_info {
	char name[SCMI_MAX_STR_SIZE];
	bool present;
	u32 *groups;
	u32 nr_groups;
};

struct scmi_pin_info {
	char name[SCMI_MAX_STR_SIZE];
	bool present;
};

struct scmi_pinctrl_info {
	u32 version;
	u16 no_ranges;
	int nr_groups;
	int nr_functions;
	int nr_pins;
	struct scmi_group_info *groups;
	struct scmi_function_info *functions;
	struct scmi_pin_info *pins;
};

struct scmi_msg_pinctrl_describe {
	__le32 range_index;
};

struct scmi_msg_resp_pinctrl_describe {
	__le32 no_ranges;
	struct {
		__le16 start;
		__le16 no_pins;
	} range[];
};

struct scmi_msg_pinctrl_pmx_get {
	__le16 pin;
};

struct scmi_msg_resp_pinctrl_pmx_get {
	__le16 function;
};

struct scmi_pin_function {
	__le16 pin;
	__le16 function;
};

struct scmi_msg_pinctrl_pmx_set {
	__le32 no_pins;
	struct scmi_pin_function settings[];
};

struct scmi_msg_pinctrl_pcf_get {
	__le16 pin;
};

struct scmi_msg_resp_pinctrl_pcf_get {
	__le32 mask;
	__le32 boolean_values;
	__le32 multi_bit_values[];
};

struct scmi_msg_pinctrl_pcf_set {
	__le16 pin;
	__le32 mask;
	__le32 boolean_values;
	__le32 multi_bit_values[];
};

static int scmi_pinctrl_attributes_get(const struct scmi_protocol_handle *ph,
				       struct scmi_pinctrl_info *pi)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_pinctrl_protocol_attributes *attr;

	ret = ph->xops->xfer_get_init(ph, PROTOCOL_ATTRIBUTES, 0, sizeof(*attr), &t);
	if (ret)
		return ret;

	attr = t->rx.buf;

	ret = ph->xops->do_xfer(ph, t);
	if (!ret) {
		pi->nr_functions = GET_FUNCTIONS_NR(attr->attributes_high);
		pi->nr_groups = GET_GROUPS_NR(attr->attributes_low);
		pi->nr_pins = GET_PINS_NR(attr->attributes_low);
		pi->no_ranges = le16_to_cpu(attr->no_ranges);
		if (pi->nr_pins == 0) {
			dev_warn(ph->dev, "returned zero pins\n");
			ret = -EINVAL;
		}
	}

	ph->xops->xfer_put(ph, t);
	return ret;
}

static int scmi_pinctrl_count_get(const struct scmi_protocol_handle *ph,
				  enum scmi_pinctrl_selector_type type)
{
	struct scmi_pinctrl_info *pi = ph->get_priv(ph);

	switch (type) {
	case PIN_TYPE:
		return pi->nr_pins;
	case GROUP_TYPE:
		return pi->nr_groups;
	case FUNCTION_TYPE:
		return pi->nr_functions;
	default:
		return -EINVAL;
	}
}

static int scmi_pinctrl_validate_id(const struct scmi_protocol_handle *ph,
				    u32 selector,
				    enum scmi_pinctrl_selector_type type)
{
	int value;

	value = scmi_pinctrl_count_get(ph, type);
	if (value < 0)
		return value;

	if (selector >= value || value == 0)
		return -EINVAL;

	return 0;
}

static int scmi_pinctrl_attributes(const struct scmi_protocol_handle *ph,
				   enum scmi_pinctrl_selector_type type,
				   u32 selector, char *name,
				   u32 *n_elems)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_pinctrl_attributes *tx;
	struct scmi_resp_pinctrl_attributes *rx;
	bool ext_name_flag;

	if (!name)
		return -EINVAL;

	ret = scmi_pinctrl_validate_id(ph, selector, type);
	if (ret)
		return ret;

	ret = ph->xops->xfer_get_init(ph, PINCTRL_ATTRIBUTES, sizeof(*tx),
				      sizeof(*rx), &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	rx = t->rx.buf;
	tx->identifier = cpu_to_le32(selector);
	tx->flags = cpu_to_le32(type);

	ret = ph->xops->do_xfer(ph, t);
	if (!ret) {
		if (n_elems)
			*n_elems = NUM_ELEMS(rx->attributes);

		strscpy(name, rx->name, SCMI_SHORT_NAME_MAX_SIZE);

		ext_name_flag = !!EXT_NAME_FLAG(rx->attributes);
	}

	ph->xops->xfer_put(ph, t);

	if (ret)
		return ret;
	/*
	 * If supported overwrite short name with the extended one;
	 * on error just carry on and use already provided short name.
	 */
	if (ext_name_flag)
		ret = ph->hops->extended_name_get(ph, PINCTRL_NAME_GET,
						  selector, (u32 *)&type, name,
						  SCMI_MAX_STR_SIZE);
	return ret;
}

struct scmi_pinctrl_ipriv {
	u32 selector;
	enum scmi_pinctrl_selector_type type;
	u32 *array;
};

static void iter_pinctrl_assoc_prepare_message(void *message,
					       u32 desc_index,
					       const void *priv)
{
	struct scmi_msg_pinctrl_list_assoc *msg = message;
	const struct scmi_pinctrl_ipriv *p = priv;

	msg->identifier = cpu_to_le32(p->selector);
	msg->flags = cpu_to_le32(p->type);
	msg->index = cpu_to_le32(desc_index);
}

static int iter_pinctrl_assoc_update_state(struct scmi_iterator_state *st,
					   const void *response, void *priv)
{
	const struct scmi_resp_pinctrl_list_assoc *r = response;

	st->num_returned = RETURNED(r->flags);
	st->num_remaining = REMAINING(r->flags);

	return 0;
}

static int
iter_pinctrl_assoc_process_response(const struct scmi_protocol_handle *ph,
				    const void *response,
				    struct scmi_iterator_state *st, void *priv)
{
	const struct scmi_resp_pinctrl_list_assoc *r = response;
	struct scmi_pinctrl_ipriv *p = priv;

	p->array[st->desc_index + st->loop_idx] =
		le16_to_cpu(r->array[st->loop_idx]);

	return 0;
}

static int scmi_pinctrl_list_associations(const struct scmi_protocol_handle *ph,
					  u32 selector,
					  enum scmi_pinctrl_selector_type type,
					  u16 size, u32 *array)
{
	int ret;
	void *iter;
	struct scmi_iterator_ops ops = {
		.prepare_message = iter_pinctrl_assoc_prepare_message,
		.update_state = iter_pinctrl_assoc_update_state,
		.process_response = iter_pinctrl_assoc_process_response,
	};
	struct scmi_pinctrl_ipriv ipriv = {
		.selector = selector,
		.type = type,
		.array = array,
	};

	if (!array || !size || type == PIN_TYPE)
		return -EINVAL;

	ret = scmi_pinctrl_validate_id(ph, selector, type);
	if (ret)
		return ret;

	iter = ph->hops->iter_response_init(ph, &ops, size,
					    PINCTRL_LIST_ASSOCIATIONS,
					    sizeof(struct scmi_msg_pinctrl_list_assoc),
					    &ipriv);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	return ph->hops->iter_response_run(iter);
}

struct scmi_settings_get_ipriv {
	u32 selector;
	enum scmi_pinctrl_selector_type type;
	bool get_all;
	unsigned int *nr_configs;
	enum scmi_pinctrl_conf_type *config_types;
	u32 *config_values;
};

static void
iter_pinctrl_settings_get_prepare_message(void *message, u32 desc_index,
					  const void *priv)
{
	struct scmi_msg_settings_get *msg = message;
	const struct scmi_settings_get_ipriv *p = priv;
	u32 attributes;

	attributes = FIELD_PREP(SELECTOR_MASK, p->type);

	if (p->get_all) {
		attributes |= FIELD_PREP(CONFIG_FLAG_MASK, 1) |
			FIELD_PREP(SKIP_CONFIGS_MASK, desc_index);
	} else {
		attributes |= FIELD_PREP(CONFIG_TYPE_MASK, p->config_types[0]);
	}

	msg->attributes = cpu_to_le32(attributes);
	msg->identifier = cpu_to_le32(p->selector);
}

static int
iter_pinctrl_settings_get_update_state(struct scmi_iterator_state *st,
				       const void *response, void *priv)
{
	const struct scmi_resp_settings_get *r = response;
	struct scmi_settings_get_ipriv *p = priv;

	if (p->get_all) {
		st->num_returned = le32_get_bits(r->num_configs, GENMASK(7, 0));
		st->num_remaining = le32_get_bits(r->num_configs, GENMASK(31, 24));
	} else {
		st->num_returned = 1;
		st->num_remaining = 0;
	}

	return 0;
}

static int
iter_pinctrl_settings_get_process_response(const struct scmi_protocol_handle *ph,
					   const void *response,
					   struct scmi_iterator_state *st,
					   void *priv)
{
	const struct scmi_resp_settings_get *r = response;
	struct scmi_settings_get_ipriv *p = priv;
	u32 type = le32_get_bits(r->configs[st->loop_idx * 2], GENMASK(7, 0));
	u32 val = le32_to_cpu(r->configs[st->loop_idx * 2 + 1]);

	if (p->get_all) {
		p->config_types[st->desc_index + st->loop_idx] = type;
	} else {
		if (p->config_types[0] != type)
			return -EINVAL;
	}

	p->config_values[st->desc_index + st->loop_idx] = val;
	++*p->nr_configs;

	return 0;
}

static int
scmi_pinctrl_settings_get(const struct scmi_protocol_handle *ph, u32 selector,
			  enum scmi_pinctrl_selector_type type,
			  unsigned int *nr_configs,
			  enum scmi_pinctrl_conf_type *config_types,
			  u32 *config_values)
{
	int ret;
	void *iter;
	unsigned int max_configs = *nr_configs;
	struct scmi_iterator_ops ops = {
		.prepare_message = iter_pinctrl_settings_get_prepare_message,
		.update_state = iter_pinctrl_settings_get_update_state,
		.process_response = iter_pinctrl_settings_get_process_response,
	};
	struct scmi_settings_get_ipriv ipriv = {
		.selector = selector,
		.type = type,
		.get_all = (max_configs > 1),
		.nr_configs = nr_configs,
		.config_types = config_types,
		.config_values = config_values,
	};

	if (!config_types || !config_values || type == FUNCTION_TYPE)
		return -EINVAL;

	ret = scmi_pinctrl_validate_id(ph, selector, type);
	if (ret)
		return ret;

	/* Prepare to count returned configs */
	*nr_configs = 0;
	iter = ph->hops->iter_response_init(ph, &ops, max_configs,
					    PINCTRL_SETTINGS_GET,
					    sizeof(struct scmi_msg_settings_get),
					    &ipriv);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	return ph->hops->iter_response_run(iter);
}

static int scmi_pinctrl_settings_get_one(const struct scmi_protocol_handle *ph,
					 u32 selector,
					 enum scmi_pinctrl_selector_type type,
					 enum scmi_pinctrl_conf_type config_type,
					 u32 *config_value)
{
	unsigned int nr_configs = 1;

	return scmi_pinctrl_settings_get(ph, selector, type, &nr_configs,
					 &config_type, config_value);
}

static int scmi_pinctrl_settings_get_all(const struct scmi_protocol_handle *ph,
					 u32 selector,
					 enum scmi_pinctrl_selector_type type,
					 unsigned int *nr_configs,
					 enum scmi_pinctrl_conf_type *config_types,
					 u32 *config_values)
{
	if (!nr_configs || *nr_configs == 0)
		return -EINVAL;

	return scmi_pinctrl_settings_get(ph, selector, type, nr_configs,
					 config_types, config_values);
}

static int
scmi_pinctrl_settings_conf(const struct scmi_protocol_handle *ph,
			   u32 selector,
			   enum scmi_pinctrl_selector_type type,
			   u32 nr_configs,
			   enum scmi_pinctrl_conf_type *config_type,
			   u32 *config_value)
{
	struct scmi_xfer *t;
	struct scmi_msg_settings_conf *tx;
	u32 attributes;
	int ret, i;
	u32 configs_in_chunk, conf_num = 0;
	u32 chunk;
	int max_msg_size = ph->hops->get_max_msg_size(ph);

	if (!config_type || !config_value || type == FUNCTION_TYPE)
		return -EINVAL;

	ret = scmi_pinctrl_validate_id(ph, selector, type);
	if (ret)
		return ret;

	configs_in_chunk = (max_msg_size - sizeof(*tx)) / (sizeof(__le32) * 2);
	while (conf_num < nr_configs) {
		chunk = (nr_configs - conf_num > configs_in_chunk) ?
			configs_in_chunk : nr_configs - conf_num;

		ret = ph->xops->xfer_get_init(ph, PINCTRL_SETTINGS_CONFIGURE,
					      sizeof(*tx) +
					      chunk * 2 * sizeof(__le32), 0, &t);
		if (ret)
			break;

		tx = t->tx.buf;
		tx->identifier = cpu_to_le32(selector);
		tx->function_id = cpu_to_le32(0xFFFFFFFF);
		attributes = FIELD_PREP(GENMASK(1, 0), type) |
			FIELD_PREP(GENMASK(9, 2), chunk);
		tx->attributes = cpu_to_le32(attributes);

		for (i = 0; i < chunk; i++) {
			tx->configs[i * 2] =
				cpu_to_le32(config_type[conf_num + i]);
			tx->configs[i * 2 + 1] =
				cpu_to_le32(config_value[conf_num + i]);
		}

		ret = ph->xops->do_xfer(ph, t);

		ph->xops->xfer_put(ph, t);

		if (ret)
			break;

		conf_num += chunk;
	}

	return ret;
}

static int scmi_pinctrl_function_select(const struct scmi_protocol_handle *ph,
					u32 group,
					enum scmi_pinctrl_selector_type type,
					u32 function_id)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_settings_conf *tx;
	u32 attributes;

	ret = scmi_pinctrl_validate_id(ph, group, type);
	if (ret)
		return ret;

	ret = ph->xops->xfer_get_init(ph, PINCTRL_SETTINGS_CONFIGURE,
				      sizeof(*tx), 0, &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	tx->identifier = cpu_to_le32(group);
	tx->function_id = cpu_to_le32(function_id);
	attributes = FIELD_PREP(GENMASK(1, 0), type) | BIT(10);
	tx->attributes = cpu_to_le32(attributes);

	ret = ph->xops->do_xfer(ph, t);
	ph->xops->xfer_put(ph, t);

	return ret;
}

static int scmi_pinctrl_request_free(const struct scmi_protocol_handle *ph,
				     u32 identifier,
				     enum scmi_pinctrl_selector_type type,
				     enum scmi_pinctrl_protocol_cmd cmd)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_request *tx;

	if (type == FUNCTION_TYPE)
		return -EINVAL;

	if (cmd != PINCTRL_REQUEST && cmd != PINCTRL_RELEASE)
		return -EINVAL;

	ret = scmi_pinctrl_validate_id(ph, identifier, type);
	if (ret)
		return ret;

	ret = ph->xops->xfer_get_init(ph, cmd, sizeof(*tx), 0, &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	tx->identifier = cpu_to_le32(identifier);
	tx->flags = cpu_to_le32(type);

	ret = ph->xops->do_xfer(ph, t);
	ph->xops->xfer_put(ph, t);

	return ret;
}

static int scmi_pinctrl_pin_request(const struct scmi_protocol_handle *ph,
				    u32 pin)
{
	return scmi_pinctrl_request_free(ph, pin, PIN_TYPE, PINCTRL_REQUEST);
}

static int scmi_pinctrl_pin_free(const struct scmi_protocol_handle *ph, u32 pin)
{
	return scmi_pinctrl_request_free(ph, pin, PIN_TYPE, PINCTRL_RELEASE);
}

static int scmi_pinctrl_get_group_info(const struct scmi_protocol_handle *ph,
				       u32 selector,
				       struct scmi_group_info *group)
{
	int ret;

	ret = scmi_pinctrl_attributes(ph, GROUP_TYPE, selector, group->name,
				      &group->nr_pins);
	if (ret)
		return ret;

	if (!group->nr_pins) {
		dev_err(ph->dev, "Group %d has 0 elements", selector);
		return -ENODATA;
	}

	group->group_pins = kmalloc_array(group->nr_pins,
					  sizeof(*group->group_pins),
					  GFP_KERNEL);
	if (!group->group_pins)
		return -ENOMEM;

	ret = scmi_pinctrl_list_associations(ph, selector, GROUP_TYPE,
					     group->nr_pins, group->group_pins);
	if (ret) {
		kfree(group->group_pins);
		return ret;
	}

	group->present = true;
	return 0;
}

static int scmi_pinctrl_get_group_name(const struct scmi_protocol_handle *ph,
				       u32 selector, const char **name)
{
	struct scmi_pinctrl_info *pi = ph->get_priv(ph);

	if (!name)
		return -EINVAL;

	if (selector >= pi->nr_groups || pi->nr_groups == 0)
		return -EINVAL;

	if (!pi->groups[selector].present) {
		int ret;

		ret = scmi_pinctrl_get_group_info(ph, selector,
						  &pi->groups[selector]);
		if (ret)
			return ret;
	}

	*name = pi->groups[selector].name;

	return 0;
}

static int scmi_pinctrl_group_pins_get(const struct scmi_protocol_handle *ph,
				       u32 selector, const u32 **pins,
				       u32 *nr_pins)
{
	struct scmi_pinctrl_info *pi = ph->get_priv(ph);

	if (!pins || !nr_pins)
		return -EINVAL;

	if (selector >= pi->nr_groups || pi->nr_groups == 0)
		return -EINVAL;

	if (!pi->groups[selector].present) {
		int ret;

		ret = scmi_pinctrl_get_group_info(ph, selector,
						  &pi->groups[selector]);
		if (ret)
			return ret;
	}

	*pins = pi->groups[selector].group_pins;
	*nr_pins = pi->groups[selector].nr_pins;

	return 0;
}

static int scmi_pinctrl_get_function_info(const struct scmi_protocol_handle *ph,
					  u32 selector,
					  struct scmi_function_info *func)
{
	int ret;

	ret = scmi_pinctrl_attributes(ph, FUNCTION_TYPE, selector, func->name,
				      &func->nr_groups);
	if (ret)
		return ret;

	if (!func->nr_groups) {
		dev_err(ph->dev, "Function %d has 0 elements", selector);
		return -ENODATA;
	}

	func->groups = kmalloc_array(func->nr_groups, sizeof(*func->groups),
				     GFP_KERNEL);
	if (!func->groups)
		return -ENOMEM;

	ret = scmi_pinctrl_list_associations(ph, selector, FUNCTION_TYPE,
					     func->nr_groups, func->groups);
	if (ret) {
		kfree(func->groups);
		return ret;
	}

	func->present = true;
	return 0;
}

static int scmi_pinctrl_get_function_name(const struct scmi_protocol_handle *ph,
					  u32 selector, const char **name)
{
	struct scmi_pinctrl_info *pi = ph->get_priv(ph);

	if (!name)
		return -EINVAL;

	if (selector >= pi->nr_functions || pi->nr_functions == 0)
		return -EINVAL;

	if (!pi->functions[selector].present) {
		int ret;

		ret = scmi_pinctrl_get_function_info(ph, selector,
						     &pi->functions[selector]);
		if (ret)
			return ret;
	}

	*name = pi->functions[selector].name;
	return 0;
}

static int
scmi_pinctrl_function_groups_get(const struct scmi_protocol_handle *ph,
				 u32 selector, u32 *nr_groups,
				 const u32 **groups)
{
	struct scmi_pinctrl_info *pi = ph->get_priv(ph);

	if (!groups || !nr_groups)
		return -EINVAL;

	if (selector >= pi->nr_functions || pi->nr_functions == 0)
		return -EINVAL;

	if (!pi->functions[selector].present) {
		int ret;

		ret = scmi_pinctrl_get_function_info(ph, selector,
						     &pi->functions[selector]);
		if (ret)
			return ret;
	}

	*groups = pi->functions[selector].groups;
	*nr_groups = pi->functions[selector].nr_groups;

	return 0;
}

static int scmi_pinctrl_mux_set(const struct scmi_protocol_handle *ph,
				u32 selector, u32 group)
{
	return scmi_pinctrl_function_select(ph, group, GROUP_TYPE, selector);
}

static int scmi_pinctrl_get_pin_info(const struct scmi_protocol_handle *ph,
				     u32 selector, struct scmi_pin_info *pin)
{
	int ret;

	if (!pin)
		return -EINVAL;

	ret = scmi_pinctrl_attributes(ph, PIN_TYPE, selector, pin->name, NULL);
	if (ret)
		return ret;

	pin->present = true;
	return 0;
}

static int scmi_pinctrl_get_pin_name(const struct scmi_protocol_handle *ph,
				     u32 selector, const char **name)
{
	struct scmi_pinctrl_info *pi = ph->get_priv(ph);

	if (!name)
		return -EINVAL;

	if (selector >= pi->nr_pins)
		return -EINVAL;

	if (!pi->pins[selector].present) {
		int ret;

		ret = scmi_pinctrl_get_pin_info(ph, selector, &pi->pins[selector]);
		if (ret)
			return ret;
	}

	*name = pi->pins[selector].name;

	return 0;
}

static int scmi_pinctrl_name_get(const struct scmi_protocol_handle *ph,
				 u32 selector,
				 enum scmi_pinctrl_selector_type type,
				 const char **name)
{
	switch (type) {
	case PIN_TYPE:
		return scmi_pinctrl_get_pin_name(ph, selector, name);
	case GROUP_TYPE:
		return scmi_pinctrl_get_group_name(ph, selector, name);
	case FUNCTION_TYPE:
		return scmi_pinctrl_get_function_name(ph, selector, name);
	default:
		return -EINVAL;
	}
}

static bool is_multi_bit_value(enum pin_config_param p)
{
	return !!(SCMI_PINCTRL_MULTI_BIT_CFGS & BIT(p));
}

unsigned int scmi_pinctrl_count_multi_bit_values(unsigned long *configs,
						 unsigned int no_configs)
{
	unsigned int i, count = 0;

	for (i = 0; i < no_configs; ++i)
		if (is_multi_bit_value(pinconf_to_config_param(configs[i])))
			++count;

	return count;
}

static int compare_configs(const void *a, const void *b)
{
	int pa, pb;

	pa = pinconf_to_config_param(*(enum pin_config_param *)a);
	pb = pinconf_to_config_param(*(enum pin_config_param *)b);

	return pb - pa;
}

int scmi_pinctrl_create_pcf(unsigned long *configs,
			    unsigned int no_configs,
			    struct scmi_pinctrl_pinconf *pcf)
{
	unsigned int i, multi_bit_idx = 0;
	enum pin_config_param param;
	int ret = 0;
	u32 arg;

	if (!pcf->multi_bit_values)
		return -EINVAL;

	pcf->mask = 0;
	pcf->boolean_values = 0;

	/* Sorting needs to be done in order to lay out
	 * the configs in descending order of their
	 * pinconf parameter value which matches
	 * the protocol specification.
	 */

	sort(configs, no_configs, sizeof(*configs), compare_configs, NULL);

	for (i = 0; i < no_configs; ++i) {
		param = pinconf_to_config_param(configs[i]);
		arg = pinconf_to_config_argument(configs[i]);

		if (param >= BITS_PER_BYTE * sizeof(pcf->mask)) {
			ret = -EINVAL;
			break;
		}

		pcf->mask |= BIT(param);

		if (is_multi_bit_value(param)) {
			if (multi_bit_idx == U32_MAX) {
				ret = -EINVAL;
				break;
			}
			pcf->multi_bit_values[multi_bit_idx++] = arg;
		} else {
			pcf->boolean_values &= ~BIT(param);
			pcf->boolean_values |= (arg << param);
		}
	}

	return ret;
}

int scmi_pinctrl_convert_from_pcf(unsigned long *configs,
				  struct scmi_pinctrl_pinconf *pcf)
{
	unsigned int index = 0, m_idx = 0, value;
	unsigned long bit, mask = pcf->mask;

	for_each_set_bit(bit, &mask, sizeof(pcf->mask) * BITS_PER_BYTE) {
		if (is_multi_bit_value((enum pin_config_param)bit))
			value = pcf->multi_bit_values[m_idx++];
		else
			value = !!(pcf->boolean_values & BIT(bit));

		configs[index++] = PIN_CONF_PACKED(bit, value);
	}

	return 0;
}

static int scmi_pinctrl_protocol_describe(const struct scmi_protocol_handle *ph,
					  struct scmi_pinctrl_pin_range *rv)
{
	struct scmi_msg_resp_pinctrl_describe *ranges;
	struct scmi_msg_pinctrl_describe *params;
	uint32_t range_index = 0, i, tmp_idx;
	struct scmi_pinctrl_info *pinfo;
	struct scmi_xfer *t;
	int ret;

	pinfo = ph->get_priv(ph);
	if (!pinfo)
		return -ENODEV;

	ret = ph->xops->xfer_get_init(ph, PINCTRL_DESCRIBE, sizeof(*params), 0,
				      &t);
	if (ret) {
		dev_err(ph->dev, "Error initializing xfer!\n");
		return ret;
	}

	params = t->tx.buf;
	ranges = t->rx.buf;

	while (range_index < pinfo->no_ranges) {
		params->range_index = cpu_to_le32(range_index);
		ret = ph->xops->do_xfer(ph, t);
		if (ret) {
			dev_err(ph->dev, "Transfer error!\n");
			goto done;
		}

		for (i = 0; i < le32_to_cpu(ranges->no_ranges); i++) {
			tmp_idx = i + range_index;
			rv[tmp_idx].start = le16_to_cpu(ranges->range[i].start);
			rv[tmp_idx].no_pins = le16_to_cpu(ranges->range[i].no_pins);
		}

		range_index += le32_to_cpu(ranges->no_ranges);
		ph->xops->reset_rx_to_maxsz(ph, t);
	}

done:
	ph->xops->xfer_put(ph, t);

	return ret;
}

static int
scmi_pinctrl_protocol_pinmux_get(const struct scmi_protocol_handle *ph, u16 pin,
				 u16 *func)
{
	struct scmi_msg_resp_pinctrl_pmx_get *rv;
	struct scmi_msg_pinctrl_pmx_get *params;
	size_t tx_size, rx_size;
	struct scmi_xfer *t;
	int ret;

	tx_size = sizeof(struct scmi_msg_pinctrl_pmx_get);
	rx_size = sizeof(struct scmi_msg_resp_pinctrl_pmx_get);

	ret = ph->xops->xfer_get_init(ph, PINCTRL_PINMUX_GET, tx_size, rx_size,
				      &t);
	if (ret) {
		dev_err(ph->dev, "Error initializing xfer!\n");
		return ret;
	}

	params = t->tx.buf;
	rv = t->rx.buf;

	params->pin = cpu_to_le16(pin);

	ret = ph->xops->do_xfer(ph, t);
	if (ret) {
		dev_err(ph->dev, "Error getting pinmux %d!\n", ret);
		goto end;
	}

	*func = le16_to_cpu(rv->function);

end:
	ph->xops->xfer_put(ph, t);

	return ret;
}

static int _scmi_pinctrl_pinmux_set(const struct scmi_protocol_handle *ph,
				    u16 no_pins,
				    const struct scmi_pinctrl_pin_function *pf)
{
	struct scmi_msg_pinctrl_pmx_set *params;
	struct scmi_xfer *t;
	unsigned int i;
	size_t tx_size;
	int ret;

	if (no_pins > U8_MAX)
		return -EINVAL;

	tx_size = sizeof(*params) +
		  no_pins * sizeof(params->settings[0]);

	ret = ph->xops->xfer_get_init(ph, PINCTRL_PINMUX_SET, tx_size, 0, &t);
	if (ret) {
		dev_err(ph->dev, "Error initializing xfer!\n");
		return -EOPNOTSUPP;
	}

	params = t->tx.buf;
	params->no_pins = cpu_to_le32(no_pins);

	for (i = 0; i < no_pins; ++i) {
		params->settings[i].pin = cpu_to_le16(pf[i].pin);
		params->settings[i].function = cpu_to_le16(pf[i].function);
	}

	ret = ph->xops->do_xfer(ph, t);
	if (ret) {
		dev_err(ph->dev, "Error setting pinmux!\n");
		ret = -EOPNOTSUPP;
		goto err;
	}

err:
	ph->xops->xfer_put(ph, t);
	return ret;

}

static int
scmi_pinctrl_protocol_pinmux_set(const struct scmi_protocol_handle *ph,
				 u16 no_pins,
				 const struct scmi_pinctrl_pin_function *pf)
{
	unsigned int i, off = 0;
	int ret = 0;

	for (i = 0; i < no_pins / PINMUX_MAX_PINS; ++i) {
		ret = _scmi_pinctrl_pinmux_set(ph, PINMUX_MAX_PINS, pf + off);
		if (ret)
			return ret;

		off += PINMUX_MAX_PINS;
		if (off > U16_MAX)
			return -EINVAL;
	}

	if (no_pins % PINMUX_MAX_PINS != 0)
		ret = _scmi_pinctrl_pinmux_set(ph, no_pins % PINMUX_MAX_PINS,
					       pf + off);

	return ret;
}

static u32 scmi_pinctrl_count_mb_configs(u32 mask)
{
	return hweight32(mask & SCMI_PINCTRL_MULTI_BIT_CFGS);
}

static int
scmi_pinctrl_add_le32_multi_bit_values(const struct scmi_protocol_handle *ph,
				       struct scmi_pinctrl_pinconf *pcf,
				       struct scmi_msg_resp_pinctrl_pcf_get *rv)
{
	unsigned int bit = sizeof(pcf->mask) * BITS_PER_BYTE - 1;
	unsigned int mb_idx = 0;
	u32 v;

	do {
		if (!(pcf->mask & BIT(bit)))
			continue;

		if (!is_multi_bit_value((enum pin_config_param)bit))
			continue;

		v = le32_to_cpu(rv->multi_bit_values[mb_idx]);
		pcf->multi_bit_values[mb_idx++] = v;
	} while (bit-- != 0);

	return 0;
}

static int
scmi_pinctrl_protocol_pinconf_get(const struct scmi_protocol_handle *ph,
				  u16 pin,
				  struct scmi_pinctrl_pinconf *pcf)
{
	struct scmi_msg_resp_pinctrl_pcf_get *rv;
	struct scmi_msg_pinctrl_pcf_get *params;
	struct scmi_xfer *t;
	int ret;

	if (!pcf->multi_bit_values)
		return -EINVAL;

	pcf->mask = 0;
	pcf->boolean_values = 0;

	ret = ph->xops->xfer_get_init(ph, PINCTRL_PINCONF_GET,
				      sizeof(struct scmi_msg_pinctrl_pcf_get),
				      0, &t);
	if (ret) {
		dev_err(ph->dev, "Error setting pinmux!\n");
		return -EOPNOTSUPP;
	}

	params = t->tx.buf;
	rv = t->rx.buf;
	params->pin = cpu_to_le16(pin);

	ret = ph->xops->do_xfer(ph, t);
	if (ret) {
		dev_err(ph->dev, "Error getting pinconf!\n");
		goto err;
	}

	pcf->mask = le32_to_cpu(rv->mask);
	pcf->boolean_values = le32_to_cpu(rv->boolean_values);

	ret = scmi_pinctrl_add_le32_multi_bit_values(ph, pcf, rv);
err:
	ph->xops->xfer_put(ph, t);

	return ret;
}

static int
scmi_pinctrl_protocol_pinconf_set(const struct scmi_protocol_handle *ph,
				  u16 pin,
				  struct scmi_pinctrl_pinconf *pcf,
				  bool override)
{
	struct scmi_msg_pinctrl_pcf_set *params;
	struct scmi_xfer *t;
	int ret, i = 0;
	u8 msg_id;
	u8 multi_bit_count;
	size_t tx_size;

	if (override)
		msg_id = PINCTRL_PINCONF_SET_OVERRIDE;
	else
		msg_id = PINCTRL_PINCONF_SET_APPEND;

	multi_bit_count = scmi_pinctrl_count_mb_configs(pcf->mask);
	tx_size = sizeof(struct scmi_msg_pinctrl_pcf_set);
	tx_size += sizeof(__le32) * multi_bit_count;

	ret = ph->xops->xfer_get_init(ph, msg_id, tx_size, 0, &t);
	if (ret) {
		dev_err(ph->dev, "Error initializing transfer!\n");
		return -EOPNOTSUPP;
	}

	params = t->tx.buf;
	params->pin = cpu_to_le16(pin);
	params->mask = cpu_to_le32(pcf->mask);
	params->boolean_values = cpu_to_le32(pcf->boolean_values);

	for (i = 0; i < multi_bit_count; ++i)
		params->multi_bit_values[i] =
			cpu_to_le32(pcf->multi_bit_values[i]);

	ret = ph->xops->do_xfer(ph, t);
	if (ret)
		dev_err(ph->dev, "Error setting pinconf!\n");

	ph->xops->xfer_put(ph, t);

	return ret;
}

static u16
scmi_pinctrl_protocol_get_no_ranges(const struct scmi_protocol_handle *ph)
{
	struct scmi_pinctrl_info *pinfo = ph->get_priv(ph);

	return pinfo->no_ranges;
}

static const struct scmi_pinctrl_proto_ops pinctrl_proto_ops = {
	.count_get = scmi_pinctrl_count_get,
	.name_get = scmi_pinctrl_name_get,
	.group_pins_get = scmi_pinctrl_group_pins_get,
	.function_groups_get = scmi_pinctrl_function_groups_get,
	.mux_set = scmi_pinctrl_mux_set,
	.settings_get_one = scmi_pinctrl_settings_get_one,
	.settings_get_all = scmi_pinctrl_settings_get_all,
	.settings_conf = scmi_pinctrl_settings_conf,
	.pin_request = scmi_pinctrl_pin_request,
	.pin_free = scmi_pinctrl_pin_free,
	.describe = scmi_pinctrl_protocol_describe,
	.pinmux_get = scmi_pinctrl_protocol_pinmux_get,
	.pinmux_set = scmi_pinctrl_protocol_pinmux_set,
	.pinconf_get = scmi_pinctrl_protocol_pinconf_get,
	.pinconf_set = scmi_pinctrl_protocol_pinconf_set,
	.get_no_ranges = scmi_pinctrl_protocol_get_no_ranges,
};

static int scmi_pinctrl_protocol_init(const struct scmi_protocol_handle *ph)
{
	int ret;
	u32 version;
	struct scmi_pinctrl_info *pinfo;

	ret = ph->xops->version_get(ph, &version);
	if (ret)
		return ret;

	dev_dbg(ph->dev, "Pinctrl Version %d.%d\n",
		PROTOCOL_REV_MAJOR(version), PROTOCOL_REV_MINOR(version));

	pinfo = devm_kzalloc(ph->dev, sizeof(*pinfo), GFP_KERNEL);
	if (!pinfo)
		return -ENOMEM;

	ret = scmi_pinctrl_attributes_get(ph, pinfo);
	if (ret)
		return ret;

	pinfo->pins = devm_kcalloc(ph->dev, pinfo->nr_pins,
				   sizeof(*pinfo->pins), GFP_KERNEL);
	if (!pinfo->pins)
		return -ENOMEM;

	pinfo->groups = devm_kcalloc(ph->dev, pinfo->nr_groups,
				     sizeof(*pinfo->groups), GFP_KERNEL);
	if (!pinfo->groups)
		return -ENOMEM;

	pinfo->functions = devm_kcalloc(ph->dev, pinfo->nr_functions,
					sizeof(*pinfo->functions), GFP_KERNEL);
	if (!pinfo->functions)
		return -ENOMEM;

	pinfo->version = version;

	return ph->set_priv(ph, pinfo, version);
}

static int scmi_pinctrl_protocol_deinit(const struct scmi_protocol_handle *ph)
{
	int i;
	struct scmi_pinctrl_info *pi = ph->get_priv(ph);

	/* Free groups_pins allocated in scmi_pinctrl_get_group_info */
	for (i = 0; i < pi->nr_groups; i++) {
		if (pi->groups[i].present) {
			kfree(pi->groups[i].group_pins);
			pi->groups[i].present = false;
		}
	}

	/* Free groups allocated in scmi_pinctrl_get_function_info */
	for (i = 0; i < pi->nr_functions; i++) {
		if (pi->functions[i].present) {
			kfree(pi->functions[i].groups);
			pi->functions[i].present = false;
		}
	}

	return 0;
}

static const struct scmi_protocol scmi_pinctrl = {
	.id = SCMI_PROTOCOL_PINCTRL,
	.owner = THIS_MODULE,
	.instance_init = &scmi_pinctrl_protocol_init,
	.instance_deinit = &scmi_pinctrl_protocol_deinit,
	.ops = &pinctrl_proto_ops,
	.supported_version = SCMI_PROTOCOL_SUPPORTED_VERSION,
};

DEFINE_SCMI_PROTOCOL_REGISTER_UNREGISTER(pinctrl, scmi_pinctrl)
