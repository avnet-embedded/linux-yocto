/* SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause) */
/*
 * NTMP table request and response data buffer formats
 * and some private macros and functions
 *
 * Copyright 2025 NXP
 *
 */
#ifndef __NTMP_PRIAVTE_H
#define __NTMP_PRIAVTE_H
#include <linux/fsl/ntmp.h>

#define TGST_MAX_ENTRY_NUM		64
#define SGCLT_MAX_GE_NUM		256
#define SGIT_MAX_CT_PLUS_CT_EXT		0x3fffffffU

#pragma pack(1)
struct common_req_data {
	__le16 update_act;
	u8 dbg_opt;
	u8 tblv_qact;
#define NTMP_QUERY_ACT		GENMASK(3, 0)
#define NTMP_TBL_VER		GENMASK(7, 0)
#define NTMP_TBLV_QACT(v, a)	(FIELD_PREP(NTMP_TBL_VER, (v)) | \
				 ((a) & NTMP_QUERY_ACT))
};

struct common_resp_query {
	__le32 entry_id;
};

struct common_resp_nq {
	__le32 status;
};

/* Generic structure for request data by entry ID  */
struct ntmp_req_by_eid {
	struct common_req_data crd;
	__le32 entry_id;
};

/* MAC Address Filter Table Request and Response Data Buffer Format */
struct maft_req_add {
	struct ntmp_req_by_eid rbe;
	struct maft_keye_data keye;
	struct maft_cfge_data cfge;
};

/*struct for response data buffer */
struct maft_resp_query {
	__le32 entry_id;
	struct maft_keye_data keye;
	struct maft_cfge_data cfge;
};

/* VLAM Address Filter table Request and Response Data Buffer Format */
struct vaft_req_add {
	struct ntmp_req_by_eid rbe;
	struct vaft_keye_data keye;
	struct vaft_cfge_data cfge;
};

/* VLAN Address Filter Table Response to Query action */
struct vaft_resp_query {
	__le32 entry_id;
	struct vaft_keye_data keye;
	struct vaft_cfge_data cfge;
};

/* RSS Table Request and Response Data Buffer Format */
struct rsst_req_update {
	struct ntmp_req_by_eid rbe;
	u8 groups[];
};

/* Time Gate Scheduling Table Resquet and Response Data Buffer Format */
struct tgst_ge {
	__le32 interval;
	u8 tc_state;
	u8 resv0;
	u8 hr_cb;
#define TGST_HR_CB		GENMASK(3, 0)
	u8 resv1;
};

struct tgst_cfge_data {
	__le64 admin_bt;
	__le32 admin_ct;
	__le32 admin_ct_ext;
	__le16 admin_cl_len;
	__le16 resv;
	struct tgst_ge ge[];
};

struct tgst_olse_data {
	__le64 oper_cfg_ct;
	__le64 oper_cfg_ce;
	__le64 oper_bt;
	__le32 oper_ct;
	__le32 oper_ct_ext;
	__le16 oper_cl_len;
	__le16 resv;
	struct tgst_ge ge[];
};

struct tgst_req_update {
	struct ntmp_req_by_eid rbe;
	struct tgst_cfge_data cfge;
};

struct tgst_resp_status {
	__le64 cfg_ct;
	__le32 status_resv;
};

struct tgst_resp_query {
	struct tgst_resp_status status;
	__le32 entry_id;
	u8 data[];
};

/* Rate Policer Table Request and Response Data Buffer Format */
struct rpt_req_ua {
	struct ntmp_req_by_eid rbe;
	struct rpt_cfge_data cfge;
	struct rpt_fee_data fee;
};

struct rpt_resp_query {
	__le32 entry_id;
	struct rpt_stse_data stse;
	struct rpt_cfge_data cfge;
	struct rpt_fee_data fee;
	struct rpt_pse_data pse;
};

/* Ingress Stream Identification Table Resquet and Response Data Buffer Format */
struct isit_ak_eid {
	__le32 entry_id;
	__le32 resv[4];
};

struct isit_ak_search {
	__le32 resume_eid;
	__le32 resv[4];
};

union isit_access_key {
	struct isit_ak_eid eid;
	struct isit_keye_data keye;
	struct isit_ak_search search;
};

/* struct for update or add operation*/
struct isit_req_ua {
	struct common_req_data crd;
	union isit_access_key ak;
	__le32 is_eid;
};

/* struct for not update or add operation, such as delete, query */
struct isit_req_qd {
	struct common_req_data crd;
	union isit_access_key ak;
};

struct isit_resp_query {
	__le32 status;
	__le32 entry_id;
	struct isit_keye_data keye;
	__le32 is_eid;
};

/* Ingress Stream Table version 0 Resquet and Response Data Buffer Format */
struct ist_req_ua {
	struct ntmp_req_by_eid rbe;
	struct ist_cfge_data cfge;
};

struct ist_resp_query {
	__le32 entry_id;
	struct ist_cfge_data cfge;
};

/* Ingress Stream filter Table Resquet and Response Data Buffer Format */
struct isft_ak_eid {
	__le32 entry_id;
	__le32 resv;
};

struct isft_ak_search {
	__le32 resume_eid;
	__le32 resv;
};

union isft_access_key {
	struct isft_ak_eid eid;
	struct isft_keye_data keye;
	struct isft_ak_search search;
};

struct isft_req_ua {
	struct common_req_data crd;
	union isft_access_key ak;
	struct isft_cfge_data cfge;
};

struct isft_req_qd {
	struct common_req_data crd;
	union isft_access_key ak;
};

struct isft_resp_query {
	__le32 status;
	__le32 entry_id;
	struct isft_keye_data keye;
	struct isft_cfge_data cfge;
};

/* Stream Gate Instance Table Resquet and Response Data Buffer Format */
struct sgit_req_ua {
	struct ntmp_req_by_eid rbe;
	struct sgit_acfge_data acfge;
	struct sgit_cfge_data cfge;
	struct sgit_icfge_data icfge;
};

struct sgit_resp_query {
	__le32 entry_id;
	struct sgit_sgise_data sgise;
	struct sgit_cfge_data cfge;
	struct sgit_icfge_data icfge;
	u8 resv;
	struct sgit_acfge_data acfge;
};

/* Stream Gate Control List Table Request and Response Data Buffer Format */
struct sgclt_req_add {
	struct ntmp_req_by_eid rbe;
	struct sgclt_cfge_data cfge;
};

struct sgclt_resp_query {
	__le32 entry_id;
	u8 ref_count;
	u8 resv[3];
	struct sgclt_cfge_data cfge;
};

/* Ingress Stream Count Table Request and Response Data Buffer Format */
struct isct_resp_query {
	__le32 entry_id;
	struct isct_stse_data stse;
};

/* Ingress Port Filter Table Request and Response Data Buffer Format */
struct ipft_req_add {
	struct common_req_data crd;
	struct ipft_keye_data keye;
	struct ipft_cfge_data cfge;
};

/* request data format of query or delete action */
struct ipft_req_qd {
	struct ntmp_req_by_eid rbe;
	__le32 resv[52];
};

struct ipft_resp_query {
	__le32 status;
	__le32 entry_id;
	struct ipft_keye_data keye;
	__le64 match_count; /* STSE_DATA */
	struct ipft_cfge_data cfge;
};

#pragma pack()

struct tgst_query_data {
	__le64 config_change_time;
	__le64 admin_bt;
	__le32 admin_ct;
	__le32 admin_ct_ext;
	__le16 admin_cl_len;
	__le64 oper_cfg_ct;
	__le64 oper_cfg_ce;
	__le64 oper_bt;
	__le32 oper_ct;
	__le32 oper_ct_ext;
	__le16 oper_cl_len;
	struct tgst_ge olse_ge[TGST_MAX_ENTRY_NUM];
	struct tgst_ge cfge_ge[TGST_MAX_ENTRY_NUM];
};

u32 ntmp_lookup_free_words(unsigned long *bitmap, u32 bitmap_size,
			   u32 num_words);
void ntmp_clear_words_bitmap(unsigned long *bitmap, u32 entry_id,
			     u32 num_words);
int ntmp_tgst_query_entry(struct netc_cbdrs *cbdrs, u32 entry_id,
			  struct tgst_query_data *data);
int ntmp_tgst_update_admin_gate_list(struct netc_cbdrs *cbdrs, u32 entry_id,
				     struct tgst_cfge_data *cfge);
int ntmp_tgst_delete_admin_gate_list(struct netc_cbdrs *cbdrs, u32 entry_id);
int ntmp_rpt_query_entry(struct netc_cbdrs *cbdrs, u32 entry_id,
			 struct ntmp_rpt_entry *entry);
int ntmp_isit_add_or_update_entry(struct netc_cbdrs *cbdrs, bool add,
				  struct ntmp_isit_entry *entry);
int ntmp_isit_query_entry(struct netc_cbdrs *cbdrs, u32 entry_id,
			  struct ntmp_isit_entry *entry);
int ntmp_isit_delete_entry(struct netc_cbdrs *cbdrs, u32 entry_id);
int ntmp_ist_query_entry(struct netc_cbdrs *cbdrs, u32 entry_id,
			 struct ist_cfge_data *cfge);
int ntmp_isft_add_or_update_entry(struct netc_cbdrs *cbdrs, bool add,
				  struct ntmp_isft_entry *entry);
int ntmp_isft_query_entry(struct netc_cbdrs *cbdrs, u32 entry_id,
			  struct ntmp_isft_entry *entry);
int ntmp_isft_delete_entry(struct netc_cbdrs *cbdrs, u32 entry_id);
int ntmp_sgit_add_or_update_entry(struct netc_cbdrs *cbdrs,
				  struct ntmp_sgit_entry *entry);
int ntmp_sgit_query_entry(struct netc_cbdrs *cbdrs, u32 entry_id,
			  struct ntmp_sgit_entry *entry);
int ntmp_sgit_delete_entry(struct netc_cbdrs *cbdrs, u32 entry_id);
int ntmp_sgclt_add_entry(struct netc_cbdrs *cbdrs,
			 struct ntmp_sgclt_entry *entry);
int ntmp_sgclt_delete_entry(struct netc_cbdrs *cbdrs, u32 entry_id);
int ntmp_sgclt_query_entry(struct netc_cbdrs *cbdrs, u32 entry_id,
			   struct ntmp_sgclt_entry *entry, u32 cfge_size);

#endif
