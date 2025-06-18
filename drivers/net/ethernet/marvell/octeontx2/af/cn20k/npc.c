// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */
#include <linux/xarray.h>
#include <linux/bitfield.h>
#include "rvu.h"
#include "npc.h"
#include "npc_profile.h"
#include "rvu_npc_hash.h"
#include "rvu_npc.h"

#define KPU_OFFSET	8
#define KEX_EXTR_CFG(bytesm1, hdr_ofs, ena, key_ofs)		\
		     (((bytesm1) << 16) | ((hdr_ofs) << 8) | ((ena) << 7) | \
		     ((key_ofs) & 0x3F))

#define NPC_DFT_RULE_ID_MK(pcifunc, id) \
	((pcifunc) | FIELD_PREP(GENMASK_ULL(31, 16), id))

#define NPC_DFT_RULE_ID_2_PCIFUNC(rid) \
	FIELD_GET(GENMASK_ULL(15, 0), rid)

#define NPC_DFT_RULE_ID_2_ID(rid) \
	FIELD_GET(GENMASK_ULL(31, 16), rid)

#define NPC_DFT_RULE_PRIO 127

static const char cn20k_def_pfl_name[] = "default";

static struct npc_priv_t npc_priv = {
	.num_banks = MAX_NUM_BANKS,
	.num_subbanks = MAX_NUM_SUB_BANKS,
};

const char *npc_kw_name[NPC_MCAM_KEY_MAX] = {
	[NPC_MCAM_KEY_DYN] = "DYNAMIC",
	[NPC_MCAM_KEY_X2] = "X2",
	[NPC_MCAM_KEY_X4] = "X4",
};

const char *npc_dft_rule_name[NPC_DFT_RULE_MAX_ID] = {
	[NPC_DFT_RULE_PROMISC_ID] = "Promisc",
	[NPC_DFT_RULE_MCAST_ID] = "Mcast",
	[NPC_DFT_RULE_BCAST_ID] = "Bcast",
	[NPC_DFT_RULE_UCAST_ID] = "Ucast",
};

static struct npc_mcam_kex_extr npc_mkex_extr_default = {
	.mkex_sign = MKEX_SIGN,
	.name = "default",
	.kpu_version = NPC_KPU_PROFILE_VER,
	.keyx_cfg = {
		/* nibble: LA..LE (ltype only) + Error code + Channel */
		[NIX_INTF_RX] = ((u64)NPC_MCAM_KEY_X2 << 32) | NPC_PARSE_NIBBLE_INTF_RX |
						(u64)NPC_EXACT_NIBBLE_HIT,
		/* nibble: LA..LE (ltype only) */
		[NIX_INTF_TX] = ((u64)NPC_MCAM_KEY_X2 << 32) | NPC_PARSE_NIBBLE_INTF_TX,
	},
	.intf_extr_lid = {
	/* Default RX MCAM KEX profile */
	[NIX_INTF_RX] = { NPC_LID_LA, NPC_LID_LA, NPC_LID_LB, NPC_LID_LB,
			  NPC_LID_LC, NPC_LID_LC, NPC_LID_LD },
	[NIX_INTF_TX] = { NPC_LID_LA, NPC_LID_LA, NPC_LID_LB, NPC_LID_LB,
			  NPC_LID_LC, NPC_LID_LD },
	},
	.intf_extr_lt = {
	/* Default RX MCAM KEX profile */
	[NIX_INTF_RX] = {
		[0] = {
			/* Layer A: Ethernet: */
			[NPC_LT_LA_ETHER] =
				/* DMAC: 6 bytes, KW1[55:8] */
				KEX_EXTR_CFG(0x05, 0x0, 0x1, NPC_KEXOF_DMAC),
			[NPC_LT_LA_CPT_HDR] =
				/* DMAC: 6 bytes, KW1[55:8] */
				KEX_EXTR_CFG(0x05, 0x0, 0x1, NPC_KEXOF_DMAC),
		},
		[1] = {
			/* Layer A: Ethernet: */
			[NPC_LT_LA_ETHER] =
				/* Ethertype: 2 bytes, KW0[55:40] */
				KEX_EXTR_CFG(0x01, 0xc, 0x1, 0x5),
			[NPC_LT_LA_CPT_HDR] =
				/* Ethertype: 2 bytes, KW0[55:40] */
				KEX_EXTR_CFG(0x01, 0xc, 0x1, 0x5),
		},
		[2] = {
			/* Layer B: Single VLAN (CTAG) */
			[NPC_LT_LB_CTAG] =
				/* CTAG VLAN: 2 bytes, KW1[7:0], KW0[63:56] */
				KEX_EXTR_CFG(0x01, 0x2, 0x1, 0x7),
			/* Layer B: Stacked VLAN (STAG|QinQ) */
			[NPC_LT_LB_STAG_QINQ] =
				/* Outer VLAN: 2 bytes, KW1[7:0], KW0[63:56] */
				KEX_EXTR_CFG(0x01, 0x2, 0x1, 0x7),
			[NPC_LT_LB_FDSA] =
				/* SWITCH PORT: 1 byte, KW0[63:56] */
				KEX_EXTR_CFG(0x0, 0x1, 0x1, 0x7),
		},
		[3] = {
			[NPC_LT_LB_CTAG] =
				/* Ethertype: 2 bytes, KW0[55:40] */
				KEX_EXTR_CFG(0x01, 0x4, 0x1, 0x5),
			[NPC_LT_LB_STAG_QINQ] =
				/* Ethertype: 2 bytes, KW0[55:40] */
				KEX_EXTR_CFG(0x01, 0x8, 0x1, 0x5),
			[NPC_LT_LB_FDSA] =
				/* Ethertype: 2 bytes, KW0[55:40] */
				KEX_EXTR_CFG(0x01, 0x4, 0x1, 0x5),
		},
		[4] = {
			/* Layer C: IPv4 */
			[NPC_LT_LC_IP] =
				/* SIP+DIP: 8 bytes, KW2[63:0] */
				KEX_EXTR_CFG(0x07, 0xc, 0x1, 0x10),
			/* Layer C: IPv6 */
			[NPC_LT_LC_IP6] =
				/* Everything up to SADDR: 8 bytes, KW2[63:0] */
				KEX_EXTR_CFG(0x07, 0x0, 0x1, 0x10),
		},
		[5] = {
			[NPC_LT_LC_IP] =
				/* TOS: 1 byte, KW1[63:56] */
				KEX_EXTR_CFG(0x0, 0x1, 0x1, 0xf),
		},
		[6] = {
			/* Layer D:UDP */
			[NPC_LT_LD_UDP] =
				/* SPORT+DPORT: 4 bytes, KW3[31:0] */
				KEX_EXTR_CFG(0x3, 0x0, 0x1, 0x18),
			/* Layer D:TCP */
			[NPC_LT_LD_TCP] =
				/* SPORT+DPORT: 4 bytes, KW3[31:0] */
				KEX_EXTR_CFG(0x3, 0x0, 0x1, 0x18),
		},
	},

	/* Default TX MCAM KEX profile */
	[NIX_INTF_TX] = {
		[0] = {
			/* Layer A: NIX_INST_HDR_S + Ethernet */
			/* NIX appends 8 bytes of NIX_INST_HDR_S at the
			 * start of each TX packet supplied to NPC.
			 */
			[NPC_LT_LA_IH_NIX_ETHER] =
				/* PF_FUNC: 2B , KW0 [47:32] */
				KEX_EXTR_CFG(0x01, 0x0, 0x1, 0x4),
			/* Layer A: HiGig2: */
			[NPC_LT_LA_IH_NIX_HIGIG2_ETHER] =
				/* PF_FUNC: 2B , KW0 [47:32] */
				KEX_EXTR_CFG(0x01, 0x0, 0x1, 0x4),
		},
		[1] = {
			[NPC_LT_LA_IH_NIX_ETHER] =
				/* SQ_ID 3 bytes, KW1[63:16] */
				KEX_EXTR_CFG(0x02, 0x02, 0x1, 0xa),
			[NPC_LT_LA_IH_NIX_HIGIG2_ETHER] =
				/* VID: 2 bytes, KW1[31:16] */
				KEX_EXTR_CFG(0x01, 0x10, 0x1, 0xa),
		},
		[2] = {
			/* Layer B: Single VLAN (CTAG) */
			[NPC_LT_LB_CTAG] =
				/* CTAG VLAN[2..3] KW0[63:48] */
				KEX_EXTR_CFG(0x01, 0x2, 0x1, 0x6),
			/* Layer B: Stacked VLAN (STAG|QinQ) */
			[NPC_LT_LB_STAG_QINQ] =
				/* Outer VLAN: 2 bytes, KW0[63:48] */
				KEX_EXTR_CFG(0x01, 0x2, 0x1, 0x6),
		},
		[3] = {
			[NPC_LT_LB_CTAG] =
				/* CTAG VLAN[2..3] KW1[15:0] */
				KEX_EXTR_CFG(0x01, 0x4, 0x1, 0x8),
			[NPC_LT_LB_STAG_QINQ] =
				/* Outer VLAN: 2 Bytes, KW1[15:0] */
				KEX_EXTR_CFG(0x01, 0x8, 0x1, 0x8),
		},
		[4] = {
			/* Layer C: IPv4 */
			[NPC_LT_LC_IP] =
				/* SIP+DIP: 8 bytes, KW2[63:0] */
				KEX_EXTR_CFG(0x07, 0xc, 0x1, 0x10),
			/* Layer C: IPv6 */
			[NPC_LT_LC_IP6] =
				/* Everything up to SADDR: 8 bytes, KW2[63:0] */
				KEX_EXTR_CFG(0x07, 0x0, 0x1, 0x10),
		},
		[5] = {
			/* Layer D:UDP */
			[NPC_LT_LD_UDP] =
				/* SPORT+DPORT: 4 bytes, KW3[31:0] */
				KEX_EXTR_CFG(0x3, 0x0, 0x1, 0x18),
			/* Layer D:TCP */
			[NPC_LT_LD_TCP] =
				/* SPORT+DPORT: 4 bytes, KW3[31:0] */
				KEX_EXTR_CFG(0x3, 0x0, 0x1, 0x18),
		},
	},
	},
};

struct npc_mcam_kex_extr *npc_mkex_extr_default_get(void)
{
	return &npc_mkex_extr_default;
}

struct npc_priv_t *npc_priv_get(void)
{
	return &npc_priv;
}

static int npc_subbank_idx_2_mcam_idx(struct rvu *rvu, struct npc_subbank *sb,
				      u16 sub_off, u16 *mcam_idx)
{
	int off, bot;

	/* for x4 section, maximum allowed subbank index =
	 * subsection depth - 1
	 */
	if (sb->key_type == NPC_MCAM_KEY_X4 &&
	    sub_off >= npc_priv.subbank_depth) {
		dev_err(rvu->dev, "%s:%d bad params\n",
			__func__, __LINE__);
		return -EINVAL;
	}

	/* for x2 section, maximum allowed subbank index =
	 * 2 * subsection depth - 1
	 */
	if (sb->key_type == NPC_MCAM_KEY_X2 &&
	    sub_off >= npc_priv.subbank_depth * 2) {
		dev_err(rvu->dev, "%s:%d bad params\n",
			__func__, __LINE__);
		return -EINVAL;
	}

	/* Find subbank offset from respective subbank (w.r.t bank) */
	off = sub_off & (npc_priv.subbank_depth - 1);

	/* if subsection idx is in bank1, add bank depth,
	 * which is part of sb->b1b
	 */
	bot = sub_off >= npc_priv.subbank_depth ? sb->b1b : sb->b0b;

	*mcam_idx = bot + off;
	return 0;
}

int npc_mcam_idx_2_key_type(struct rvu *rvu, u16 mcam_idx, u8 *key_type)
{
	struct npc_subbank *sb;
	int bank_off, sb_id;

	/* mcam_idx should be less than (2 * bank depth) */
	if (mcam_idx >= npc_priv.bank_depth * 2) {
		dev_err(rvu->dev, "%s:%d bad params\n",
			__func__, __LINE__);
		return -EINVAL;
	}

	/* find mcam offset per bank */
	bank_off = mcam_idx & (npc_priv.bank_depth - 1);

	/* Find subbank id */
	sb_id = bank_off / npc_priv.subbank_depth;

	/* Check if subbank id is more than maximum
	 * number of subbanks available
	 */
	if (sb_id >= npc_priv.num_subbanks) {
		dev_err(rvu->dev, "%s:%d invalid subbank %d\n",
			__func__, __LINE__, sb_id);
		return -EINVAL;
	}

	sb = &npc_priv.sb[sb_id];

	*key_type = sb->key_type;

	return 0;
}

static int npc_mcam_idx_2_subbank_idx(struct rvu *rvu, u16 mcam_idx,
				      struct npc_subbank **sb,
				      int *sb_off)
{
	int bank_off, sb_id;

	/* mcam_idx should be less than (2 * bank depth) */
	if (mcam_idx >= npc_priv.bank_depth * 2) {
		dev_err(rvu->dev, "%s:%d bad params\n",
			__func__, __LINE__);
		return -EINVAL;
	}

	/* find mcam offset per bank */
	bank_off = mcam_idx & (npc_priv.bank_depth - 1);

	/* Find subbank id */
	sb_id = bank_off / npc_priv.subbank_depth;

	/* Check if subbank id is more than maximum
	 * number of subbanks available
	 */
	if (sb_id >= npc_priv.num_subbanks) {
		dev_err(rvu->dev, "%s:%d invalid subbank %d\n",
			__func__, __LINE__, sb_id);
		return -EINVAL;
	}

	*sb = &npc_priv.sb[sb_id];

	/* Subbank offset per bank */
	*sb_off = bank_off % npc_priv.subbank_depth;

	/* Index in a subbank should add subbank depth
	 * if it is in bank1
	 */
	if (mcam_idx >= npc_priv.bank_depth)
		*sb_off += npc_priv.subbank_depth;

	return 0;
}

static int __npc_subbank_contig_alloc(struct rvu *rvu,
				      struct npc_subbank *sb,
				      int key_type, int sidx,
				      int eidx, int prio,
				      int count, int t, int b,
				      unsigned long *bmap,
				      u16 *save)
{
	int k, offset, delta = 0;
	int cnt = 0, sbd;

	sbd = npc_priv.subbank_depth;

	if (sidx >= npc_priv.bank_depth)
		delta = sbd;

	switch (prio) {
	case NPC_MCAM_LOWER_PRIO:
	case NPC_MCAM_ANY_PRIO:
		/* Find an area of size 'count' from sidx to eidx */
		offset = bitmap_find_next_zero_area(bmap, sbd, sidx - b,
						    count, 0);

		if (offset >= sbd) {
			dev_err(rvu->dev,
				"%s:%d Could not find contigious(%d) entries\n",
				__func__, __LINE__, count);
			return -EFAULT;
		}

		dev_dbg(rvu->dev,
			"%s:%d sidx=%d eidx=%d t=%d b=%d offset=%d count=%d delta=%d\n",
			__func__, __LINE__, sidx, eidx, t, b, offset, count, delta);

		for (cnt = 0; cnt < count; cnt++)
			save[cnt] = offset + cnt + delta;

		break;

	case NPC_MCAM_HIGHER_PRIO:
		/* Find an area of 'count' from eidx to sidx */
		for (k = eidx - b; cnt < count && k >= (sidx - b); k--) {
			/* If an intermediate slot is not free,
			 * reset the counter (cnt) to zero as
			 * request is for contigious.
			 */
			if (test_bit(k, bmap)) {
				cnt = 0;
				continue;
			}

			save[cnt++] = k + delta;
		}
		break;
	}

	/* Found 'count' number of free slots */
	if (cnt == count)
		return 0;

	dev_dbg(rvu->dev,
		"%s:%d Could not find contigious(%d) entries in subbbank=%u\n",
		__func__, __LINE__, count, sb->idx);
	return -EFAULT;
}

static int __npc_subbank_non_contig_alloc(struct rvu *rvu,
					  struct npc_subbank *sb,
					  int key_type, int sidx,
					  int eidx, int prio,
					  int t, int b,
					  unsigned long *bmap,
					  int count, u16 *save,
					  bool max_alloc, int *alloc_cnt)
{
	unsigned long index;
	int cnt = 0, delta;
	int k, sbd;

	sbd = npc_priv.subbank_depth;
	delta = sidx >= npc_priv.bank_depth ? sbd : 0;

	switch (prio) {
	/* Find an area of size 'count' from sidx to eidx */
	case NPC_MCAM_LOWER_PRIO:
	case NPC_MCAM_ANY_PRIO:
		index = find_next_zero_bit(bmap, sbd, sidx - b);
		if (index >= sbd) {
			dev_err(rvu->dev,
				"%s:%d Error happened to alloc %u, bitmap_weight=%u, sb->idx=%u\n",
				__func__, __LINE__, count,
				bitmap_weight(bmap, sbd),
				sb->idx);
			break;
		}

		for (k = index; cnt < count && k <= (eidx - b); k++) {
			/* Skip used slots */
			if (test_bit(k, bmap))
				continue;

			save[cnt++] = k + delta;
		}
		break;

	/* Find an area of 'count' from eidx to sidx */
	case NPC_MCAM_HIGHER_PRIO:
		for (k = eidx - b; cnt < count && k >= (sidx - b); k--) {
			/* Skip used slots */
			if (test_bit(k, bmap))
				continue;

			save[cnt++] = k + delta;
		}
		break;
	}

	/* Update allocated 'cnt' to alloc_cnt */
	*alloc_cnt = cnt;

	/* Successfully allocated requested count slots */
	if (cnt == count)
		return 0;

	/* Allocation successful for cnt < count */
	if (max_alloc && cnt > 0)
		return 0;

	dev_dbg(rvu->dev,
		"%s:%d Could not find non contigious entries(%u) in subbank(%u) cnt=%d max_alloc=%d\n",
		__func__, __LINE__, count, sb->idx, cnt, max_alloc);

	return -EFAULT;
}

static void __npc_subbank_sboff_2_off(struct rvu *rvu, struct npc_subbank *sb,
				      int sb_off, unsigned long **bmap, int *off)
{
	int sbd;

	sbd = npc_priv.subbank_depth;

	*off = sb_off & (sbd - 1);
	*bmap = (sb_off >= sbd) ? sb->b1map : sb->b0map;
}

/* set/clear bitmap */
static bool __npc_subbank_mark_slot(struct rvu *rvu,
				    struct npc_subbank *sb,
				    int sb_off, bool set)
{
	unsigned long *bmap;
	int off;

	/* if sb_off >= subbank.depth, then slots are in
	 * bank1
	 */
	__npc_subbank_sboff_2_off(rvu, sb, sb_off, &bmap, &off);

	dev_dbg(rvu->dev,
		"%s:%d Marking set=%d sb_off=%d sb->idx=%d off=%d\n",
		__func__, __LINE__, set, sb_off, sb->idx, off);

	if (set) {
		/* Slot is already used */
		if (test_bit(off, bmap))
			return false;

		sb->free_cnt--;
		set_bit(off, bmap);
		return true;
	}

	/* Slot is already free */
	if (!test_bit(off, bmap))
		return false;

	sb->free_cnt++;
	clear_bit(off, bmap);
	return true;
}

static int __npc_subbank_mark_free(struct rvu *rvu, struct npc_subbank *sb)
{
	int rc, blkaddr;
	void *val;

	sb->flags = NPC_SUBBANK_FLAG_FREE;
	sb->key_type = 0;

	bitmap_clear(sb->b0map, 0, npc_priv.subbank_depth);
	bitmap_clear(sb->b1map, 0, npc_priv.subbank_depth);

	if (!xa_erase(&npc_priv.xa_sb_used, sb->arr_idx)) {
		dev_err(rvu->dev, "%s:%d Error to delete from xa_sb_used array\n",
			__func__, __LINE__);
		return -EFAULT;
	}

	rc = xa_insert(&npc_priv.xa_sb_free, sb->arr_idx,
		       xa_mk_value(sb->idx), GFP_KERNEL);
	if (rc) {
		val = xa_load(&npc_priv.xa_sb_free, sb->arr_idx);
		dev_err(rvu->dev,
			"%s:%d Error to add sb(%u) to xa_sb_free array at arr_idx=%d, val=%lu\n",
			__func__, __LINE__, sb->idx, sb->arr_idx, xa_to_value(val));
	}

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NPC, 0);
	rvu_write64(rvu, blkaddr,
		    NPC_AF_MCAM_SECTIONX_CFG_EXT(sb->idx),
		    NPC_MCAM_KEY_X2);

	return rc;
}

static int __npc_subbank_mark_used(struct rvu *rvu, struct npc_subbank *sb,
				   int key_type)

{
	int rc;

	sb->flags = NPC_SUBBANK_FLAG_USED;
	sb->key_type = key_type;
	if (key_type == NPC_MCAM_KEY_X4)
		sb->free_cnt = npc_priv.subbank_depth;
	else
		sb->free_cnt = 2 * npc_priv.subbank_depth;

	bitmap_clear(sb->b0map, 0, npc_priv.subbank_depth);
	bitmap_clear(sb->b1map, 0, npc_priv.subbank_depth);

	if (!xa_erase(&npc_priv.xa_sb_free, sb->arr_idx)) {
		dev_err(rvu->dev, "%s:%d Error to delete from xa_sb_free array\n",
			__func__, __LINE__);
		return -EFAULT;
	}

	rc = xa_insert(&npc_priv.xa_sb_used, sb->arr_idx,
		       xa_mk_value(sb->idx), GFP_KERNEL);
	if (rc)
		dev_err(rvu->dev, "%s:%d Error to add to xa_sb_used array\n",
			__func__, __LINE__);

	return rc;
}

static bool __npc_subbank_free(struct rvu *rvu, struct npc_subbank *sb,
			       u16 sb_off)
{
	bool deleted = false;
	unsigned long *bmap;
	int rc, off;

	deleted = __npc_subbank_mark_slot(rvu, sb, sb_off, false);
	if (!deleted)
		goto done;

	__npc_subbank_sboff_2_off(rvu, sb, sb_off, &bmap, &off);

	/* Check whether we can mark whole subbank as free */
	if (sb->key_type == NPC_MCAM_KEY_X4) {
		if (sb->free_cnt < npc_priv.subbank_depth)
			goto done;
	} else {
		if (sb->free_cnt < 2 * npc_priv.subbank_depth)
			goto done;
	}

	/* All slots in subbank are unused. Mark the subbank as free
	 * and add to free pool
	 */
	rc = __npc_subbank_mark_free(rvu, sb);
	if (rc)
		dev_err(rvu->dev, "%s:%d Error to free subbank\n",
			__func__, __LINE__);

done:
	return deleted;
}

static int npc_subbank_free(struct rvu *rvu, struct npc_subbank *sb, u16 sb_off)
{
	bool deleted;

	mutex_lock(&sb->lock);
	deleted = __npc_subbank_free(rvu, sb, sb_off);
	mutex_unlock(&sb->lock);

	return deleted ? 0 : -EFAULT;
}

static int __npc_subbank_alloc(struct rvu *rvu, struct npc_subbank *sb,
			       int key_type, int ref, int limit, int prio,
			       bool contig, int count, u16 *mcam_idx,
			       int idx_sz, bool max_alloc, int *alloc_cnt)
{
	int cnt, t, b, i, blkaddr;
	bool new_sub_bank = false;
	unsigned long *bmap;
	u16 *save = NULL;
	int sidx, eidx;
	bool diffbank;
	int bw, bfree;
	int rc = 0;
	bool ret;

	/* Check if enough space is there to return requested number of
	 * mcam indexes incase of contigious allocation
	 */
	if (!max_alloc && count > idx_sz) {
		dev_err(rvu->dev,
			"%s:%d Less space, count=%d idx_sz=%d sb_id=%d\n",
			__func__, __LINE__, count, idx_sz, sb->idx);
		return -ENOSPC;
	}

	/* Allocation on mutliple subbank is not supported by this function.
	 * it means that ref and limit should be on same subbank.
	 *
	 * ref and limit values should be validated w.r.t prio as below.
	 * say ref = 100, limit = 200,
	 * if NPC_MCAM_LOWER_PRIO, allocate index 100
	 * if NPC_MCAM_HIGHER_PRIO, below sanity test returns error.
	 * if NPC_MCAM_ANY_PRIO, allocate index 100
	 *
	 * say ref = 200, limit = 100
	 * if NPC_MCAM_LOWER_PRIO, below sanity test returns error.
	 * if NPC_MCAM_HIGHER_PRIO, allocate index 200
	 * if NPC_MCAM_ANY_PRIO, allocate index 100
	 *
	 * Please note that NPC_MCAM_ANY_PRIO does not have any restriction
	 * on "ref" and "limit" values. ie, ref > limit and limit > ref
	 * are valid cases.
	 */
	if ((prio == NPC_MCAM_LOWER_PRIO && ref > limit) ||
	    (prio == NPC_MCAM_HIGHER_PRIO && ref < limit)) {
		dev_err(rvu->dev, "%s:%d Wrong ref_enty(%d) or limit(%d)\n",
			__func__, __LINE__, ref, limit);
		return -EINVAL;
	}

	/* x4 indexes are from 0 to bank size as it combines two x2 banks */
	if (key_type == NPC_MCAM_KEY_X4 &&
	    (ref >= npc_priv.bank_depth || limit >= npc_priv.bank_depth)) {
		dev_err(rvu->dev, "%s:%d Wrong ref_enty(%d) or limit(%d) for x4\n",
			__func__, __LINE__, ref, limit);
		return -EINVAL;
	}

	/* This function is called either bank0 or bank1 portion of a subbank.
	 * so ref and limit should be on same bank.
	 */
	diffbank = !!((ref & npc_priv.bank_depth) ^ (limit & npc_priv.bank_depth));
	if (diffbank) {
		dev_err(rvu->dev, "%s:%d request ref and limit should be from same bank\n",
			__func__, __LINE__);
		return -EINVAL;
	}

	sidx = min_t(int, limit, ref);
	eidx = max_t(int, limit, ref);

	/* Find total number of slots available; both used and free */
	cnt = eidx - sidx + 1;
	if (contig && cnt < count) {
		dev_err(rvu->dev, "%s:%d Wrong ref_enty(%d) or limit(%d) for count(%d)\n",
			__func__, __LINE__, ref, limit, count);
		return -EINVAL;
	}

	/* If subbank is free, check if requested number of indexes is less than
	 * or equal to mcam entries available in the subbank if contig.
	 */
	if (sb->flags & NPC_SUBBANK_FLAG_FREE) {
		if (contig && count > npc_priv.subbank_depth) {
			dev_err(rvu->dev, "%s:%d Less number of entries\n",
				__func__, __LINE__);
			goto err;
		}

		new_sub_bank = true;
		goto process;
	}

	/* Flag should be set for all used subbanks */
	WARN_ONCE(!(sb->flags & NPC_SUBBANK_FLAG_USED),
		  "Used flag is not set(%#x)\n", sb->flags);

	/* If subbank key type does not match with requested key_type,
	 * return error
	 */
	if (sb->key_type != key_type) {
		dev_dbg(rvu->dev, "%s:%d subbank key_type mismatch\n",
			__func__, __LINE__);
		rc = -EINVAL;
		goto err;
	}

process:
	/* if ref or limit >= npc_priv.bank_depth, index are in bank1.
	 * else bank0.
	 */
	if (ref >= npc_priv.bank_depth) {
		bmap = sb->b1map;
		t = sb->b1t;
		b = sb->b1b;
	} else {
		bmap = sb->b0map;
		t = sb->b0t;
		b = sb->b0b;
	}

	/* Calculate free slots */
	bw = bitmap_weight(bmap, npc_priv.subbank_depth);
	bfree = npc_priv.subbank_depth - bw;

	if (!bfree) {
		rc = -ENOSPC;
		goto err;
	}

	/* If request is for contigious, then max we can allocate is
	 * equal to subbank_depth
	 */
	if (contig && bfree < count) {
		rc = -ENOSPC;
		dev_err(rvu->dev, "%s:%d no space for entry\n",
			__func__, __LINE__);
		goto err;
	}

	/* 'save' array stores available indexes temporarily before
	 * marking it as allocated
	 */
	save = kcalloc(count, sizeof(u16), GFP_KERNEL);
	if (!save) {
		rc = -ENOMEM;
		goto err;
	}

	if (contig) {
		rc =  __npc_subbank_contig_alloc(rvu, sb, key_type,
						 sidx, eidx, prio,
						 count, t, b,
						 bmap, save);
		/* contigious allocation success means that
		 * requested number of free slots got
		 * allocated
		 */
		if (!rc)
			*alloc_cnt = count;

	} else {
		rc =  __npc_subbank_non_contig_alloc(rvu, sb, key_type,
						     sidx, eidx, prio,
						     t, b, bmap,
						     count, save,
						     max_alloc, alloc_cnt);
	}

	if (rc)
		goto err;

	/* Mark new subbank bank as used */
	if (new_sub_bank) {
		blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NPC, 0);
		if (blkaddr < 0) {
			dev_err(rvu->dev,
				"%s:%d NPC block not implemented\n",
				__func__, __LINE__);
			goto err;
		}

		rc =  __npc_subbank_mark_used(rvu, sb, key_type);
		if (rc) {
			dev_err(rvu->dev, "%s:%d Error to mark subbank as used\n",
				__func__, __LINE__);
			goto err;
		}

		/* Configure section type to key_type */
		rvu_write64(rvu, blkaddr,
			    NPC_AF_MCAM_SECTIONX_CFG_EXT(sb->idx),
			    key_type);
	}

	for (i = 0; i < *alloc_cnt; i++) {
		rc = npc_subbank_idx_2_mcam_idx(rvu, sb, save[i], &mcam_idx[i]);
		if (rc) {
			dev_err(rvu->dev, "%s:%d Error to find mcam idx for %u\n",
				__func__, __LINE__, save[i]);
			/* TODO: handle err case gracefully */
			goto err;
		}

		/* Mark all slots as used */
		ret = __npc_subbank_mark_slot(rvu, sb, save[i], true);
		if (!ret) {
			dev_err(rvu->dev, "%s:%d Error to mark mcam_idx %u\n",
				__func__, __LINE__, mcam_idx[i]);
			rc = -EFAULT;
			goto err;
		}
	}

err:
	kfree(save);
	return rc;
}

static int npc_subbank_alloc(struct rvu *rvu, struct npc_subbank *sb,
			     int key_type, int ref, int limit, int prio,
			     bool contig, int count, u16 *mcam_idx,
			     int idx_sz, bool max_alloc, int *alloc_cnt)
{
	int rc;

	mutex_lock(&sb->lock);
	rc = __npc_subbank_alloc(rvu, sb, key_type, ref, limit, prio,
				 contig, count, mcam_idx, idx_sz,
				 max_alloc, alloc_cnt);
	mutex_unlock(&sb->lock);

	return rc;
}

static int npc_del_from_pf_maps(struct rvu *rvu, u16 mcam_idx)
{
	int pcifunc, idx;
	void *map;

	map = xa_erase(&npc_priv.xa_idx2pf_map, mcam_idx);
	if (!map) {
		dev_err(rvu->dev,
			"%s:%d failed to erase mcam_idx(%u) from xa_idx2pf map\n",
			__func__, __LINE__, mcam_idx);
		return -EFAULT;
	}

	pcifunc = xa_to_value(map);
	map = xa_load(&npc_priv.xa_pf_map, pcifunc);
	idx = xa_to_value(map);

	map = xa_erase(&npc_priv.xa_pf2idx_map[idx], mcam_idx);
	if (!map) {
		dev_err(rvu->dev,
			"%s:%d failed to erase mcam_idx(%u) from xa_pf2idx_map map\n",
			__func__, __LINE__, mcam_idx);
		return -EFAULT;
	}
	return 0;
}

static int npc_add_to_pf_maps(struct rvu *rvu, u16 mcam_idx, int pcifunc)
{
	int rc, idx;
	void *map;

	dev_dbg(rvu->dev,
		"%s:%d add2maps mcam_idx(%u) to xa_idx2pf map pcifunc=%#x\n",
		__func__, __LINE__, mcam_idx, pcifunc);

	rc = xa_insert(&npc_priv.xa_idx2pf_map, mcam_idx,
		       xa_mk_value(pcifunc), GFP_KERNEL);

	if (rc) {
		map = xa_load(&npc_priv.xa_idx2pf_map, mcam_idx);
		dev_err(rvu->dev,
			"%s:%d failed to insert mcam_idx(%u) to xa_idx2pf map, existing value=%lu\n",
			__func__, __LINE__, mcam_idx, xa_to_value(map));
		return -EFAULT;
	}

	map = xa_load(&npc_priv.xa_pf_map, pcifunc);
	idx = xa_to_value(map);

	rc = xa_insert(&npc_priv.xa_pf2idx_map[idx], mcam_idx,
		       xa_mk_value(pcifunc), GFP_KERNEL);

	if (rc) {
		map = xa_load(&npc_priv.xa_pf2idx_map[idx], mcam_idx);
		dev_err(rvu->dev,
			"%s:%d failed to insert mcam_idx(%u) to xa_pf2idx_map map, earlier value=%lu idx=%u\n",
			__func__, __LINE__, mcam_idx, xa_to_value(map), idx);
		return -EFAULT;
	}

	return 0;
}

static bool npc_subbank_suits(struct npc_subbank *sb, int key_type)
{
	mutex_lock(&sb->lock);

	if (!sb->key_type) {
		mutex_unlock(&sb->lock);
		return true;
	}

	if (sb->key_type == key_type) {
		mutex_unlock(&sb->lock);
		return true;
	}

	mutex_unlock(&sb->lock);
	return false;
}

#define SB_ALIGN_UP(val)   (((val) + npc_priv.subbank_depth) & \
			    ~((npc_priv.subbank_depth) - 1))
#define SB_ALIGN_DOWN(val) ALIGN_DOWN((val), npc_priv.subbank_depth)

static void npc_subbank_iter_down(struct rvu *rvu,
				  int ref, int limit,
				  int *cur_ref, int *cur_limit,
				  bool *start, bool *stop)
{
	int align;

	*stop = false;

	/* ALIGN_DOWN the limit to current subbank boundary bottom index */
	if (*start) {
		*start = false;
		*cur_ref = ref;
		align = SB_ALIGN_DOWN(ref);
		if (align < limit) {
			*stop = true;
			*cur_limit = limit;
			return;
		}
		*cur_limit = align;
		return;
	}

	*cur_ref = *cur_limit - 1;
	align = *cur_ref - npc_priv.subbank_depth + 1;
	if (align <= limit) {
		*stop = true;
		*cur_limit = limit;
		return;
	}

	*cur_limit = align;
}

static void npc_subbank_iter_up(struct rvu *rvu,
				int ref, int limit,
				int *cur_ref, int *cur_limit,
				bool *start, bool *stop)
{
	int align;

	*stop = false;

	/* ALIGN_UP the limit to current subbank boundary top index */
	if (*start) {
		*start = false;
		*cur_ref = ref;

		/* Find next lower prio subbank's bottom index */
		align = SB_ALIGN_UP(ref);

		/* Crosses limit ? */
		if (align - 1 > limit) {
			*stop = true;
			*cur_limit = limit;
			return;
		}

		/* Current subbank's top index */
		*cur_limit = align - 1;
		return;
	}

	*cur_ref = *cur_limit + 1;
	align = *cur_ref + npc_priv.subbank_depth - 1;

	if (align >= limit) {
		*stop = true;
		*cur_limit = limit;
		return;
	}

	*cur_limit = align;
}

static int npc_subbank_iter(struct rvu *rvu, int key_type,
			    int ref, int limit, int prio,
			    int *cur_ref, int *cur_limit,
			    bool *start, bool *stop)
{
	if (prio != NPC_MCAM_HIGHER_PRIO)
		npc_subbank_iter_up(rvu, ref, limit,
				    cur_ref, cur_limit,
				    start, stop);
	else
		npc_subbank_iter_down(rvu, ref, limit,
				      cur_ref, cur_limit,
				      start, stop);

	/* limit and ref should < bank_depth for x4 */
	if (key_type == NPC_MCAM_KEY_X4) {
		if (*cur_ref >= npc_priv.bank_depth)
			return -EINVAL;

		if (*cur_limit >= npc_priv.bank_depth)
			return -EINVAL;
	}
	/* limit and ref should < 2 * bank_depth, for x2 */
	if (*cur_ref >= 2 * npc_priv.bank_depth)
		return -EINVAL;

	if (*cur_limit >= 2 * npc_priv.bank_depth)
		return -EINVAL;

	return 0;
}

static int npc_idx_free(struct rvu *rvu, u16 *mcam_idx, int count,
			bool maps_del)
{
	struct npc_subbank *sb;
	int idx, i;
	bool ret;
	int rc;

	for (i = 0; i < count; i++) {
		rc =  npc_mcam_idx_2_subbank_idx(rvu, mcam_idx[i],
						 &sb, &idx);
		if (rc)
			return rc;

		ret = npc_subbank_free(rvu, sb, idx);
		if (ret)
			return -EINVAL;

		if (!maps_del)
			continue;

		rc = npc_del_from_pf_maps(rvu, mcam_idx[i]);
		if (rc)
			return rc;
	}

	return 0;
}

static int npc_multi_subbank_ref_alloc(struct rvu *rvu, int key_type,
				       int ref, int limit, int prio,
				       bool contig, int count,
				       u16 *mcam_idx)
{
	struct npc_subbank *sb;
	unsigned long *bmap;
	int sb_off, off, rc;
	int cnt = 0;
	bool bitset;

	if (prio != NPC_MCAM_HIGHER_PRIO) {
		while (ref <= limit) {
			/* Calculate subbank and subbank index */
			rc =  npc_mcam_idx_2_subbank_idx(rvu, ref,
							 &sb, &sb_off);
			if (rc)
				goto err;

			/* If subbank is not suitable for requested key type
			 * restart search from next subbank
			 */
			if (!npc_subbank_suits(sb, key_type)) {
				ref = SB_ALIGN_UP(ref);
				if (contig) {
					rc = npc_idx_free(rvu, mcam_idx, cnt, false);
					if (rc)
						return rc;
					cnt = 0;
				}
				continue;
			}

			mutex_lock(&sb->lock);

			/* If subbank is free; mark it as used */
			if (sb->flags & NPC_SUBBANK_FLAG_FREE) {
				rc =  __npc_subbank_mark_used(rvu, sb, key_type);
				if (rc) {
					mutex_unlock(&sb->lock);
					dev_err(rvu->dev,
						"%s:%d Error to add to use array\n",
						__func__, __LINE__);
					goto err;
				}
			}

			/* Find correct bmap */
			__npc_subbank_sboff_2_off(rvu, sb, sb_off, &bmap, &off);

			/* if bit is already set, resset 'cnt' */
			bitset = test_bit(off, bmap);
			if (bitset) {
				mutex_unlock(&sb->lock);
				if (contig) {
					rc = npc_idx_free(rvu, mcam_idx, cnt, false);
					if (rc)
						return rc;
					cnt = 0;
				}

				ref++;
				continue;
			}

			set_bit(off, bmap);
			sb->free_cnt--;
			mcam_idx[cnt++] = ref;
			mutex_unlock(&sb->lock);

			if (cnt == count)
				return 0;
			ref++;
		}

		/* Could not allocate request count slots */
		goto err;
	}
	while (ref >= limit) {
		rc =  npc_mcam_idx_2_subbank_idx(rvu, ref,
						 &sb, &sb_off);
		if (rc)
			goto err;

		if (!npc_subbank_suits(sb, key_type)) {
			ref = SB_ALIGN_DOWN(ref) - 1;
			if (contig) {
				rc = npc_idx_free(rvu, mcam_idx, cnt, false);
				if (rc)
					return rc;

				cnt = 0;
			}
			continue;
		}

		mutex_lock(&sb->lock);

		if (sb->flags & NPC_SUBBANK_FLAG_FREE) {
			rc =  __npc_subbank_mark_used(rvu, sb, key_type);
			if (rc) {
				mutex_unlock(&sb->lock);
				dev_err(rvu->dev,
					"%s:%d Error to add to use array\n",
					__func__, __LINE__);
				goto err;
			}
		}

		__npc_subbank_sboff_2_off(rvu, sb, sb_off, &bmap, &off);
		bitset = test_bit(off, bmap);
		if (bitset) {
			mutex_unlock(&sb->lock);
			if (contig) {
				cnt = 0;
				rc = npc_idx_free(rvu, mcam_idx, cnt, false);
				if (rc)
					return rc;
			}
			ref--;
			continue;
		}

		mcam_idx[cnt++] = ref;
		sb->free_cnt--;
		set_bit(off, bmap);
		mutex_unlock(&sb->lock);

		if (cnt == count)
			return 0;
		ref--;
	}

err:
	rc = npc_idx_free(rvu, mcam_idx, cnt, false);
	if (rc)
		dev_err(rvu->dev,
			"%s:%d Error happend while freeing cnt=%u indexes\n",
			__func__, __LINE__, cnt);

	return -ENOSPC;
}

static int npc_subbank_free_cnt(struct rvu *rvu, struct npc_subbank *sb,
				int key_type)
{
	int cnt, spd;

	spd = npc_priv.subbank_depth;
	mutex_lock(&sb->lock);

	if (sb->flags & NPC_SUBBANK_FLAG_FREE)
		cnt = key_type == NPC_MCAM_KEY_X4 ? spd : 2 * spd;
	else
		cnt = sb->free_cnt;

	mutex_unlock(&sb->lock);
	return cnt;
}

static int npc_subbank_ref_alloc(struct rvu *rvu, int key_type,
				 int ref, int limit, int prio,
				 bool contig, int count,
				 u16 *mcam_idx)
{
	struct npc_subbank *sb1, *sb2;
	bool max_alloc, start, stop;
	int r, l, sb_idx1, sb_idx2;
	int tot = 0, rc;
	int alloc_cnt;

	max_alloc = !contig;

	start = true;
	stop = false;

	/* Loop until we cross the ref/limit boundary */
	while (!stop) {
		rc = npc_subbank_iter(rvu, key_type, ref, limit, prio,
				      &r, &l, &start, &stop);

		dev_dbg(rvu->dev,
			"%s:%d ref=%d limit=%d r=%d l=%d start=%d stop=%d tot=%d count=%d rc=%d\n",
			__func__, __LINE__, ref, limit, r, l, start, stop, tot, count, rc);

		if (rc)
			goto err;

		/* Find subbank and subbank index for ref */
		rc = npc_mcam_idx_2_subbank_idx(rvu, r, &sb1,
						&sb_idx1);
		if (rc)
			goto err;

		dev_dbg(rvu->dev,
			"%s:%d ref subbank=%d off=%d\n",
			__func__, __LINE__, sb1->idx, sb_idx1);

		/* Skip subbank if it is not available for the keytype */
		if (!npc_subbank_suits(sb1, key_type)) {
			dev_dbg(rvu->dev,
				"%s:%d not suitable sb=%d key_type=%d\n",
				__func__, __LINE__, sb1->idx, key_type);
			continue;
		}

		/* Find subbank and subbank index for limit */
		rc = npc_mcam_idx_2_subbank_idx(rvu, l, &sb2,
						&sb_idx2);
		if (rc)
			goto err;

		dev_dbg(rvu->dev,
			"%s:%d limit subbank=%d off=%d\n",
			__func__, __LINE__, sb_idx1, sb_idx2);

		/* subbank of ref and limit should be same */
		if (sb1 != sb2) {
			dev_err(rvu->dev,
				"%s:%d l(%d) and r(%d) are not in same subbank\n",
				__func__, __LINE__, r, l);
			goto err;
		}

		if (contig && npc_subbank_free_cnt(rvu, sb1, key_type) < count) {
			dev_dbg(rvu->dev, "%s:%d less count =%d\n",
				__func__, __LINE__,
				npc_subbank_free_cnt(rvu, sb1, key_type));
			continue;
		}

		/* Try in one bank of a subbank */
		alloc_cnt = 0;
		rc =  npc_subbank_alloc(rvu, sb1, key_type,
					r, l, prio, contig,
					count - tot, mcam_idx + tot,
					count - tot, max_alloc,
					&alloc_cnt);

		tot += alloc_cnt;

		dev_dbg(rvu->dev, "%s:%d Allocated tot=%d alloc_cnt=%d\n",
			__func__, __LINE__, tot, alloc_cnt);

		if (!rc && count == tot)
			return 0;
	}
err:
	dev_dbg(rvu->dev, "%s:%d Error to allocate\n",
		__func__, __LINE__);

	/* non contigous allocation fails. We need to do clean up */
	if (max_alloc) {
		rc = npc_idx_free(rvu, mcam_idx, tot, false);
		if (rc)
			dev_err(rvu->dev,
				"%s:%d failed to free %u indexes\n",
				 __func__, __LINE__, tot);
	}

	return -EFAULT;
}

/* Minimize allocation from bottom and top subbanks for noref allocations.
 * Default allocations are ref based, and will be allocated from top
 * subbanks (least priority subbanks). Since default allocation is at very
 * early stage of kernel netdev probes, this subbanks will be moved to
 * used subbanks list. This will pave a way for noref allocation from these
 * used subbanks. Skip allocation for these top and bottom, and try free
 * bank next. If none slot is available, come back and search in these
 * subbanks.
 */
static const int npc_subbank_restricted_idxs[] = {31, /* subbank 31 */
						  0, /* subbank 0 */};

static bool npc_subbank_restrict_usage(struct rvu *rvu, int index)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(npc_subbank_restricted_idxs); i++) {
		if (index == npc_subbank_restricted_idxs[i])
			return true;
	}

	return false;
}

static int npc_subbank_noref_alloc(struct rvu *rvu, int key_type, bool contig,
				   int count, u16 *mcam_idx)
{
	struct npc_subbank *sb;
	unsigned long index;
	int tot = 0, rc;
	bool max_alloc;
	int alloc_cnt;
	int idx, i;
	void *val;

	max_alloc = !contig;

	/* Check used subbanks for free slots */
	xa_for_each(&npc_priv.xa_sb_used, index, val) {
		idx = xa_to_value(val);

		/* Minimize allocation from restricted subbanks
		 * in noref allocations.
		 */
		if (npc_subbank_restrict_usage(rvu, index))
			continue;

		sb = &npc_priv.sb[idx];

		/* Skip if not suitable subbank */
		if (!npc_subbank_suits(sb, key_type))
			continue;

		if (contig && npc_subbank_free_cnt(rvu, sb, key_type) < count)
			continue;

		/* try in bank 0. Try passing ref and limit equal to
		 * subbank boundaries
		 */
		alloc_cnt = 0;
		rc =  npc_subbank_alloc(rvu, sb, key_type,
					sb->b0b, sb->b0t, 0,
					contig, count - tot,
					mcam_idx + tot,
					count - tot,
					max_alloc, &alloc_cnt);

		/* Non contigious allocation may allocate less than
		 * requested 'count'.
		 */
		tot += alloc_cnt;

		dev_dbg(rvu->dev,
			"%s:%d Allocated %d from subbank %d, tot=%d count=%d\n",
			__func__, __LINE__, alloc_cnt, sb->idx, tot, count);

		/* Successfully allocated */
		if (!rc && count == tot)
			return 0;

		/* x4 entries can be allocated from bank 0 only */
		if (key_type == NPC_MCAM_KEY_X4)
			continue;

		/* try in bank 1 for x2 */
		alloc_cnt = 0;
		rc =  npc_subbank_alloc(rvu, sb, key_type,
					sb->b1b, sb->b1t, 0,
					contig, count - tot,
					mcam_idx + tot,
					count - tot, max_alloc,
					&alloc_cnt);

		tot += alloc_cnt;

		dev_dbg(rvu->dev,
			"%s:%d Allocated %d from subbank %d, tot=%d count=%d\n",
			__func__, __LINE__, alloc_cnt, sb->idx, tot, count);

		if (!rc && count == tot)
			return 0;
	}

	/* Allocate in free subbanks */
	xa_for_each(&npc_priv.xa_sb_free, index, val) {
		idx = xa_to_value(val);
		sb = &npc_priv.sb[idx];

		/* Minimize allocation from restricted subbanks
		 * in noref allocations.
		 */
		if (npc_subbank_restrict_usage(rvu, index))
			continue;

		if (!npc_subbank_suits(sb, key_type))
			continue;

		/* try in bank 0 */
		alloc_cnt = 0;
		rc =  npc_subbank_alloc(rvu, sb, key_type,
					sb->b0b, sb->b0t, 0,
					contig, count - tot,
					mcam_idx + tot,
					count - tot,
					max_alloc, &alloc_cnt);

		tot += alloc_cnt;

		dev_dbg(rvu->dev,
			"%s:%d Allocated %d from subbank %d, tot=%d count=%d\n",
			__func__, __LINE__, alloc_cnt, sb->idx, tot, count);

		/* Successfully allocated */
		if (!rc && count == tot)
			return 0;

		/* x4 entries can be allocated from bank 0 only */
		if (key_type == NPC_MCAM_KEY_X4)
			continue;

		/* try in bank 1 for x2 */
		alloc_cnt = 0;
		rc =  npc_subbank_alloc(rvu, sb,
					key_type, sb->b1b, sb->b1t, 0,
					contig, count - tot,
					mcam_idx + tot, count - tot,
					max_alloc, &alloc_cnt);

		tot += alloc_cnt;

		dev_dbg(rvu->dev,
			"%s:%d Allocated %d from subbank %d, tot=%d count=%d\n",
			__func__, __LINE__, alloc_cnt, sb->idx, tot, count);

		if (!rc && count == tot)
			return 0;
	}

	/* Allocate from restricted subbanks */
	for (i = 0; i < ARRAY_SIZE(npc_subbank_restricted_idxs); i++) {
		idx = npc_subbank_restricted_idxs[i];
		sb = &npc_priv.sb[idx];

		/* Skip if not suitable subbank */
		if (!npc_subbank_suits(sb, key_type))
			continue;

		if (contig && npc_subbank_free_cnt(rvu, sb, key_type) < count)
			continue;

		/* try in bank 0. Try passing ref and limit equal to
		 * subbank boundaries
		 */
		alloc_cnt = 0;
		rc =  npc_subbank_alloc(rvu, sb, key_type,
					sb->b0b, sb->b0t, 0,
					contig, count - tot,
					mcam_idx + tot,
					count - tot,
					max_alloc, &alloc_cnt);

		/* Non contigious allocation may allocate less than
		 * requested 'count'.
		 */
		tot += alloc_cnt;

		dev_dbg(rvu->dev,
			"%s:%d Allocated %d from subbank %d, tot=%d count=%d\n",
			__func__, __LINE__, alloc_cnt, sb->idx, tot, count);

		/* Successfully allocated */
		if (!rc && count == tot)
			return 0;

		/* x4 entries can be allocated from bank 0 only */
		if (key_type == NPC_MCAM_KEY_X4)
			continue;

		/* try in bank 1 for x2 */
		alloc_cnt = 0;
		rc =  npc_subbank_alloc(rvu, sb, key_type,
					sb->b1b, sb->b1t, 0,
					contig, count - tot,
					mcam_idx + tot,
					count - tot, max_alloc,
					&alloc_cnt);

		tot += alloc_cnt;

		dev_dbg(rvu->dev,
			"%s:%d Allocated %d from subbank %d, tot=%d count=%d\n",
			__func__, __LINE__, alloc_cnt, sb->idx, tot, count);

		if (!rc && count == tot)
			return 0;
	}

	/* non contigous allocation fails. We need to do clean up */
	if (max_alloc)
		npc_idx_free(rvu, mcam_idx, tot, false);

	dev_dbg(rvu->dev, "%s:%d non-contig allocation fails\n",
		__func__, __LINE__);

	return -EFAULT;
}

int npc_cn20k_idx_free(struct rvu *rvu, u16 *mcam_idx, int count)
{
	return npc_idx_free(rvu, mcam_idx, count, true);
}

int npc_cn20k_ref_idx_alloc(struct rvu *rvu, int pcifunc, int key_type,
			    int prio, u16 *mcam_idx, int ref, int limit,
			    bool contig, int count)
{
	int i, eidx, rc, bd;
	bool ref_valid;

	bd = npc_priv.bank_depth;

	/* Special case: ref == 0 && limit= 0 && prio == HIGH && count == 1
	 * Here user wants to allocate 0th entry
	 */
	if (!ref && !limit && prio == NPC_MCAM_HIGHER_PRIO &&
	    count == 1) {
		rc = npc_subbank_ref_alloc(rvu, key_type, ref, limit,
					   prio, contig, count, mcam_idx);

		if (rc)
			return rc;
		goto add2map;
	}

	ref_valid = !!(limit || ref);
	if (!ref_valid) {
		if (contig && count > npc_priv.subbank_depth)
			goto try_noref_multi_subbank;

		rc = npc_subbank_noref_alloc(rvu, key_type, contig,
					     count, mcam_idx);
		if (!rc)
			goto add2map;

try_noref_multi_subbank:
		eidx = (key_type == NPC_MCAM_KEY_X4) ? bd - 1 : 2 * bd - 1;

		if (prio == NPC_MCAM_HIGHER_PRIO)
			rc = npc_multi_subbank_ref_alloc(rvu, key_type,
							 eidx, 0,
							 NPC_MCAM_HIGHER_PRIO,
							 contig, count,
							 mcam_idx);
		else
			rc = npc_multi_subbank_ref_alloc(rvu, key_type,
							 0, eidx,
							 NPC_MCAM_LOWER_PRIO,
							 contig, count,
							 mcam_idx);

		if (!rc)
			goto add2map;

		return rc;
	}

	if ((prio == NPC_MCAM_LOWER_PRIO && ref > limit) ||
	    (prio == NPC_MCAM_HIGHER_PRIO && ref < limit)) {
		dev_err(rvu->dev, "%s:%d Wrong ref_enty(%d) or limit(%d)\n",
			__func__, __LINE__, ref, limit);
		return -EINVAL;
	}

	if ((key_type == NPC_MCAM_KEY_X4 && (ref >= bd || limit >= bd)) ||
	    (key_type == NPC_MCAM_KEY_X2 && (ref >= 2 * bd || limit >= 2 * bd))) {
		dev_err(rvu->dev, "%s:%d Wrong ref_enty(%d) or limit(%d)\n",
			__func__, __LINE__, ref, limit);
		return -EINVAL;
	}

	if (contig && count > npc_priv.subbank_depth)
		goto try_ref_multi_subbank;

	rc = npc_subbank_ref_alloc(rvu, key_type, ref, limit,
				   prio, contig, count, mcam_idx);
	if (!rc)
		goto add2map;

try_ref_multi_subbank:
	rc = npc_multi_subbank_ref_alloc(rvu, key_type,
					 ref, limit, prio,
					 contig, count, mcam_idx);
	if (!rc)
		goto add2map;

	return rc;

add2map:
	for (i = 0; i < count; i++) {
		rc = npc_add_to_pf_maps(rvu, mcam_idx[i], pcifunc);
		if (rc)
			return rc;
	}

	return 0;
}

void npc_cn20k_subbank_calc_free(struct rvu *rvu, int *x2_free, int *x4_free, int *sb_free)
{
	struct npc_subbank *sb;
	int i;

	/* Reset all stats to zero */
	*x2_free = 0;
	*x4_free = 0;
	*sb_free = 0;

	for (i = 0; i < npc_priv.num_subbanks; i++) {
		sb = &npc_priv.sb[i];
		mutex_lock(&sb->lock);

		/* Count number of free subbanks */
		if (sb->flags & NPC_SUBBANK_FLAG_FREE) {
			(*sb_free)++;
			goto next;
		}

		/* Sumup x4 free count */
		if (sb->key_type == NPC_MCAM_KEY_X4) {
			(*x4_free) += sb->free_cnt;
			goto next;
		}

		/* Sumup x2 free counts */
		(*x2_free) += sb->free_cnt;
next:
		mutex_unlock(&sb->lock);
	}
}

static const int
subbank_srch_order[MAX_NUM_SUB_BANKS] = {
					/* 30th index subbank 0 */
					    /*[0]*/ 30,
					 /*[1]*/15, /*[2]*/17,
					 /*[3]*/14, /*[4]*/18,
					 /*[5]*/13, /*[6]*/19,
					 /*[7]*/12, /*[8]*/20,
					 /*[9]*/11, /*[10]*/21,
					 /*[11]*/10, /*[12]*/22,
					 /*[13]*/9, /*[14]*/23,
					 /*[15]*/8, /*[16]*/24,
					 /*[17]*/7, /*[18]*/25,
					 /*[19]*/6, /*[20]*/26,
					 /*[21]*/5, /*[22]*/27,
					 /*[23]*/4, /*[24]*/28,
					 /*[25]*/3, /*[26]*/29,
					 /*[27]*/2, /*[28]*/16,
					 /*[29]*/1, /*[30]*/0,
					     /*[31]*/31,
					/* 31th index subbank 31 */};

static void npc_subbank_init(struct rvu *rvu, struct npc_subbank *sb, int idx)
{
	mutex_init(&sb->lock);

	sb->b0b = idx * npc_priv.subbank_depth;
	sb->b0t = sb->b0b + npc_priv.subbank_depth - 1;

	sb->b1b = npc_priv.bank_depth + idx * npc_priv.subbank_depth;
	sb->b1t = sb->b1b + npc_priv.subbank_depth - 1;

	sb->flags = NPC_SUBBANK_FLAG_FREE;
	sb->idx = idx;
	sb->arr_idx = subbank_srch_order[idx];

	 dev_dbg(rvu->dev, "%s:%d sb->idx=%u sb->arr_idx=%u\n",
		 __func__, __LINE__, sb->idx, sb->arr_idx);

	/* Keep first and last subbank at end of free array; so that
	 * it will be used at last
	 */
	xa_store(&npc_priv.xa_sb_free, sb->arr_idx,
		 xa_mk_value(sb->idx), GFP_KERNEL);
}

static int npc_pcifunc_map_create(struct rvu *rvu)
{
	int pf, vf, numvfs;
	int cnt = 0;
	u16 pcifunc;
	u64 cfg;

	for (pf = 0; pf < rvu->hw->total_pfs; pf++) {
		cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_CFG(pf));
		numvfs = (cfg >> 12) & 0xFF;

		/* Skip not enabled PFs */
		if (!(cfg & BIT_ULL(20)))
			goto chk_vfs;

		/* If Admin function, check on VFs */
		if (cfg & BIT_ULL(21))
			goto chk_vfs;

		pcifunc = pf << 9;

		xa_store(&npc_priv.xa_pf_map, (unsigned long)pcifunc,
			 xa_mk_value(cnt), GFP_KERNEL);

		cnt++;

chk_vfs:
		for (vf = 0; vf < numvfs; vf++) {
			pcifunc = (pf << 9) | (vf + 1);

			xa_store(&npc_priv.xa_pf_map, (unsigned long)pcifunc,
				 xa_mk_value(cnt), GFP_KERNEL);
			cnt++;
		}
	}

	return cnt;
}

static int npc_priv_init(struct rvu *rvu)
{
	struct npc_mcam *mcam = &rvu->hw->mcam;
	int blkaddr, num_banks, bank_depth;
	int num_subbanks, subbank_depth;
	u64 npc_const1, npc_const2 = 0;
	struct npc_subbank *sb;
	u64 cfg;
	int i;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NPC, 0);
	if (blkaddr < 0) {
		dev_err(rvu->dev, "%s:%d NPC block not implemented\n",
			__func__, __LINE__);
		return -ENODEV;
	}

	npc_const1 = rvu_read64(rvu, blkaddr, NPC_AF_CONST1);
	if (npc_const1 & BIT_ULL(63))
		npc_const2 = rvu_read64(rvu, blkaddr, NPC_AF_CONST2);

	num_banks = mcam->banks;
	bank_depth = mcam->banksize;

	num_subbanks = FIELD_GET(GENMASK_ULL(39, 32), npc_const2);
	if (npc_priv.num_subbanks != num_subbanks) {
		dev_err(rvu->dev, "%s:%d number of subbanks(%d) should be %u\n",
			__func__, __LINE__, num_subbanks, MAX_NUM_SUB_BANKS);
		return -EINVAL;
	}

	subbank_depth =	bank_depth / num_subbanks;
	if (subbank_depth != MAX_SUBBANK_DEPTH) {
		dev_err(rvu->dev,
			"%s:%d subbank depth(%d) is not equal to %u\n",
			__func__, __LINE__, subbank_depth, MAX_SUBBANK_DEPTH);
	}

	npc_priv.bank_depth = bank_depth;
	npc_priv.subbank_depth = subbank_depth;

	/* Get kex configured key size */
	cfg = rvu_read64(rvu, blkaddr, NPC_AF_INTFX_KEX_CFG(0));
	npc_priv.kw = FIELD_GET(GENMASK_ULL(34, 32), cfg);

	dev_info(rvu->dev,
		 "banks=%u depth=%u, subbanks=%u depth=%u, key type=%s\n",
		 num_banks, bank_depth, num_subbanks, subbank_depth,
		 npc_kw_name[npc_priv.kw]);

	npc_priv.sb = kcalloc(num_subbanks, sizeof(struct npc_subbank), GFP_KERNEL);
	if (!npc_priv.sb)
		return -ENOMEM;

	xa_init_flags(&npc_priv.xa_sb_used, XA_FLAGS_ALLOC);
	xa_init_flags(&npc_priv.xa_sb_free, XA_FLAGS_ALLOC);
	xa_init_flags(&npc_priv.xa_idx2pf_map, XA_FLAGS_ALLOC);
	xa_init_flags(&npc_priv.xa_pf_map, XA_FLAGS_ALLOC);
	xa_init_flags(&npc_priv.xa_pf2dfl_rmap, XA_FLAGS_ALLOC);

	/* Initialize subbanks */
	for (i = 0, sb = npc_priv.sb; i < num_subbanks; i++, sb++)
		npc_subbank_init(rvu, sb, i);

	/* Get number of pcifuncs in the system */
	npc_priv.pf_cnt = npc_pcifunc_map_create(rvu);
	npc_priv.xa_pf2idx_map = kcalloc(npc_priv.pf_cnt, sizeof(struct xarray),
					 GFP_KERNEL);
	if (!npc_priv.xa_pf2idx_map)
		return -ENOMEM;

	for (i = 0; i < npc_priv.pf_cnt; i++)
		xa_init_flags(&npc_priv.xa_pf2idx_map[i], XA_FLAGS_ALLOC);

	return 0;
}

static void npc_config_kpmcam(struct rvu *rvu, int blkaddr,
			      const struct npc_kpu_profile_cam *kpucam,
			      int kpm, int entry)
{
	struct npc_kpu_cam cam0 = {0};
	struct npc_kpu_cam cam1 = {0};

	cam1.state = kpucam->state & kpucam->state_mask;
	cam1.dp0_data = kpucam->dp0 & kpucam->dp0_mask;
	cam1.dp1_data = kpucam->dp1 & kpucam->dp1_mask;
	cam1.dp2_data = kpucam->dp2 & kpucam->dp2_mask;

	cam0.state = ~kpucam->state & kpucam->state_mask;
	cam0.dp0_data = ~kpucam->dp0 & kpucam->dp0_mask;
	cam0.dp1_data = ~kpucam->dp1 & kpucam->dp1_mask;
	cam0.dp2_data = ~kpucam->dp2 & kpucam->dp2_mask;

	rvu_write64(rvu, blkaddr,
		    NPC_AF_KPMX_ENTRYX_CAMX(kpm, entry, 0), *(u64 *)&cam0);
	rvu_write64(rvu, blkaddr,
		    NPC_AF_KPMX_ENTRYX_CAMX(kpm, entry, 1), *(u64 *)&cam1);
}

void npc_config_kpmaction(struct rvu *rvu, int blkaddr,
			  const struct npc_kpu_profile_action *kpuaction,
			  int kpm, int entry, bool pkind)
{
	struct npc_kpm_action0 action0 = {0};
	struct npc_kpu_action1 action1 = {0};
	u64 reg;

	action1.errlev = kpuaction->errlev;
	action1.errcode = kpuaction->errcode;
	action1.dp0_offset = kpuaction->dp0_offset;
	action1.dp1_offset = kpuaction->dp1_offset;
	action1.dp2_offset = kpuaction->dp2_offset;

	if (pkind)
		reg = NPC_AF_PKINDX_ACTION1(entry);
	else
		reg = NPC_AF_KPMX_ENTRYX_ACTION1(kpm, entry);

	rvu_write64(rvu, blkaddr, reg, *(u64 *)&action1);

	action0.byp_count = kpuaction->bypass_count;
	action0.capture_ena = kpuaction->cap_ena;
	action0.parse_done = kpuaction->parse_done;
	action0.next_state = kpuaction->next_state;
	action0.capture_lid = kpuaction->lid;
	action0.capture_ltype = kpuaction->ltype;
	action0.capture_flags = kpuaction->flags;
	action0.ptr_advance = kpuaction->ptr_advance;
	action0.var_len_offset = kpuaction->offset;
	action0.var_len_mask = kpuaction->mask;
	action0.var_len_right = kpuaction->right;
	action0.var_len_shift = kpuaction->shift;

	if (pkind)
		reg = NPC_AF_PKINDX_ACTION0(entry);
	else
		reg = NPC_AF_KPMX_ENTRYX_ACTION0(kpm, entry);

	rvu_write64(rvu, blkaddr, reg, *(u64 *)&action0);
}

static void npc_program_single_kpm_profile(struct rvu *rvu, int blkaddr,
					   int kpm, int start_entry,
					   const struct npc_kpu_profile *profile)
{
	int entry, num_entries, max_entries;
	u64 idx;

	if (profile->cam_entries != profile->action_entries) {
		dev_err(rvu->dev,
			"kpm%d: CAM and action entries [%d != %d] not equal\n",
			kpm, profile->cam_entries, profile->action_entries);
	}

	max_entries = rvu->hw->npc_kpu_entries / 2;
	entry = start_entry;
	/* Program CAM match entries for previous kpm extracted data */
	num_entries = min_t(int, profile->cam_entries, max_entries);
	for (idx = 0; entry < num_entries + start_entry; entry++, idx++)
		npc_config_kpmcam(rvu, blkaddr, &profile->cam[idx], kpm, entry);

	entry = start_entry;
	/* Program this kpm's actions */
	num_entries = min_t(int, profile->action_entries, max_entries);
	for (idx = 0; entry < num_entries + start_entry; entry++, idx++)
		npc_config_kpmaction(rvu, blkaddr, &profile->action[idx],
				     kpm, entry, false);
}

static void npc_enable_kpm_entry(struct rvu *rvu, int blkaddr, int kpm, int num_entries)
{
	u64 entry_mask;

	entry_mask = npc_enable_mask(num_entries);
	/* Disable first KPU_MAX_CST_ENT entries for built-in profile */
	if (!rvu->kpu.custom)
		entry_mask |= GENMASK_ULL(KPU_MAX_CST_ENT - 1, 0);
	rvu_write64(rvu, blkaddr,
		    NPC_AF_KPMX_ENTRY_DISX(kpm, 0), entry_mask);
	if (num_entries <= 64) {
		/* Disable all the entries in W1, W2 and W3 */
		rvu_write64(rvu, blkaddr,
			    NPC_AF_KPMX_ENTRY_DISX(kpm, 1),
			    npc_enable_mask(0));
		rvu_write64(rvu, blkaddr,
			    NPC_AF_KPMX_ENTRY_DISX(kpm, 2),
			    npc_enable_mask(0));
		rvu_write64(rvu, blkaddr,
			    NPC_AF_KPMX_ENTRY_DISX(kpm, 3),
			    npc_enable_mask(0));
		return;
	}

	num_entries = num_entries - 64;
	entry_mask = npc_enable_mask(num_entries);
	rvu_write64(rvu, blkaddr,
		    NPC_AF_KPMX_ENTRY_DISX(kpm, 1), entry_mask);
	if (num_entries <= 64) {
		/* Disable all the entries in W2 and W3 */
		rvu_write64(rvu, blkaddr,
			    NPC_AF_KPMX_ENTRY_DISX(kpm, 2),
			    npc_enable_mask(0));
		rvu_write64(rvu, blkaddr,
			    NPC_AF_KPMX_ENTRY_DISX(kpm, 3),
			    npc_enable_mask(0));
		return;
	}

	num_entries = num_entries - 64;
	entry_mask = npc_enable_mask(num_entries);
	rvu_write64(rvu, blkaddr,
		    NPC_AF_KPMX_ENTRY_DISX(kpm, 2), entry_mask);
	if (num_entries <= 64) {
		/* Disable all the entries in W3 */
		rvu_write64(rvu, blkaddr,
			    NPC_AF_KPMX_ENTRY_DISX(kpm, 3),
			    npc_enable_mask(0));
		return;
	}

	num_entries = num_entries - 64;
	entry_mask = npc_enable_mask(num_entries);
	rvu_write64(rvu, blkaddr,
		    NPC_AF_KPMX_ENTRY_DISX(kpm, 3), entry_mask);
}

static void npc_program_kpm_profile(struct rvu *rvu, int blkaddr, int num_kpms)
{
	const struct npc_kpu_profile *profile1, *profile2;
	int idx, total_cam_entries;

	for (idx = 0; idx < num_kpms; idx++) {
		profile1 = &rvu->kpu.kpu[idx];
		npc_program_single_kpm_profile(rvu, blkaddr, idx, 0, profile1);
		profile2 = &rvu->kpu.kpu[idx + KPU_OFFSET];
		npc_program_single_kpm_profile(rvu, blkaddr, idx,
					       profile1->cam_entries,
					       profile2);
		total_cam_entries = profile1->cam_entries + profile2->cam_entries;
		npc_enable_kpm_entry(rvu, blkaddr, idx, total_cam_entries);
		rvu_write64(rvu, blkaddr, NPC_AF_KPMX_PASS2_OFFSET(idx),
			    profile1->cam_entries);
		/* Enable the KPUs associated with this KPM */
		rvu_write64(rvu, blkaddr, NPC_AF_KPUX_CFG(idx), 0x01);
		rvu_write64(rvu, blkaddr, NPC_AF_KPUX_CFG(idx + KPU_OFFSET), 0x01);
	}
}

void npc_cn20k_parser_profile_init(struct rvu *rvu, int blkaddr)
{
	struct rvu_hwinfo *hw = rvu->hw;
	int num_pkinds, idx;

	/* Disable all KPMs and their entries */
	for (idx = 0; idx < hw->npc_kpms; idx++) {
		rvu_write64(rvu, blkaddr,
			    NPC_AF_KPMX_ENTRY_DISX(idx, 0), ~0ULL);
		rvu_write64(rvu, blkaddr,
			    NPC_AF_KPMX_ENTRY_DISX(idx, 1), ~0ULL);
		rvu_write64(rvu, blkaddr,
			    NPC_AF_KPMX_ENTRY_DISX(idx, 2), ~0ULL);
		rvu_write64(rvu, blkaddr,
			    NPC_AF_KPMX_ENTRY_DISX(idx, 3), ~0ULL);
	}

	for (idx = 0; idx < hw->npc_kpus; idx++)
		rvu_write64(rvu, blkaddr, NPC_AF_KPUX_CFG(idx), 0x00);

	/* Load and customize KPU profile. */
	npc_load_kpu_profile(rvu);

	/* Configure KPU and KPM mapping for second pass */
	rvu_write64(rvu, blkaddr, NPC_AF_KPM_PASS2_CFG, 0x76543210);

	/* First program IKPU profile i.e PKIND configs.
	 * Check HW max count to avoid configuring junk or
	 * writing to unsupported CSR addresses.
	 */
	num_pkinds = rvu->kpu.pkinds;
	num_pkinds = min_t(int, hw->npc_pkinds, num_pkinds);

	for (idx = 0; idx < num_pkinds; idx++)
		npc_config_kpmaction(rvu, blkaddr, &rvu->kpu.ikpu[idx], 0, idx, true);

	/* Program KPM CAM and Action profiles */
	npc_program_kpm_profile(rvu, blkaddr, hw->npc_kpms);
}

static void npc_program_mkex_rx(struct rvu *rvu, int blkaddr,
				struct npc_mcam_kex_extr *mkex_extr,
				u8 intf)
{
	u8 num_extr = rvu->hw->npc_kex_extr;
	int extr, lt;

	if (is_npc_intf_tx(intf))
		return;

	rvu_write64(rvu, blkaddr, NPC_AF_INTFX_KEX_CFG(intf),
		    mkex_extr->keyx_cfg[NIX_INTF_RX]);

	/* Program EXTRACTOR */
	for (extr = 0; extr < num_extr; extr++)
		rvu_write64(rvu, blkaddr, NPC_AF_INTFX_EXTRACTORX_CFG(intf, extr),
			    mkex_extr->intf_extr_lid[intf][extr]);

	/* Program EXTRACTOR_LTYPE */
	for (extr = 0; extr < num_extr; extr++)
		for (lt = 0; lt < NPC_MAX_LT; lt++)
			CN20K_SET_EXTR_LT(intf, extr, lt,
					  mkex_extr->intf_extr_lt[intf][extr][lt]);
}

static void npc_program_mkex_tx(struct rvu *rvu, int blkaddr,
				struct npc_mcam_kex_extr *mkex_extr,
				u8 intf)
{
	u8 num_extr = rvu->hw->npc_kex_extr;
	int extr, lt;

	if (is_npc_intf_rx(intf))
		return;

	rvu_write64(rvu, blkaddr, NPC_AF_INTFX_KEX_CFG(intf),
		    mkex_extr->keyx_cfg[NIX_INTF_TX]);

	/* Program EXTRACTOR */
	for (extr = 0; extr < num_extr; extr++)
		rvu_write64(rvu, blkaddr, NPC_AF_INTFX_EXTRACTORX_CFG(intf, extr),
			    mkex_extr->intf_extr_lid[intf][extr]);

	/* Program EXTRACTOR_LTYPE */
	for (extr = 0; extr < num_extr; extr++)
		for (lt = 0; lt < NPC_MAX_LT; lt++)
			CN20K_SET_EXTR_LT(intf, extr, lt,
					  mkex_extr->intf_extr_lt[intf][extr][lt]);
}

static void npc_program_mkex_profile(struct rvu *rvu, int blkaddr,
				     struct npc_mcam_kex_extr *mkex_extr)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u8 intf;

	for (intf = 0; intf < hw->npc_intfs; intf++) {
		npc_program_mkex_rx(rvu, blkaddr, mkex_extr, intf);
		npc_program_mkex_tx(rvu, blkaddr, mkex_extr, intf);
	}

	/* Programme mkex hash profile */
	npc_program_mkex_hash(rvu, blkaddr);
}

void npc_cn20k_load_mkex_profile(struct rvu *rvu, int blkaddr,
				 const char *mkex_profile)
{
	struct npc_mcam_kex_extr *mcam_kex_extr;
	struct device *dev = &rvu->pdev->dev;
	void __iomem *mkex_prfl_addr = NULL;
	u64 prfl_sz;
	int ret;

	/* If user not selected mkex profile */
	if (rvu->kpu_fwdata_sz ||
	    !strncmp(mkex_profile, cn20k_def_pfl_name, MKEX_NAME_LEN))
		goto program_mkex_extr;

	/* Setting up the mapping for mkex profile image */
	ret = npc_fwdb_prfl_img_map(rvu, &mkex_prfl_addr, &prfl_sz);
	if (ret < 0)
		goto program_mkex_extr;

	mcam_kex_extr = (struct npc_mcam_kex_extr __force *)mkex_prfl_addr;

	while (((s64)prfl_sz > 0) && (mcam_kex_extr->mkex_sign != MKEX_END_SIGN)) {
		/* Compare with mkex mod_param name string */
		if (mcam_kex_extr->mkex_sign == MKEX_SIGN &&
		    !strncmp(mcam_kex_extr->name, mkex_profile, MKEX_NAME_LEN)) {
			rvu->kpu.mcam_kex_prfl.mkex_extr = mcam_kex_extr;
			goto program_mkex_extr;
		}

		mcam_kex_extr++;
		prfl_sz -= sizeof(struct npc_mcam_kex);
	}
	dev_warn(dev, "Failed to load requested profile: %s\n", mkex_profile);

program_mkex_extr:
	dev_info(rvu->dev, "Using %s mkex profile\n", rvu->kpu.mcam_kex_prfl.mkex_extr->name);
	/* Program selected mkex profile */
	npc_program_mkex_profile(rvu, blkaddr, rvu->kpu.mcam_kex_prfl.mkex_extr);
	if (mkex_prfl_addr)
		iounmap(mkex_prfl_addr);
}

static int npc_setup_mcam_section(struct rvu *rvu, int key_type)
{
	int blkaddr, sec;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NPC, 0);
	if (blkaddr < 0) {
		dev_err(rvu->dev, "%s: NPC block not implemented\n", __func__);
		return -ENODEV;
	}

	for (sec = 0; sec < npc_priv.num_subbanks; sec++)
		rvu_write64(rvu, blkaddr,
			    NPC_AF_MCAM_SECTIONX_CFG_EXT(sec), key_type);

	return 0;
}

int npc_cn20k_dft_rules_idx_get(struct rvu *rvu, u16 pcifunc, u16 *bcast,
				u16 *mcast, u16 *promisc, u16 *ucast)
{
	u16 *ptr[4] = {promisc, mcast, bcast, ucast};
	unsigned long idx;
	bool set = false;
	void *val;
	int i, j;

	if (!npc_priv.init_done)
		return 0;

	if (is_lbk_vf(rvu, pcifunc)) {
		if (!ptr[0])
			return -ENOMEM;

		idx = NPC_DFT_RULE_ID_MK(pcifunc, NPC_DFT_RULE_PROMISC_ID);
		val = xa_load(&npc_priv.xa_pf2dfl_rmap, idx);
		if (!val) {
			pr_debug("%s:%d Failed to find %s index for pcifunc=%#x\n",
				 __func__, __LINE__,
				 npc_dft_rule_name[NPC_DFT_RULE_PROMISC_ID], pcifunc);

			*ptr[0] = USHRT_MAX;
			return -ESRCH;
		}

		*ptr[0] = xa_to_value(val);
		return 0;
	}

	if (is_vf(pcifunc)) {
		if (!ptr[3])
			return -ENOMEM;

		idx = NPC_DFT_RULE_ID_MK(pcifunc, NPC_DFT_RULE_UCAST_ID);
		val = xa_load(&npc_priv.xa_pf2dfl_rmap, idx);
		if (!val) {
			pr_debug("%s:%d Failed to find %s index for pcifunc=%#x\n",
				 __func__, __LINE__,
				 npc_dft_rule_name[NPC_DFT_RULE_UCAST_ID], pcifunc);

			*ptr[3] = USHRT_MAX;
			return -ESRCH;
		}

		*ptr[3] = xa_to_value(val);
		return 0;
	}

	for (i = NPC_DFT_RULE_START_ID, j = 0; i < NPC_DFT_RULE_MAX_ID; i++,
	     j++) {
		if (!ptr[j])
			continue;

		idx = NPC_DFT_RULE_ID_MK(pcifunc, i);
		val = xa_load(&npc_priv.xa_pf2dfl_rmap, idx);
		if (!val) {
			pr_debug("%s:%d Failed to find %s index for pcifunc=%#x\n",
				 __func__, __LINE__,
				 npc_dft_rule_name[i], pcifunc);

			*ptr[j] = USHRT_MAX;
			continue;
		}

		*ptr[j] = xa_to_value(val);
		set = true;
	}

	return  set ? 0 : -ESRCH;
}

static bool npc_is_cgx_or_lbk(struct rvu *rvu, u16 pcifunc)
{
	return is_pf_cgxmapped(rvu, rvu_get_pf(pcifunc)) ||
		is_lbk_vf(rvu, pcifunc);
}

void npc_cn20k_dft_rules_free(struct rvu *rvu, u16 pcifunc)
{
	struct npc_mcam_free_entry_req free_req = { 0 };
	unsigned long index;
	struct msg_rsp rsp;
	u16 ptr[4];
	int rc, i;
	void *map;

	if (!npc_priv.init_done)
		return;

	if (!npc_is_cgx_or_lbk(rvu, pcifunc)) {
		dev_dbg(rvu->dev,
			"%s:%d dft rule allocation is only for cgx mapped device, pcifunc=%#x\n",
			__func__, __LINE__, pcifunc);
		return;
	}

	rc = npc_cn20k_dft_rules_idx_get(rvu, pcifunc, &ptr[0], &ptr[1],
					 &ptr[2], &ptr[3]);
	if (rc)
		return;

	/* LBK */
	if (is_lbk_vf(rvu, pcifunc)) {
		index = NPC_DFT_RULE_ID_MK(pcifunc, NPC_DFT_RULE_PROMISC_ID);
		map = xa_erase(&npc_priv.xa_pf2dfl_rmap, index);
		if (!map)
			dev_dbg(rvu->dev,
				"%s:%d Err from delete %s mcam idx from xarray (pcifunc=%#x\n",
				__func__, __LINE__,
				npc_dft_rule_name[NPC_DFT_RULE_PROMISC_ID],
				pcifunc);

		goto free_rules;
	}

	/* VF */
	if (is_vf(pcifunc)) {
		index = NPC_DFT_RULE_ID_MK(pcifunc, NPC_DFT_RULE_UCAST_ID);
		map = xa_erase(&npc_priv.xa_pf2dfl_rmap, index);
		if (!map)
			dev_dbg(rvu->dev,
				"%s:%d Err from delete %s mcam idx from xarray (pcifunc=%#x\n",
				__func__, __LINE__,
				npc_dft_rule_name[NPC_DFT_RULE_UCAST_ID],
				pcifunc);

		goto free_rules;
	}

	/* PF */
	for (i = NPC_DFT_RULE_START_ID; i < NPC_DFT_RULE_MAX_ID; i++)  {
		index = NPC_DFT_RULE_ID_MK(pcifunc, i);
		map = xa_erase(&npc_priv.xa_pf2dfl_rmap, index);
		if (!map)
			dev_dbg(rvu->dev,
				"%s:%d Err from delete %s mcam idx from xarray (pcifunc=%#x\n",
				__func__, __LINE__, npc_dft_rule_name[i],
				pcifunc);
	}

free_rules:

	free_req.hdr.pcifunc = pcifunc;
	free_req.all = 1;
	rc = rvu_mbox_handler_npc_mcam_free_entry(rvu, &free_req, &rsp);
	if (rc)
		dev_err(rvu->dev,
			"%s:%d Error deleting default entries (pcifunc=%#x\n",
			__func__, __LINE__, pcifunc);
}

int npc_cn20k_dft_rules_alloc(struct rvu *rvu, u16 pcifunc)
{
	u16 mcam_idx[4] = { 0 }, pf_ucast, pf_pcifunc;
	struct npc_mcam_alloc_entry_req req = { 0 };
	struct npc_mcam_alloc_entry_rsp rsp = { 0 };
	int ret, eidx, i, k, pf, cnt;
	struct rvu_pfvf *pfvf;
	unsigned long index;
	u16 b, m, p, u;

	if (!npc_priv.init_done)
		return 0;

	if (!npc_is_cgx_or_lbk(rvu, pcifunc)) {
		dev_dbg(rvu->dev,
			"%s:%d dft rule allocation is only for cgx mapped device, pcifunc=%#x\n",
			__func__, __LINE__, pcifunc);
		return 0;
	}

	/* Check if default rules are already alloced for this pcifunc */
	ret =  npc_cn20k_dft_rules_idx_get(rvu, pcifunc, &b, &m, &p, &u);
	if (!ret) {
		dev_err(rvu->dev,
			"%s:%d default rules are already installed (pcifunc=%#x)\n",
			__func__, __LINE__, pcifunc);
		dev_err(rvu->dev,
			"%s:%d bcast(%u) mcast(%u) promisc(%u) ucast(%u)\n",
			__func__, __LINE__, b, m, p, u);
		return 0;
	}

	/* Set ref index as lowest priority index */
	eidx = 2 * npc_priv.bank_depth - 1;

	/* Install only UCAST for VF */
	cnt = is_vf(pcifunc) ? 1 : ARRAY_SIZE(mcam_idx);

	/* For VF pcifunc, allocate default mcam indexes by taking
	 * ref as PF's ucast index.
	 */
	if (is_vf(pcifunc)) {
		pf = rvu_get_pf(pcifunc);
		pf_pcifunc = pf << RVU_PFVF_PF_SHIFT;

		/* Get PF's ucast entry index */
		ret = npc_cn20k_dft_rules_idx_get(rvu, pf_pcifunc, NULL,
						  NULL, NULL, &pf_ucast);

		/* There is no PF rules installed; and VF installation comes
		 * first. PF may come later.
		 * TODO: Install PF rules before installing VF rules.
		 */

		/* Set PF's ucast as ref entry */
		if (!ret)
			eidx = pf_ucast;
	}

	pfvf = rvu_get_pfvf(rvu, pcifunc);
	pfvf->hw_prio = NPC_DFT_RULE_PRIO;

	req.contig = false;
	req.ref_prio = NPC_MCAM_HIGHER_PRIO;
	req.ref_entry = eidx;
	req.kw_type = NPC_MCAM_KEY_X2;
	req.count = cnt;
	req.hdr.pcifunc = pcifunc;

	ret = rvu_mbox_handler_npc_mcam_alloc_entry(rvu, &req, &rsp);

	/* successfully allocated index */
	if (!ret) {
		/* Copy indexes to local array */
		for (i = 0; i < cnt; i++)
			mcam_idx[i] = rsp.entry_list[i];

		goto chk_sanity;
	}

	/* If there is no slots available and request is for PF,
	 * return error.
	 */
	if (!is_vf(pcifunc)) {
		dev_err(rvu->dev,
			"%s:%d Default index allocation failed for pcifunc=%#x\n",
			__func__, __LINE__, pcifunc);
		return ret;
	}

	/* We could not find an index with higher priority index for VF.
	 * Find rule with lower priority index and set hardware priority
	 * as NPC_DFT_RULE_PRIO - 1 (higher hw priority)
	 */
	req.contig = false;
	req.kw_type = NPC_MCAM_KEY_X2;
	req.count = cnt;
	req.hdr.pcifunc = pcifunc;
	req.ref_prio = NPC_MCAM_LOWER_PRIO;
	req.ref_entry = eidx + 1;
	ret = rvu_mbox_handler_npc_mcam_alloc_entry(rvu, &req, &rsp);
	if (ret) {
		dev_err(rvu->dev,
			"%s:%d Default index allocation failed for pcifunc=%#x\n",
			__func__, __LINE__, pcifunc);
		return ret;
	}

	/* Copy indexes to local array */
	for (i = 0; i < cnt; i++)
		mcam_idx[i] = rsp.entry_list[i];

	pfvf->hw_prio = NPC_DFT_RULE_PRIO - 1;

chk_sanity:
	dev_dbg(rvu->dev,
		"%s:%d Default index for pcifunc=%#x, bcast=%u mcast=%u promis=%u ucast=%u cnt=%u\n",
		__func__, __LINE__, pcifunc, mcam_idx[0], mcam_idx[1],
		mcam_idx[2], mcam_idx[3], cnt);

	/* LBK */
	if (is_lbk_vf(rvu, pcifunc)) {
		index = NPC_DFT_RULE_ID_MK(pcifunc, NPC_DFT_RULE_PROMISC_ID);
		ret = xa_insert(&npc_priv.xa_pf2dfl_rmap, index,
				xa_mk_value(mcam_idx[0]), GFP_KERNEL);
		if (ret) {
			dev_err(rvu->dev,
				"%s:%d Err to insert %s mcam idx to xarray pcifunc=%#x\n",
				__func__, __LINE__, npc_dft_rule_name[NPC_DFT_RULE_PROMISC_ID],
				pcifunc);
			ret = -EFAULT;
			goto err;
		}

		goto done;
	}

	/* VF */
	if (is_vf(pcifunc)) {
		index = NPC_DFT_RULE_ID_MK(pcifunc, NPC_DFT_RULE_UCAST_ID);
		ret = xa_insert(&npc_priv.xa_pf2dfl_rmap, index,
				xa_mk_value(mcam_idx[0]), GFP_KERNEL);
		if (ret) {
			dev_err(rvu->dev,
				"%s:%d Err to insert %s mcam idx to xarray pcifunc=%#x\n",
				__func__, __LINE__, npc_dft_rule_name[NPC_DFT_RULE_UCAST_ID],
				pcifunc);
			ret = -EFAULT;
			goto err;
		}

		goto done;
	}

	/* PF */
	for (i = NPC_DFT_RULE_START_ID, k = 0; i < NPC_DFT_RULE_MAX_ID &&
	     k < cnt; i++, k++) {
		index = NPC_DFT_RULE_ID_MK(pcifunc, i);
		ret = xa_insert(&npc_priv.xa_pf2dfl_rmap, index,
				xa_mk_value(mcam_idx[k]), GFP_KERNEL);
		if (ret) {
			dev_err(rvu->dev,
				"%s:%d Err to insert %s mcam idx to xarray pcifunc=%#x\n",
				__func__, __LINE__, npc_dft_rule_name[i],
				pcifunc);
			ret = -EFAULT;
			goto err;
		}
	}

done:
	return 0;
err:
	/* TODO: handle errors */
	return ret;
}

int npc_cn20k_deinit(struct rvu *rvu)
{
	int i;

	xa_destroy(&npc_priv.xa_sb_used);
	xa_destroy(&npc_priv.xa_sb_free);
	xa_destroy(&npc_priv.xa_idx2pf_map);
	xa_destroy(&npc_priv.xa_pf_map);
	xa_destroy(&npc_priv.xa_pf2dfl_rmap);

	for (i = 0; i < npc_priv.pf_cnt; i++)
		xa_destroy(&npc_priv.xa_pf2idx_map[i]);

	kfree(npc_priv.xa_pf2idx_map);
	kfree(npc_priv.sb);
	return 0;
}

int npc_cn20k_init(struct rvu *rvu)
{
	int err;

	err = npc_setup_mcam_section(rvu, NPC_MCAM_KEY_X2);
	if (err) {
		dev_err(rvu->dev, "%s: mcam section configuration failure\n",
			__func__);
		return err;
	}

	err = npc_priv_init(rvu);
	if (err) {
		dev_err(rvu->dev, "%s:%d Error to init\n",
			__func__, __LINE__);
		return err;
	}

	npc_priv.init_done = true;

	return 0;
}
