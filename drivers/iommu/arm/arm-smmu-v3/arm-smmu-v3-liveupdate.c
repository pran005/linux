// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Google LLC
 * Author: Praan (TODO: Update in orig commit)
 */

#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/iommu-liveupdate.h>
#include <linux/kexec_handover.h>
#include "arm-smmu-v3.h"

#ifdef CONFIG_IOMMU_LIVEUPDATE
static int arm_smmu_preserve_cd_table_linear(struct device *dev,
					     struct arm_smmu_master *master,
					     struct iommu_device_ser *device_ser)
{
	struct arm_smmu_ctx_desc_cfg *cd_table = &master->cd_table;
	u32 size = cd_table->linear.num_ents * sizeof(struct arm_smmu_cd);
	u64 state;
	int ret;

	ret = dma_preserve_coherent_allocation(dev, cd_table->linear.table,
					       size, cd_table->cdtab_dma, &state);
	if (ret)
		return ret;

	device_ser->smmuv3.l1_cdtab_lu_state = state;
	device_ser->smmuv3.num_l2_cdtables = 0;

	return 0;
}

static int arm_smmu_preserve_cd_table_2lvl(struct device *dev,
					   struct arm_smmu_master *master,
					   struct iommu_device_ser *device_ser)
{
	struct arm_smmu_ctx_desc_cfg *cd_table = &master->cd_table;
	u32 l1size = cd_table->l2.num_l1_ents * sizeof(struct arm_smmu_cdtab_l1);
	u32 num_l2 = 0;
	u64 *l2_states;
	u64 state;
	int ret, i;

	ret = dma_preserve_coherent_allocation(dev, cd_table->l2.l1tab,
					       l1size, cd_table->cdtab_dma, &state);
	if (ret)
		return ret;

	device_ser->smmuv3.l1_cdtab_lu_state = state;

	for (i = 0; i < cd_table->l2.num_l1_ents; i++) {
		if (cd_table->l2.l2ptrs[i])
			num_l2++;
	}

	device_ser->smmuv3.num_l2_cdtables = num_l2;
	if (!num_l2)
		return 0;

	l2_states = kho_alloc_preserve(sizeof(*l2_states) * num_l2);
	if (!l2_states) {
		ret = -ENOMEM;
		goto err_unpreserve_cd_l1;
	}

	device_ser->smmuv3.l2_cdtab_lu_states_phys = virt_to_phys(l2_states);
	num_l2 = 0;

	for (i = 0; i < cd_table->l2.num_l1_ents; i++) {
		dma_addr_t l2_dma;

		if (!cd_table->l2.l2ptrs[i])
			continue;

		l2_dma = le64_to_cpu(cd_table->l2.l1tab[i].l2ptr) & STRTAB_L1_DESC_L2PTR_MASK;
		ret = dma_preserve_coherent_allocation(dev, cd_table->l2.l2ptrs[i],
						       CTXDESC_L2_ENTRIES * sizeof(struct arm_smmu_cd),
						       l2_dma, &state);
		if (ret)
			goto err_free_cd_l2_states;

		l2_states[num_l2++] = state;
	}

	return 0;

err_free_cd_l2_states:
	for (i = i - 1; i >= 0; i--) {
		if (cd_table->l2.l2ptrs[i]) {
			num_l2--;
			dma_unpreserve_coherent_allocation(dev, l2_states[num_l2]);
		}
	}
	kho_unpreserve_free(l2_states);
err_unpreserve_cd_l1:
	dma_unpreserve_coherent_allocation(dev, device_ser->smmuv3.l1_cdtab_lu_state);
	return ret;
}

int arm_smmu_preserve_device(struct device *dev,
				    struct iommu_device_ser *device_ser)
{
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);
	struct arm_smmu_domain *smmu_domain;
	struct arm_smmu_ctx_desc_cfg *cd_table = &master->cd_table;
	struct iommu_domain_ser *domain_ser;
	int ret = 0;

	/*
	 * We'd anyway configure abort STEs for non-preserved masters.
	 * TODO: Re-visit for identity once IOMMUFD noIOMMU is merged
	 * TODO: Re-visit for CXL + ATS + Identity CD Table thing
	 * 	 Can use cd_table_allocated() helper here?
	 */
	if (domain->type == IOMMU_DOMAIN_IDENTITY ||
	    domain->type == IOMMU_DOMAIN_BLOCKED)
		return 0;

	/*
	 * For nested domains we only need to preserve STE.
	 * The S2 parent domain's page tables are preserved via its own
	 * iommu_preserve_domain() call during IOMMUFD's HWPT preservation.
	 * Since the CD Table in this case lives in the guest memory, it is
	 * naturally preserved by default across KHO when Live Update is enabled.
	 * Thus, since CD isn't allocated via DMA allocator by the host driver
	 * we must not attempt preserving CD here.
	 */
	if (domain->type == IOMMU_DOMAIN_NESTED)
		goto skip_cd_preservation;

	smmu_domain = to_smmu_domain(domain);

	/* SVA domains cannot be preserved across KHO */
	if (smmu_domain->stage == ARM_SMMU_DOMAIN_SVA) {
		dev_err(dev, "SVA domains are NOT preserved across KHO \n");
		return -EOPNOTSUPP;
	}

	/*
	 * The IOMMU LU Core doesn't support preservation at a PASID
	 * granularity yet, reject preservation to prevent leaving active
	 * PASIDs pointing to unpreserved tables.
	 */
	if (arm_smmu_ssids_in_use(&master->cd_table)) {
		dev_err(dev, "Preserving devices with active PASIDS is NOT supported w/ Live Update");
		return -EOPNOTSUPP;
	}

	if (domain->preserved_state) {
		domain_ser = domain->preserved_state;
	} else {
		/* Fallback for kernel-managed domains */
		ret = iommu_preserve_domain(domain, &domain_ser);
		if (ret)
			return ret;
	}

	/* Link this master to the preserved IOMMU domain in the ABI */
	device_ser->domain_iommu_ser.domain_phys = virt_to_phys(domain_ser);

	/* If it's not Stage-1, or the CD table isn't allocated, we're done */
	if (smmu_domain->stage != ARM_SMMU_DOMAIN_S1 ||
	    !arm_smmu_cdtab_allocated(&master->cd_table))
		goto skip_cd_preservation;

	if (cd_table->s1fmt == STRTAB_STE_0_S1FMT_LINEAR)
		ret = arm_smmu_preserve_cd_table_linear(dev, master, device_ser);
	else if (cd_table->s1fmt == STRTAB_STE_0_S1FMT_64K_L2)
		ret = arm_smmu_preserve_cd_table_2lvl(dev, master, device_ser);

skip_cd_preservation:
	/* Mark the master as preserved to track state during disable */
	master->preserved = ret ? false : true;

	return ret;
}

static int arm_smmu_preserve_strtab_2lvl(struct arm_smmu_device *smmu,
					 struct iommu_hw_ser *iommu_ser)
{
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	u32 l1size = cfg->l2.num_l1_ents * sizeof(struct arm_smmu_strtab_l1);
	unsigned long *l2_active;
	struct rb_node *node;
	u32 num_l2 = 0;
	u64 *l2_states;
	u64 state;
	int ret, i;

	/* Preserve the L1 Stream table */
	ret = dmam_preserve_allocation_attrs(smmu->dev, cfg->l2.l1tab,
					     l1size, cfg->l2.l1_dma, 0, &state);
	if (ret) {
		dev_err(smmu->dev, "L1 table preservation failed\n");
		return ret;
	}
	iommu_ser->smmuv3.l1_strtab_lu_state = state;

	/* Bitmap to track L2 tables for preserved masters */
	l2_active = bitmap_zalloc(cfg->l2.num_l1_ents, GFP_KERNEL);
	if (!l2_active) {
		ret = -ENOMEM;
		goto err_unpreserve_l1;
	}

	mutex_lock(&smmu->streams_mutex);
	for (node = rb_first(&smmu->streams); node; node = rb_next(node)) {
		struct arm_smmu_stream *stream =
			rb_entry(node, struct arm_smmu_stream, node);

		if (stream->master->preserved) {
			u32 idx = arm_smmu_strtab_l1_idx(stream->id);
			set_bit(idx, l2_active);
		}
	}
	mutex_unlock(&smmu->streams_mutex);

	/* Count L2 tables to preserve */
	for (i = 0; i < cfg->l2.num_l1_ents; i++) {
		if (cfg->l2.l2ptrs[i] && test_bit(i, l2_active))
			num_l2++;
	}

	dev_info(smmu->dev, "Preserving %d L2 tables\n", num_l2);
	iommu_ser->smmuv3.num_l2_tables = num_l2;

	if (!num_l2) {
		bitmap_free(l2_active);
		return 0;
	}

	l2_states = kho_alloc_preserve(sizeof(*l2_states) * num_l2);
	if (!l2_states) {
		ret = -ENOMEM;
		goto err_free_bitmap;
	}

	iommu_ser->smmuv3.l2_strtab_lu_states_phys = virt_to_phys(l2_states);
	num_l2 = 0;

	/* Preserve L2 tables for all preserved masters */
	for (i = 0; i < cfg->l2.num_l1_ents; i++) {
		dma_addr_t l2_dma;

		if (!cfg->l2.l2ptrs[i] || !test_bit(i, l2_active))
			continue;

		/* Fetch L2 table address */
		l2_dma = le64_to_cpu(cfg->l2.l1tab[i].l2ptr) & STRTAB_L1_DESC_L2PTR_MASK;
		/* Preserve the L2 table for this master */
		ret = dmam_preserve_allocation_attrs(smmu->dev, cfg->l2.l2ptrs[i],
						     sizeof(struct arm_smmu_strtab_l2),
						     l2_dma, 0, &state);
		if (ret)
			goto err_free_l2_states;

		l2_states[num_l2++] = state;
	}

	bitmap_free(l2_active);
	return 0;

err_free_l2_states:
	for (i = i - 1; i >= 0; i--) {
		if (cfg->l2.l2ptrs[i] && test_bit(i, l2_active)) {
			dma_addr_t l2_dma = le64_to_cpu(cfg->l2.l1tab[i].l2ptr) & STRTAB_L1_DESC_L2PTR_MASK;
			num_l2--;
			dmam_unpreserve_allocation(smmu->dev, cfg->l2.l2ptrs[i],
						   sizeof(struct arm_smmu_strtab_l2),
						   l2_dma, l2_states[num_l2]);
		}
	}
	kho_unpreserve_free(l2_states);
err_free_bitmap:
	bitmap_free(l2_active);
err_unpreserve_l1:
	dmam_unpreserve_allocation(smmu->dev, cfg->l2.l1tab, l1size,
				   cfg->l2.l1_dma, iommu_ser->smmuv3.l1_strtab_lu_state);
	return ret;
}

static int arm_smmu_preserve_strtab_linear(struct arm_smmu_device *smmu,
					   struct iommu_hw_ser *iommu_ser)
{
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	u32 size = (1 << smmu->sid_bits) * sizeof(struct arm_smmu_ste);
	u64 state;
	int ret;

	/* STRTAB BASE can't be changed hitlessly, preserve the whole table */
	ret = dmam_preserve_allocation_attrs(smmu->dev, cfg->linear.table, size,
					     cfg->linear.ste_dma, 0, &state);
	if (ret)
		return ret;

	iommu_ser->smmuv3.l1_strtab_lu_state = state;
	iommu_ser->smmuv3.num_l2_tables = 0;
	return 0;
}

int arm_smmu_preserve(struct iommu_device *iommu,
		      struct iommu_hw_ser *iommu_ser)
{
	struct arm_smmu_device *smmu =
		container_of(iommu, struct arm_smmu_device, iommu);

	/* Basic info */
	iommu_ser->smmuv3.phys_addr = smmu->base_phys;
	iommu_ser->type = IOMMU_ARM_SMMUV3;
	iommu_ser->smmuv3.strtab_base_cfg =
		readl_relaxed(smmu->base + ARM_SMMU_STRTAB_BASE_CFG);

	/* We always implements 2-level when supported by HW */
	if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB)
		return arm_smmu_preserve_strtab_2lvl(smmu, iommu_ser);
	else
		return arm_smmu_preserve_strtab_linear(smmu, iommu_ser);
}

static void arm_smmu_liveupdate_clear_l1_std(struct arm_smmu_device *smmu,
					     unsigned long *l2_active)
{
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	int i;

	for (i = 0; i < cfg->l2.num_l1_ents; i++) {
		if (!cfg->l2.l2ptrs[i] || test_bit(i, l2_active))
			continue;

		/* Clear L1 STD for unpreserved streams */
		WRITE_ONCE(cfg->l2.l1tab[i].l2ptr, 0);
	}
}

int arm_smmu_liveupdate_shutdown(struct arm_smmu_device *smmu)
{
	struct arm_smmu_master *master;
	struct arm_smmu_stream *stream;
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	struct rb_node *node;
	struct arm_smmu_ste abort_ste;
	struct arm_smmu_cmd cmd_cfgi, cmd_el2, cmd_nsnh;
	unsigned long *l2_active = NULL;
	bool is_2lvl = smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB;

	if (is_2lvl) {
		l2_active = bitmap_zalloc(cfg->l2.num_l1_ents, GFP_KERNEL);
		if (!l2_active) {
			dev_err(smmu->dev, "OOM: Falling back to hard disable\n");
			return -ENOMEM;
		}
	}

	/* Prepare an abort STE for unpreserved masters */
	arm_smmu_make_abort_ste(&abort_ste);

	/*
	 * We do not scrub unpreserved Context Descriptors (CDs) here since:
	 *
	 * 1. Each master has its own independently allocated CD table page,
	 *    i.e. multiple masters never share a CD table.
	 *
	 * 2. We explicitly reject preserving any device with active PASIDs in
	 *    the .preserve_device op. Thus, any preserved master is guaranteed
	 *    to only be using CD[0].
	 *
	 * Therefore, partial preservation within a CD table is not possible,
	 * and we only need to isolate unpreserved streams within shared
	 * Stream Tables.
	 */
	mutex_lock(&smmu->streams_mutex);

	/* Install the abort STEs for unpreserved masters */
	for (node = rb_first(&smmu->streams); node; node = rb_next(node)) {
		stream = rb_entry(node, struct arm_smmu_stream, node);
		master = stream->master;

		if (master->preserved) {
			if (is_2lvl)
				set_bit(arm_smmu_strtab_l1_idx(stream->id), l2_active);
		} else {
			arm_smmu_write_ste(master, stream->id,
				  arm_smmu_get_step_for_sid(smmu, stream->id),
				  &abort_ste);
		}
	}

	/* Invalidate completely unpreserved streams */
	if (is_2lvl) {
		arm_smmu_liveupdate_clear_l1_std(smmu, l2_active);
		bitmap_free(l2_active);
	}

	mutex_unlock(&smmu->streams_mutex);

	/* Sync hardware caches to observe updated structures */
	cmd_cfgi = arm_smmu_make_cmd_cfgi_all();
	arm_smmu_cmdq_issue_cmdlist(smmu, &smmu->cmdq, &cmd_cfgi, 1, true);

	/*
	 * Aggressively flush all TLBs to ensure no stale entries exist for
	 * unpreserved streams. The preserved streams will take a minor hit
	 * re-walking their page tables, but this guarantees safety.
	 */
	if (smmu->features & ARM_SMMU_FEAT_HYP) {
		cmd_el2 = arm_smmu_make_cmd_op(CMDQ_OP_TLBI_EL2_ALL);
		arm_smmu_cmdq_issue_cmdlist(smmu, &smmu->cmdq, &cmd_el2, 1, true);
	}

	cmd_nsnh = arm_smmu_make_cmd_op(CMDQ_OP_TLBI_NSNH_ALL);
	arm_smmu_cmdq_issue_cmdlist(smmu, &smmu->cmdq, &cmd_nsnh, 1, true);

	return 0;
}

static int arm_smmu_liveupdate_restore_strtab_2lvl(struct arm_smmu_device *smmu)
{
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	struct iommu_hw_ser *iommu_ser = iommu_preserved_state(&smmu->iommu);
	u64 reg;
	phys_addr_t l1_phys;
	u32 l1size;
	u64 *l2_states;
	int i;
	u32 num_l2 = iommu_ser->smmuv3.num_l2_tables;

	/* Extract L1 physical address directly from active hardware */
	reg = readq_relaxed(smmu->base + ARM_SMMU_STRTAB_BASE);
	l1_phys = reg & STRTAB_BASE_ADDR_MASK;
	
	l1size = cfg->l2.num_l1_ents * sizeof(struct arm_smmu_strtab_l1);

	/* Restore the L1 table */
	cfg->l2.l1tab = dmam_restore_allocation_attrs(smmu->dev, l1size,
						      &cfg->l2.l1_dma, GFP_KERNEL, 0,
						      iommu_ser->smmuv3.l1_strtab_lu_state);
	if (!cfg->l2.l1tab) {
		dev_err(smmu->dev, "KHO: Failed to restore L1 Stream Table\n");
		return -ENOMEM;
	}

	cfg->l2.l2ptrs = devm_kcalloc(smmu->dev, cfg->l2.num_l1_ents,
				      sizeof(*cfg->l2.l2ptrs), GFP_KERNEL);
	if (!cfg->l2.l2ptrs)
		return -ENOMEM;

	if (!num_l2)
		return 0;

	l2_states = phys_to_virt(iommu_ser->smmuv3.l2_strtab_lu_states_phys);
	num_l2 = 0;

	/* Restore active L2 tables based on preserved state array */
	for (i = 0; i < cfg->l2.num_l1_ents; i++) {
		struct arm_smmu_strtab_l1 *desc = &cfg->l2.l1tab[i];
		dma_addr_t l2_dma;
		u64 val = le64_to_cpu(desc->l2ptr);

		/* Skip L1 descriptors wiped by the outgoing .shutdown hook */
		if (!FIELD_GET(STRTAB_L1_DESC_SPAN, val))
			continue;

		l2_dma = val & STRTAB_L1_DESC_L2PTR_MASK;
		cfg->l2.l2ptrs[i] = dmam_restore_allocation_attrs(smmu->dev,
								  sizeof(struct arm_smmu_strtab_l2),
								  &l2_dma, GFP_KERNEL, 0,
								  l2_states[num_l2++]);
		if (!cfg->l2.l2ptrs[i]) {
			dev_err(smmu->dev, "KHO: Failed to restore L2 table at idx %d\n", i);
			return -ENOMEM;
		}
	}

	kho_restore_free(l2_states);
	dev_info(smmu->dev, "KHO: Successfully restored 2-level Stream Table\n");
	return 0;
}

int arm_smmu_liveupdate_restore_strtab(struct arm_smmu_device *smmu)
{
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	struct iommu_hw_ser *iommu_ser;

	iommu_ser = iommu_preserved_state(&smmu->iommu);
	if (!iommu_ser)
		return 0;

	if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB) {
		return arm_smmu_liveupdate_restore_strtab_2lvl(smmu);
	} else {
		u32 size = (1 << smmu->sid_bits) * sizeof(struct arm_smmu_ste);
		cfg->linear.table = dmam_restore_allocation_attrs(smmu->dev, size,
								 &cfg->linear.ste_dma, GFP_KERNEL, 0,
								 iommu_ser->smmuv3.l1_strtab_lu_state);
		
		if (!cfg->linear.table)
			return -ENOMEM;

		dev_info(smmu->dev, "KHO: Successfully restored linear Stream Table\n");
	}
		
	return 0;
}

int arm_smmu_liveupdate_restore_cd_tables(struct arm_smmu_master *master)
{
	struct arm_smmu_device *smmu = master->smmu;
	struct arm_smmu_ctx_desc_cfg *cd_table = &master->cd_table;
	struct iommu_device_ser *dev_ser = dev_iommu_restored_state(master->dev);
	struct arm_smmu_ste *ste;
	u64 val;
	phys_addr_t l1_phys;
	u32 l1size, i, num_l2;
	u64 *l2_states;

	if (!dev_ser)
		return 0;

	/* Extract CD Table address from the active STEs */
	ste = arm_smmu_get_step_for_sid(smmu, master->streams[0].id);
	val = le64_to_cpu(ste->data[0]);

	/* If the STE isn't S1_TRANS, no CD table exists */
	if (!(val & STRTAB_STE_0_V) || 
	    FIELD_GET(STRTAB_STE_0_CFG, val) != STRTAB_STE_0_CFG_S1_TRANS)
		return 0;

	l1_phys = val & STRTAB_STE_0_S1CTXPTR_MASK;

	/* Determine format from STE */
	if (FIELD_GET(STRTAB_STE_0_S1FMT, val) == STRTAB_STE_0_S1FMT_LINEAR) {
		u32 max_contexts = 1 << FIELD_GET(STRTAB_STE_0_S1CDMAX, val);
		l1size = max_contexts * sizeof(struct arm_smmu_cd);
		
		cd_table->linear.table = dmam_restore_allocation_attrs(smmu->dev, l1size,
								       &cd_table->cdtab_dma, GFP_KERNEL, 0,
								       dev_ser->smmuv3.l1_cdtab_lu_state);
		return cd_table->linear.table ? 0 : -ENOMEM;
	}

	/* Restore L1 CD Table */
	cd_table->s1fmt = STRTAB_STE_0_S1FMT_64K_L2;
	cd_table->l2.num_l1_ents = DIV_ROUND_UP(1 << FIELD_GET(STRTAB_STE_0_S1CDMAX, val), CTXDESC_L2_ENTRIES);
	l1size = cd_table->l2.num_l1_ents * sizeof(struct arm_smmu_cdtab_l1);

	cd_table->l2.l1tab = dmam_restore_allocation_attrs(smmu->dev, l1size,
							   &cd_table->cdtab_dma, GFP_KERNEL, 0,
							   dev_ser->smmuv3.l1_cdtab_lu_state);
	if (!cd_table->l2.l1tab)
		return -ENOMEM;

	cd_table->l2.l2ptrs = devm_kcalloc(smmu->dev, cd_table->l2.num_l1_ents,
					   sizeof(*cd_table->l2.l2ptrs), GFP_KERNEL);
	if (!cd_table->l2.l2ptrs)
		return -ENOMEM;

	num_l2 = dev_ser->smmuv3.num_l2_cdtables;
	if (!num_l2)
		return 0;

	l2_states = phys_to_virt(dev_ser->smmuv3.l2_cdtab_lu_states_phys);
	num_l2 = 0;

	/* Walk the L1 CD table and restore active L2s */
	for (i = 0; i < cd_table->l2.num_l1_ents; i++) {
		struct arm_smmu_cdtab_l1 *desc = &cd_table->l2.l1tab[i];
		dma_addr_t l2_dma;
		u64 l1_val = le64_to_cpu(desc->l2ptr);

		if (!(l1_val & CTXDESC_L1_DESC_V))
			continue;

		l2_dma = l1_val & CTXDESC_L1_DESC_L2PTR_MASK;
		cd_table->l2.l2ptrs[i] = dmam_restore_allocation_attrs(smmu->dev,
								       sizeof(struct arm_smmu_cdtab_l2),
								       &l2_dma, GFP_KERNEL, 0,
								       l2_states[num_l2++]);
		if (!cd_table->l2.l2ptrs[i])
			return -ENOMEM;
	}

	kho_restore_free(l2_states);
	return 0;
}

#endif
