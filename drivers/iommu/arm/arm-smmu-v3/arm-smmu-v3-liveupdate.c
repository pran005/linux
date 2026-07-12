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

#endif
