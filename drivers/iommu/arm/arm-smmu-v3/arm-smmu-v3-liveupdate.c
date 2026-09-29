// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Google LLC
 * Author: Pranjal Shrivastava <praan@google.com>
 */

#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/iommu-liveupdate.h>
#include <linux/kexec_handover.h>
#include "arm-smmu-v3.h"

#ifdef CONFIG_IOMMU_LIVEUPDATE
static int arm_smmu_preserve_cd_table_linear(struct arm_smmu_master *master,
					     struct iommu_device_ser *device_ser)
{
	struct device *dev = master->smmu->dev;
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

static int arm_smmu_preserve_cd_table_2lvl(struct arm_smmu_master *master,
					   struct iommu_device_ser *device_ser)
{
	struct device *dev = master->smmu->dev;
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
	if (IS_ERR(l2_states)) {
		ret = PTR_ERR(l2_states);
		goto err_unpreserve_cd_l1;
	}

	device_ser->smmuv3.l2_cdtab_lu_states_phys = virt_to_phys(l2_states);
	num_l2 = 0;

	for (i = 0; i < cd_table->l2.num_l1_ents; i++) {
		dma_addr_t l2_dma;

		if (!cd_table->l2.l2ptrs[i])
			continue;

		l2_dma = le64_to_cpu(cd_table->l2.l1tab[i].l2ptr) & CTXDESC_L1_DESC_L2PTR_MASK;
		ret = dma_preserve_coherent_allocation(dev, cd_table->l2.l2ptrs[i],
						       sizeof(struct arm_smmu_cdtab_l2),
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

static void arm_smmu_unpreserve_cd_table(struct arm_smmu_master *master,
					 struct iommu_device_ser *device_ser)
{
	struct device *dev = master->smmu->dev;
	u32 num_l2 = device_ser->smmuv3.num_l2_cdtables;
	u64 *l2_states;
	u32 i;

	if (!device_ser->smmuv3.l1_cdtab_lu_state)
		return;

	if (num_l2) {
		l2_states = phys_to_virt(device_ser->smmuv3.l2_cdtab_lu_states_phys);
		for (i = 0; i < num_l2; i++)
			dma_unpreserve_coherent_allocation(dev, l2_states[i]);
		kho_unpreserve_free(l2_states);
	}
	dma_unpreserve_coherent_allocation(dev, device_ser->smmuv3.l1_cdtab_lu_state);
	memset(&device_ser->smmuv3, 0, sizeof(device_ser->smmuv3));
}

static u64 *arm_smmu_l2_strtab_states(struct arm_smmu_device *smmu)
{
	struct iommu_hw_ser *iommu_ser = iommu_preserved_state(&smmu->iommu);

	return phys_to_virt(iommu_ser->smmuv3.l2_strtab_lu_states_phys);
}

static bool arm_smmu_l2_strtab_in_use(struct arm_smmu_device *smmu, u32 idx)
{
	struct rb_node *node;

	lockdep_assert_held(&smmu->streams_mutex);

	for (node = rb_first(&smmu->streams); node; node = rb_next(node)) {
		struct arm_smmu_stream *stream =
			rb_entry(node, struct arm_smmu_stream, node);

		if (stream->master->preserved &&
		    arm_smmu_strtab_l1_idx(stream->id) == idx)
			return true;
	}
	return false;
}

/* Unpreserve the L2 tables of the first @num_streams, unless still in use */
static void arm_smmu_unpreserve_l2_strtabs(struct arm_smmu_master *master,
					   unsigned int num_streams)
{
	struct arm_smmu_device *smmu = master->smmu;
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	u64 *l2_states;
	unsigned int i;

	if (!(smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB))
		return;

	l2_states = arm_smmu_l2_strtab_states(smmu);

	mutex_lock(&smmu->streams_mutex);
	for (i = 0; i < num_streams; i++) {
		u32 idx = arm_smmu_strtab_l1_idx(master->streams[i].id);
		dma_addr_t l2_dma;

		if (!l2_states[idx] || arm_smmu_l2_strtab_in_use(smmu, idx))
			continue;

		l2_dma = le64_to_cpu(cfg->l2.l1tab[idx].l2ptr) & STRTAB_L1_DESC_L2PTR_MASK;
		dmam_unpreserve_coherent_allocation(smmu->dev, cfg->l2.l2ptrs[idx],
						    sizeof(struct arm_smmu_strtab_l2),
						    l2_dma, l2_states[idx]);
		l2_states[idx] = 0;
	}
	mutex_unlock(&smmu->streams_mutex);
}

/* Preserve the L2 tables holding the STEs of @master */
static int arm_smmu_preserve_l2_strtabs(struct arm_smmu_master *master)
{
	struct arm_smmu_device *smmu = master->smmu;
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	u64 *l2_states;
	unsigned int i;
	int ret;

	if (!(smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB))
		return 0;

	l2_states = arm_smmu_l2_strtab_states(smmu);

	for (i = 0; i < master->num_streams; i++) {
		u32 idx = arm_smmu_strtab_l1_idx(master->streams[i].id);
		dma_addr_t l2_dma;

		if (l2_states[idx])
			continue;

		l2_dma = le64_to_cpu(cfg->l2.l1tab[idx].l2ptr) & STRTAB_L1_DESC_L2PTR_MASK;
		ret = dmam_preserve_coherent_allocation(smmu->dev,
						cfg->l2.l2ptrs[idx],
						sizeof(struct arm_smmu_strtab_l2),
						l2_dma, &l2_states[idx]);
		if (ret) {
			arm_smmu_unpreserve_l2_strtabs(master, i);
			return ret;
		}
	}
	return 0;
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

	memset(&device_ser->smmuv3, 0, sizeof(device_ser->smmuv3));

	/*
	 * We'd anyway configure abort STEs for non-preserved masters.
	 * TODO: Re-visit for identity once IOMMUFD noIOMMU is merged
	 * TODO: Re-visit for CXL + ATS + Identity CD Table thing
	 *       Can use cd_table_allocated() helper here?
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
		dev_err(dev, "SVA domains are NOT preserved across KHO\n");
		return -EOPNOTSUPP;
	}

	/*
	 * The IOMMU LU Core doesn't support preservation at a PASID
	 * granularity yet, reject preservation to prevent leaving active
	 * PASIDs pointing to unpreserved tables.
	 */
	if (arm_smmu_ssids_in_use(&master->cd_table)) {
		dev_err(dev, "Preserving devices with active PASIDS is NOT supported w/ Live Update\n");
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
		ret = arm_smmu_preserve_cd_table_linear(master, device_ser);
	else if (cd_table->s1fmt == STRTAB_STE_0_S1FMT_64K_L2)
		ret = arm_smmu_preserve_cd_table_2lvl(master, device_ser);

skip_cd_preservation:
	if (ret)
		return ret;

	ret = arm_smmu_preserve_l2_strtabs(master);
	if (ret) {
		arm_smmu_unpreserve_cd_table(master, device_ser);
		return ret;
	}

	/* Mark the master as preserved to track state during disable */
	master->preserved = true;
	return 0;
}

void arm_smmu_unpreserve_device(struct device *dev,
				struct iommu_device_ser *device_ser)
{
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);

	if (!master->preserved)
		return;

	master->preserved = false;
	arm_smmu_unpreserve_l2_strtabs(master, master->num_streams);
	arm_smmu_unpreserve_cd_table(master, device_ser);
}

static int arm_smmu_preserve_strtab_2lvl(struct arm_smmu_device *smmu,
					 struct iommu_hw_ser *iommu_ser)
{
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	u32 l1size = cfg->l2.num_l1_ents * sizeof(struct arm_smmu_strtab_l1);
	u64 *l2_states;
	u64 state;
	int ret;

	/* Preserve the L1 Stream table */
	ret = dmam_preserve_coherent_allocation(smmu->dev, cfg->l2.l1tab,
						l1size, cfg->l2.l1_dma, &state);
	if (ret) {
		dev_err(smmu->dev, "L1 table preservation failed\n");
		return ret;
	}
	iommu_ser->smmuv3.l1_strtab_lu_state = state;

	/* The L2 tables are preserved along with the masters using them */
	l2_states = kho_alloc_preserve(sizeof(*l2_states) * cfg->l2.num_l1_ents);
	if (IS_ERR(l2_states)) {
		dmam_unpreserve_coherent_allocation(smmu->dev, cfg->l2.l1tab,
						    l1size, cfg->l2.l1_dma, state);
		return PTR_ERR(l2_states);
	}

	iommu_ser->smmuv3.l2_strtab_lu_states_phys = virt_to_phys(l2_states);
	return 0;
}

static void arm_smmu_unpreserve_strtab_2lvl(struct arm_smmu_device *smmu,
					    struct iommu_hw_ser *iommu_ser)
{
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	u32 l1size = cfg->l2.num_l1_ents * sizeof(struct arm_smmu_strtab_l1);
	u64 *l2_states = phys_to_virt(iommu_ser->smmuv3.l2_strtab_lu_states_phys);
	u32 i;

	for (i = 0; i < cfg->l2.num_l1_ents; i++) {
		dma_addr_t l2_dma;

		if (!l2_states[i])
			continue;

		l2_dma = le64_to_cpu(cfg->l2.l1tab[i].l2ptr) & STRTAB_L1_DESC_L2PTR_MASK;
		dmam_unpreserve_coherent_allocation(smmu->dev, cfg->l2.l2ptrs[i],
						    sizeof(struct arm_smmu_strtab_l2),
						    l2_dma, l2_states[i]);
	}
	kho_unpreserve_free(l2_states);

	dmam_unpreserve_coherent_allocation(smmu->dev, cfg->l2.l1tab, l1size,
					    cfg->l2.l1_dma,
					    iommu_ser->smmuv3.l1_strtab_lu_state);
}

static int arm_smmu_preserve_strtab_linear(struct arm_smmu_device *smmu,
					   struct iommu_hw_ser *iommu_ser)
{
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	u32 size = (1 << smmu->sid_bits) * sizeof(struct arm_smmu_ste);
	u64 state;
	int ret;

	/* STRTAB BASE can't be changed hitlessly, preserve the whole table */
	ret = dmam_preserve_coherent_allocation(smmu->dev, cfg->linear.table,
						size, cfg->linear.ste_dma,
						&state);
	if (ret)
		return ret;

	iommu_ser->smmuv3.l1_strtab_lu_state = state;
	iommu_ser->smmuv3.l2_strtab_lu_states_phys = 0;
	return 0;
}

static void arm_smmu_unpreserve_strtab_linear(struct arm_smmu_device *smmu,
					      struct iommu_hw_ser *iommu_ser)
{
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	u32 size = (1 << smmu->sid_bits) * sizeof(struct arm_smmu_ste);

	dmam_unpreserve_coherent_allocation(smmu->dev, cfg->linear.table, size,
					    cfg->linear.ste_dma,
					    iommu_ser->smmuv3.l1_strtab_lu_state);
}

int arm_smmu_preserve(struct iommu_device *iommu,
		      struct iommu_hw_ser *iommu_ser)
{
	struct arm_smmu_device *smmu =
		container_of(iommu, struct arm_smmu_device, iommu);

	/* Basic info */
	iommu_ser->smmuv3.phys_addr = smmu->base_phys;
	iommu_ser->token = smmu->base_phys;
	iommu_ser->type = IOMMU_ARM_SMMUV3;
	iommu_ser->smmuv3.strtab_base_cfg =
		readl_relaxed(smmu->base + ARM_SMMU_STRTAB_BASE_CFG);

	/* We always implements 2-level when supported by HW */
	if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB)
		return arm_smmu_preserve_strtab_2lvl(smmu, iommu_ser);
	else
		return arm_smmu_preserve_strtab_linear(smmu, iommu_ser);
}

void arm_smmu_unpreserve(struct iommu_device *iommu,
			 struct iommu_hw_ser *iommu_ser)
{
	struct arm_smmu_device *smmu =
		container_of(iommu, struct arm_smmu_device, iommu);

	if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB)
		arm_smmu_unpreserve_strtab_2lvl(smmu, iommu_ser);
	else
		arm_smmu_unpreserve_strtab_linear(smmu, iommu_ser);
}

#endif
