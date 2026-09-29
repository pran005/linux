// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Google LLC
 * Author: Pranjal Shrivastava <praan@google.com>
 */

#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
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

	/* Record the ASID/VMID for the incoming kernel to cross-check */
	device_ser->domain_iommu_ser.attachment_id =
		smmu_domain->stage == ARM_SMMU_DOMAIN_S1 ?
			smmu_domain->cd.asid : smmu_domain->s2_cfg.vmid;

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
	u32 cr0;
	int ret;

	/* Only the incoming kernel unmasks the SMMU interrupts again */
	if (arm_smmu_disable_irqs(smmu))
		dev_warn(smmu->dev, "failed to disable irqs\n");

	/* Wait for a running EVTQ handler */
	if (smmu->combined_irq || smmu->evtq.q.irq)
		synchronize_irq(smmu->combined_irq ?: smmu->evtq.q.irq);

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

	/*
	 * No need to drain the CMDQ: the invalidations above are synced, no
	 * other submitters are left at shutdown and the incoming kernel
	 * invalidates everything again.
	 * TODO: Quiesce the CMDQV VCMDQs assigned to guests.
	 */

	/* Disable the queues, leaving SMMUEN set for the preserved masters */
	cr0 = readl_relaxed(smmu->base + ARM_SMMU_CR0);
	cr0 &= ~(CR0_CMDQEN | CR0_EVTQEN | CR0_PRIQEN);
	ret = arm_smmu_write_reg_sync(smmu, cr0, ARM_SMMU_CR0, ARM_SMMU_CR0ACK);
	if (ret)
		dev_err(smmu->dev, "failed to disable queues\n");
	return ret;
}

static int arm_smmu_liveupdate_restore_strtab_2lvl(struct arm_smmu_device *smmu,
						   struct iommu_hw_ser *iommu_ser,
						   u32 cfg_reg, phys_addr_t base)
{
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	u32 num_l1_ents, i;
	u64 *l2_states;
	int ret;

	if (!iommu_ser->smmuv3.l2_strtab_lu_states_phys)
		return -EINVAL;
	l2_states = phys_to_virt(iommu_ser->smmuv3.l2_strtab_lu_states_phys);

	ret = arm_smmu_kexec_parse_strtab_2lvl(smmu, cfg_reg, base,
					       &num_l1_ents);
	if (ret)
		goto out_free_states;
	cfg->l2.num_l1_ents = num_l1_ents;

	ret = -ENOMEM;
	cfg->l2.l1tab = dmam_restore_coherent_allocation(smmu->dev,
			num_l1_ents * sizeof(*cfg->l2.l1tab), &cfg->l2.l1_dma,
			GFP_KERNEL, iommu_ser->smmuv3.l1_strtab_lu_state);
	if (!cfg->l2.l1tab)
		goto out_free_states;

	cfg->l2.l2ptrs = devm_kcalloc(smmu->dev, num_l1_ents,
				      sizeof(*cfg->l2.l2ptrs), GFP_KERNEL);
	if (!cfg->l2.l2ptrs)
		goto out_free_states;

	/* The outgoing .shutdown cleared the L1 STDs of unpreserved L2 tables */
	for (i = 0; i < num_l1_ents; i++) {
		u64 l1_desc = le64_to_cpu(cfg->l2.l1tab[i].l2ptr);
		phys_addr_t l2_base;
		dma_addr_t l2_dma;

		ret = arm_smmu_kexec_check_strtab_l1_desc(smmu, l1_desc, i,
							  &l2_base);
		if (ret == 1)
			continue;
		if (ret)
			goto out_free_states;

		if (!l2_states[i]) {
			dev_err(smmu->dev, "L1[%u] has no preserved L2 table\n",
				i);
			ret = -EINVAL;
			goto out_free_states;
		}

		l2_dma = l2_base;
		cfg->l2.l2ptrs[i] = dmam_restore_coherent_allocation(smmu->dev,
				sizeof(*cfg->l2.l2ptrs[i]), &l2_dma, GFP_KERNEL,
				l2_states[i]);
		if (!cfg->l2.l2ptrs[i]) {
			ret = -ENOMEM;
			goto out_free_states;
		}
	}
	ret = 0;

out_free_states:
	kho_restore_free(l2_states);
	return ret;
}

static int
arm_smmu_liveupdate_restore_strtab_linear(struct arm_smmu_device *smmu,
					  struct iommu_hw_ser *iommu_ser,
					  u32 cfg_reg, phys_addr_t base)
{
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	u32 num_ents;
	int ret;

	ret = arm_smmu_kexec_parse_strtab_linear(smmu, cfg_reg, base,
						 &num_ents);
	if (ret)
		return ret;
	cfg->linear.num_ents = num_ents;

	cfg->linear.table = dmam_restore_coherent_allocation(smmu->dev,
			num_ents * sizeof(*cfg->linear.table),
			&cfg->linear.ste_dma, GFP_KERNEL,
			iommu_ser->smmuv3.l1_strtab_lu_state);
	if (!cfg->linear.table)
		return -ENOMEM;
	return 0;
}

/*
 * Take over the stream table left programmed by the previous kernel and
 * reserve the ASIDs/VMIDs used by the preserved STEs. Returns -ENOENT if
 * nothing was preserved for this SMMU.
 */
int arm_smmu_liveupdate_restore_strtab(struct arm_smmu_device *smmu)
{
	u32 cfg_reg = readl_relaxed(smmu->base + ARM_SMMU_STRTAB_BASE_CFG);
	u64 base_reg = readq_relaxed(smmu->base + ARM_SMMU_STRTAB_BASE);
	bool is_2lvl = smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB;
	phys_addr_t base = base_reg & STRTAB_BASE_ADDR_MASK;
	u32 fmt = FIELD_GET(STRTAB_BASE_CFG_FMT, cfg_reg);
	struct iommu_hw_ser *iommu_ser;
	int ret;

	iommu_ser = iommu_get_preserved_data(smmu->base_phys, IOMMU_ARM_SMMUV3);
	if (!iommu_ser)
		return -ENOENT;

	if (cfg_reg != iommu_ser->smmuv3.strtab_base_cfg) {
		dev_err(smmu->dev, "STRTAB_BASE_CFG changed across live update\n");
		return -EINVAL;
	}

	/* The preserving kernel always uses a 2-level table when supported */
	if (fmt == STRTAB_BASE_CFG_FMT_2LVL && is_2lvl)
		ret = arm_smmu_liveupdate_restore_strtab_2lvl(smmu, iommu_ser,
							      cfg_reg, base);
	else if (fmt == STRTAB_BASE_CFG_FMT_LINEAR && !is_2lvl)
		ret = arm_smmu_liveupdate_restore_strtab_linear(smmu, iommu_ser,
								cfg_reg, base);
	else
		ret = -EINVAL;
	if (ret) {
		dev_err(smmu->dev, "failed to restore stream table: %d\n", ret);
		return ret;
	}

	/* Keep new domains off the ASIDs/VMIDs used by the preserved STEs */
	ret = arm_smmu_kexec_scan_and_resv_ids(smmu);
	if (ret) {
		dev_err(smmu->dev, "failed to reserve in-use ASIDs/VMIDs\n");
		arm_smmu_kexec_unresv_ids(smmu);
		return ret;
	}

	dev_info(smmu->dev, "restored preserved %s stream table\n",
		 is_2lvl ? "2-level" : "linear");
	return 0;
}

int arm_smmu_liveupdate_restore_cd_tables(struct arm_smmu_master *master)
{
	struct arm_smmu_device *smmu = master->smmu;
	struct arm_smmu_ctx_desc_cfg *cd_table = &master->cd_table;
	struct iommu_device_ser *dev_ser = dev_iommu_restored_state(master->dev);
	u32 max_contexts, s1fmt, num_l2, restored = 0, i;
	struct arm_smmu_ste *ste;
	u64 *l2_states = NULL;
	phys_addr_t cdtab;
	u64 ste0;
	int ret;

	if (!dev_ser)
		return 0;

	/* Only an S1 STE has a CD table behind it */
	ste = arm_smmu_get_step_for_sid(smmu, master->streams[0].id);
	ste0 = le64_to_cpu(ste->data[0]);
	if (!(ste0 & STRTAB_STE_0_V) ||
	    FIELD_GET(STRTAB_STE_0_CFG, ste0) != STRTAB_STE_0_CFG_S1_TRANS)
		return 0;

	ret = arm_smmu_kexec_check_ste_cdtab(smmu, ste0, &cdtab, &s1fmt,
					     &max_contexts);
	if (ret)
		return ret;

	cd_table->s1cdmax = ilog2(max_contexts);
	cd_table->s1fmt = s1fmt;

	if (s1fmt == STRTAB_STE_0_S1FMT_LINEAR) {
		cd_table->linear.num_ents = max_contexts;
		cd_table->linear.table = dma_restore_coherent_allocation(smmu->dev,
				max_contexts * sizeof(*cd_table->linear.table),
				&cd_table->cdtab_dma, GFP_KERNEL,
				dev_ser->smmuv3.l1_cdtab_lu_state);
		return cd_table->linear.table ? 0 : -ENOMEM;
	}

	cd_table->l2.num_l1_ents = DIV_ROUND_UP(max_contexts,
						CTXDESC_L2_ENTRIES);
	cd_table->l2.l1tab = dma_restore_coherent_allocation(smmu->dev,
			cd_table->l2.num_l1_ents * sizeof(*cd_table->l2.l1tab),
			&cd_table->cdtab_dma, GFP_KERNEL,
			dev_ser->smmuv3.l1_cdtab_lu_state);
	if (!cd_table->l2.l1tab)
		return -ENOMEM;

	cd_table->l2.l2ptrs = kcalloc(cd_table->l2.num_l1_ents,
				      sizeof(*cd_table->l2.l2ptrs), GFP_KERNEL);
	if (!cd_table->l2.l2ptrs)
		return -ENOMEM;

	num_l2 = dev_ser->smmuv3.num_l2_cdtables;
	if (num_l2)
		l2_states = phys_to_virt(dev_ser->smmuv3.l2_cdtab_lu_states_phys);

	for (i = 0; i < cd_table->l2.num_l1_ents; i++) {
		u64 l1_desc = le64_to_cpu(cd_table->l2.l1tab[i].l2ptr);
		phys_addr_t l2_base;
		dma_addr_t l2_dma;

		ret = arm_smmu_kexec_check_cdtab_l1_desc(l1_desc, &l2_base);
		if (ret == 1)
			continue;
		if (ret)
			goto out_free_states;

		if (restored >= num_l2) {
			ret = -EINVAL;
			goto out_free_states;
		}

		l2_dma = l2_base;
		cd_table->l2.l2ptrs[i] = dma_restore_coherent_allocation(smmu->dev,
				sizeof(*cd_table->l2.l2ptrs[i]), &l2_dma,
				GFP_KERNEL, l2_states[restored++]);
		if (!cd_table->l2.l2ptrs[i]) {
			ret = -ENOMEM;
			goto out_free_states;
		}
	}
	ret = 0;

out_free_states:
	if (l2_states)
		kho_restore_free(l2_states);
	return ret;
}

/* Hand over the reserved ASID/VMID, releasing the never programmed one */
static int arm_smmu_liveupdate_inherit_id(struct arm_smmu_domain *smmu_domain,
					  u32 id)
{
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	int ret;

	if (smmu_domain->stage == ARM_SMMU_DOMAIN_S1) {
		if (smmu_domain->cd.asid == id)
			return 0;

		/* Only a reserved entry, which loads as NULL, can be taken */
		if (xa_load(&smmu->asid_map, id))
			return -EBUSY;
		ret = xa_err(xa_store(&smmu->asid_map, id, smmu_domain,
				      GFP_KERNEL));
		if (ret)
			return ret;
		xa_erase(&smmu->asid_map, smmu_domain->cd.asid);
		smmu_domain->cd.asid = id;
		return 0;
	}

	if (smmu_domain->s2_cfg.vmid == id)
		return 0;

	/* The vmid_map already holds @id, simply transfer its ownership */
	ida_free(&smmu->vmid_map, smmu_domain->s2_cfg.vmid);
	smmu_domain->s2_cfg.vmid = id;
	return 0;
}

/*
 * Inherit the live ASID/VMID of a restored master, after checking that
 * @smmu_domain matches its live translation. Called before
 * arm_smmu_attach_prepare() builds the invalidation array.
 */
int arm_smmu_liveupdate_attach_restored(struct arm_smmu_master *master,
					struct arm_smmu_domain *smmu_domain)
{
	struct iommu_device_ser *dev_ser = dev_iommu_restored_state(master->dev);
	struct arm_smmu_device *smmu = master->smmu;
	struct pt_iommu_armv8_hw_info info;
	struct arm_smmu_ste *ste;
	u64 ste0, ttb, live_ttb;
	u32 id;

	lockdep_assert_held(&arm_smmu_asid_lock);

	if (!dev_ser || !iommu_domain_restored_state(&smmu_domain->domain))
		return 0;

	ste = arm_smmu_get_step_for_sid(smmu, master->streams[0].id);
	ste0 = le64_to_cpu(ste->data[0]);
	if (!(ste0 & STRTAB_STE_0_V))
		return 0;

	pt_iommu_armv8_hw_info(&smmu_domain->armv8pt, &info);

	switch (FIELD_GET(STRTAB_STE_0_CFG, ste0)) {
	case STRTAB_STE_0_CFG_S1_TRANS: {
		struct arm_smmu_cd *cdptr;
		u64 cd0;

		if (smmu_domain->stage != ARM_SMMU_DOMAIN_S1)
			goto err_mismatch;

		cdptr = arm_smmu_get_cd_ptr(master, IOMMU_NO_PASID);
		if (!cdptr)
			goto err_mismatch;

		cd0 = le64_to_cpu(cdptr->data[0]);
		if (!(cd0 & CTXDESC_CD_0_V))
			goto err_mismatch;

		id = FIELD_GET(CTXDESC_CD_0_ASID, cd0);
		live_ttb = le64_to_cpu(cdptr->data[1]) & CTXDESC_CD_1_TTB0_MASK;
		ttb = info.ttb & CTXDESC_CD_1_TTB0_MASK;
		break;
	}
	case STRTAB_STE_0_CFG_S2_TRANS:
		if (smmu_domain->stage != ARM_SMMU_DOMAIN_S2)
			goto err_mismatch;

		id = FIELD_GET(STRTAB_STE_2_S2VMID, le64_to_cpu(ste->data[2]));
		live_ttb = le64_to_cpu(ste->data[3]) & STRTAB_STE_3_S2TTB_MASK;
		ttb = info.ttb & STRTAB_STE_3_S2TTB_MASK;
		break;
	default:
		/* Nothing to inherit, nested STEs aren't restored (yet) */
		return 0;
	}

	if (live_ttb != ttb || id != dev_ser->domain_iommu_ser.attachment_id)
		goto err_mismatch;

	/* A shared restored domain inherits its ID on the first attach */
	if (!list_empty(&smmu_domain->devices) &&
	    id != (smmu_domain->stage == ARM_SMMU_DOMAIN_S1 ?
		   smmu_domain->cd.asid : smmu_domain->s2_cfg.vmid))
		goto err_mismatch;

	return arm_smmu_liveupdate_inherit_id(smmu_domain, id);

err_mismatch:
	dev_err(master->dev,
		"restored domain doesn't match the live translation\n");
	return -EINVAL;
}

#endif
