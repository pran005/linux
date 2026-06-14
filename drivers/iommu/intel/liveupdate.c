// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2026, Google LLC
 * Author: Samiullah Khawaja <skhawaja@google.com>
 */

#define pr_fmt(fmt)    "DMAR: liveupdate: " fmt

#include <linux/kexec_handover.h>
#include <linux/liveupdate.h>
#include <linux/iommu-liveupdate.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "iommu.h"
#include "../iommu-pages.h"

/* 2 tables per bus in scalable mode with upper table at odd bit */
#define CONTEXT_TABLE_PRESERVED_BIT(bus, devfn) ((bus << 1) + (devfn >> 7))
static bool is_context_table_preserved(struct intel_iommu *iommu,
				       struct iommu_hw_ser *ser,
				       u8 bus, u8 devfn)
{
	return test_bit(CONTEXT_TABLE_PRESERVED_BIT(bus, devfn),
			(unsigned long *)&ser->intel.context_tables_bitmap[0]);
}

static void unpreserve_context_table(struct intel_iommu *iommu,
				     struct iommu_hw_ser *ser,
				     u8 bus, u8 devfn)
{
	struct context_entry *context;

	spin_lock(&iommu->lock);
	context = iommu_context_addr(iommu, bus, devfn, 0);
	spin_unlock(&iommu->lock);
	if (context && is_context_table_preserved(iommu, ser, bus, devfn)) {
		iommu_unpreserve_pages(context);
		clear_bit(CONTEXT_TABLE_PRESERVED_BIT(bus, devfn),
			  (unsigned long *)&ser->intel.context_tables_bitmap[0]);
	}
}

static int preserve_context_table(struct intel_iommu *iommu,
				  struct iommu_hw_ser *ser,
				  u8 bus, u8 devfn)
{
	struct context_entry *context;
	int ret;

	spin_lock(&iommu->lock);
	context = iommu_context_addr(iommu, bus, devfn, 0);
	spin_unlock(&iommu->lock);
	if (context && !is_context_table_preserved(iommu, ser, bus, devfn)) {
		ret = iommu_preserve_pages(context);
		if (ret)
			return ret;

		set_bit(CONTEXT_TABLE_PRESERVED_BIT(bus, devfn),
			(unsigned long *)&ser->intel.context_tables_bitmap[0]);
	}

	return 0;
}

static void clear_unpreserved_context_root_entries(struct intel_iommu *iommu,
						   struct iommu_hw_ser *ser)
{
	struct root_entry *root;
	int i;

	for (i = 0; i < ROOT_ENTRY_NR; i++) {
		root = &iommu->root_entry[i];

		if (!is_context_table_preserved(iommu, ser, i, 0) && (root->lo & 1)) {
			root->lo = 0;
			__iommu_flush_cache(iommu,
					    &root->lo,
					    sizeof(root->lo));
		}

		if (!sm_supported(iommu))
			continue;

		if (!is_context_table_preserved(iommu, ser, i, 0x80) && (root->hi & 1)) {
			root->hi = 0;
			__iommu_flush_cache(iommu,
					    &root->hi,
					    sizeof(root->hi));
		}
	}
}

static int clear_unpreserve_context_entry_fn(struct device *dev,
					     struct iommu_device *iommu,
					     void *arg)
{
	struct device_domain_info *info;

	info = dev_iommu_priv_get(dev);
	if (!info)
		return 0;

	if (dev_is_pci(dev) && dev_iommu_preserved_state(dev))
		return 0;

	domain_context_clear(info);
	return 0;
}

void clear_unpreserved_context_entries(struct intel_iommu *iommu)
{
	struct iommu_dev_iter iter = {
		.fn = clear_unpreserve_context_entry_fn,
		.iommu = &iommu->iommu,
		.arg = NULL,

	};

	/* Clear context entries for unpreserved devices */
	iommu_for_each_dev(&iter);

	/* Clear reference to unpreserved context tables */
	clear_unpreserved_context_root_entries(iommu,
					       iommu_preserved_state(&iommu->iommu));

	/*
	 * Some devices might not have teardown/detached properly depending on
	 * whether a proper device remove is done before kexec is triggered.
	 * Also unpreserved context tables are removed during shutdown. So issue
	 * global invalidations to remove references to unpreserved tables and
	 * entries.
	 */
	iommu->flush.flush_context(iommu, 0, 0, 0, DMA_CCMD_GLOBAL_INVL);
	if (sm_supported(iommu))
		qi_flush_pasid_cache(iommu, 0, QI_PC_GLOBAL, 0);
	iommu->flush.flush_iotlb(iommu, 0, 0, 0, DMA_TLB_GLOBAL_FLUSH);
}

static void unpreserve_iommu_context_tables(struct intel_iommu *iommu,
					    struct iommu_hw_ser *ser)
{
	int i;

	for (i = 0; i < ROOT_ENTRY_NR; i++) {
		unpreserve_context_table(iommu, ser, i, 0);

		if (!sm_supported(iommu))
			continue;

		unpreserve_context_table(iommu, ser, i, 0x80);
	}
}

static int preserve_iommu_context_tables(struct device_domain_info *info)
{
	struct iommu_hw_ser *iommu_ser;
	struct intel_iommu *iommu;
	int ret;
	int i;

	/* IOMMU for this device should already preserved.*/
	iommu = info->iommu;
	iommu_ser = iommu_preserved_state(&iommu->iommu);
	if (!iommu_ser)
		return -EINVAL;

	/*
	 * We could do preservation of context tables only for the bus of this
	 * device, but these devices can have PCI aliases, so context tables for
	 * those will also require preservation. Also unpreserve would require
	 * some kind of refcounting where the context table will only be
	 * unpreserved when the last device associated with it is unpreserved.
	 *
	 * This introduces unnecessary complication with minimum benefits as the
	 * unpreserved context tables will probably be recreated by the next
	 * kernel as these are all active devices. We follow simpler approach by
	 * just preserving the currently active context tables.
	 */
	for (i = 0; i < ROOT_ENTRY_NR; i++) {
		ret = preserve_context_table(iommu, iommu_ser, i, 0);
		if (ret)
			return ret;

		if (!sm_supported(iommu))
			continue;

		ret = preserve_context_table(iommu, iommu_ser, i, 0x80);
		if (ret)
			return ret;
	}

	return 0;
}

static void restore_iommu_context(struct intel_iommu *iommu)
{
	struct context_entry *context;
	int i;

	for (i = 0; i < ROOT_ENTRY_NR; i++) {
		context = iommu_context_addr(iommu, i, 0, 0);
		if (context)
			iommu_restore_pages(virt_to_phys(context));

		if (!sm_supported(iommu))
			continue;

		context = iommu_context_addr(iommu, i, 0x80, 0);
		if (context)
			iommu_restore_pages(virt_to_phys(context));
	}
}

static int _restore_used_domain_ids(struct iommu_device_ser *ser, void *arg)
{
	int id = ser->domain_iommu_ser.attachment_id;
	struct iommu_hw_ser *iommu_hw_ser;
	struct intel_iommu *iommu = arg;

	if (WARN_ON(!ser->domain_iommu_ser.iommu_phys))
		return -ENOENT;

	iommu_hw_ser = phys_to_virt(ser->domain_iommu_ser.iommu_phys);
	if (iommu_hw_ser->type != IOMMU_INTEL)
		return 0;

	/* Only allocate domain ID from associated IOMMU HW unit */
	if (iommu_hw_ser->intel.phys_addr != iommu->reg_phys)
		return 0;

	/*
	 * This can fail as multiple preserved devices can share the same domain
	 * ID. Since this is done during DMAR init so these failures can be
	 * ignored.
	 */
	ida_alloc_range(&iommu->domain_ida, id, id, GFP_ATOMIC);
	return 0;
}

void intel_iommu_liveupdate_restore_root_table(struct intel_iommu *iommu,
					       struct iommu_hw_ser *iommu_ser)
{
	if (!iommu_ser->intel.restored)
		iommu_restore_pages(iommu_ser->intel.root_table);

	iommu->root_entry = __va(iommu_ser->intel.root_table);

	if (!iommu_ser->intel.restored)
		restore_iommu_context(iommu);

	iommu_ser->intel.restored = 1;
	iommu_for_each_preserved_device(_restore_used_domain_ids, iommu);
}

int intel_iommu_domain_reattach_iommu(struct dmar_domain *domain,
				      struct intel_iommu *iommu,
				      struct iommu_device_ser *device_ser)
{
	struct iommu_domain_info *info, *curr;
	int ret = -ENOSPC;
	int restored_did;

	if (domain->domain.type == IOMMU_DOMAIN_SVA)
		return 0;

	restored_did = device_ser->domain_iommu_ser.attachment_id;
	if (!ida_exists(&iommu->domain_ida, restored_did))
		return -EINVAL;

	info = kzalloc_obj(*info);
	if (!info)
		return -ENOMEM;

	guard(mutex)(&iommu->did_lock);
	curr = xa_load(&domain->iommu_array, iommu->seq_id);
	if (curr) {
		curr->refcnt++;
		kfree(info);
		return 0;
	}

	info->refcnt	= 1;
	info->did	= restored_did;
	info->iommu	= iommu;
	curr = xa_cmpxchg(&domain->iommu_array, iommu->seq_id,
			  NULL, info, GFP_KERNEL);
	if (curr) {
		ret = xa_err(curr) ? : -EBUSY;
		goto err_unlock;
	}

	return 0;

err_unlock:
	kfree(info);
	return ret;
}

enum pasid_lu_op {
	PASID_LU_OP_PRESERVE = 1,
	PASID_LU_OP_UNPRESERVE,
	PASID_LU_OP_RESTORE,
	PASID_LU_OP_FREE,
};

static int pasid_lu_do_op(void *table, enum pasid_lu_op op)
{
	int ret = 0;

	switch (op) {
	case PASID_LU_OP_PRESERVE:
		ret = iommu_preserve_pages(table);
		break;
	case PASID_LU_OP_UNPRESERVE:
		iommu_unpreserve_pages(table);
		break;
	case PASID_LU_OP_RESTORE:
		iommu_restore_pages(virt_to_phys(table));
		break;
	case PASID_LU_OP_FREE:
		iommu_free_pages(table);
		break;
	}

	return ret;
}

static int pasid_lu_handle_pd(struct pasid_dir_entry *dir,
			      u32 max_pasid, enum pasid_lu_op op)
{
	int max_pde = max_pasid >> PASID_PDE_SHIFT;
	struct pasid_entry *table;
	int i, ret;

	for (i = 0; i < max_pde; i++) {
		table = get_pasid_table_from_pde(&dir[i]);
		if (!table)
			continue;

		ret = pasid_lu_do_op(table, op);
		if (ret)
			goto err;
	}

	ret = pasid_lu_do_op(dir, op);
	if (ret)
		goto err;

	return 0;

err:
	if (op != PASID_LU_OP_PRESERVE)
		return ret;

	for (; i >= 0; i--) {
		table = get_pasid_table_from_pde(&dir[i]);
		if (!table)
			continue;

		pasid_lu_do_op(table, PASID_LU_OP_UNPRESERVE);
	}

	return ret;
}

int intel_iommu_preserve_device(struct device *dev,
				struct iommu_device_ser *device_ser)
{
	struct device_domain_info *info = dev_iommu_priv_get(dev);
	int ret;

	if (!dev_is_pci(dev)) {
		dev_err(dev, "Cannot preserve non-PCI device\n");
		return -EOPNOTSUPP;
	}

	if (!info || !info->domain)
		return -EINVAL;

	ret = preserve_iommu_context_tables(info);
	if (ret)
		return ret;

	device_ser->domain_iommu_ser.attachment_id = domain_id_iommu(info->domain,
								     info->iommu);
	return 0;
}

int intel_iommu_preserve(struct iommu_device *iommu_dev,
			 struct iommu_hw_ser *ser)
{
	struct intel_iommu *iommu;
	int ret;

	iommu = container_of(iommu_dev, struct intel_iommu, iommu);

	ret = iommu_preserve_pages(iommu->root_entry);
	if (ret)
		return ret;

	ser->intel.phys_addr = iommu->reg_phys;
	ser->intel.root_table = __pa(iommu->root_entry);
	ser->type = IOMMU_INTEL;
	ser->token = ser->intel.phys_addr;

	return 0;
}

void intel_iommu_unpreserve(struct iommu_device *iommu_dev,
			    struct iommu_hw_ser *ser)
{
	struct intel_iommu *iommu;

	iommu = container_of(iommu_dev, struct intel_iommu, iommu);

	unpreserve_iommu_context_tables(iommu, ser);
	iommu_unpreserve_pages(iommu->root_entry);
}
