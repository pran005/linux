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
#include "pasid.h"
#include "../iommu-pages.h"

/* 2 tables per bus in scalable mode with upper table at odd bit */
#define CONTEXT_TABLE_PRESERVED_BIT(bus, devfn) (((bus) << 1) + ((devfn) >> 7))
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

	/*
	 * In the Intel IOMMU driver, context tables are never freed once they
	 * are allocated during runtime, as they can be shared across multiple
	 * devices. So taking the iommu lock here to protect against concurrent
	 * allocations inside iommu_context_addr() should be enough. Once the
	 * address is read, it is safe to use it without holding the lock.
	 */
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

	/*
	 * Intel IOMMU context tables are never freed by the driver once
	 * allocated. It is safe to access the context pointer outside of the
	 * iommu->lock.
	 */
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

	/*
	 * Individual invalidations for each context table removal are not
	 * needed as we issue global invalidations later.
	 */
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

static void clear_unpreserved_context(struct device_domain_info *info, u8 bus, u8 devfn)
{
	struct context_entry *context;

	/*
	 * This cleanup is done during shutdown, so it should be fine to only
	 * clear the entries here and issue one global invalidation later to
	 * invalidate all cleared entries.
	 *
	 * Note that the device IOTLB invalidation for unpreserved devices is
	 * skipped this way, but that should not be needed as the devices are
	 * quiesced at this point. This should improve the performance of the
	 * cleanup process and avoids any invalidation timeouts because drivers
	 * might have moved devices to D3 state.
	 *
	 * The iommu lock is not needed as the context tables are never removed
	 * and the new ones are not added during shutdown.
	 */
	context = iommu_context_addr(info->iommu, bus, devfn, 0);
	if (context) {
		/*
		 * Individual invalidations are not needed as we issue global
		 * invalidations later once all the cleanups are done.
		 */
		context_clear_present(context);
		__iommu_flush_cache(info->iommu, context, sizeof(*context));
		context_clear_entry(context);
		__iommu_flush_cache(info->iommu, context, sizeof(*context));
	}
}

static int clear_unpreserved_alias_cb(struct pci_dev *pdev, u16 alias, void *data)
{
	struct device_domain_info *info = data;

	clear_unpreserved_context(info, PCI_BUS_NUM(alias), alias & 0xff);
	return 0;
}

static int clear_unpreserve_context_entry_fn(struct device *dev,
					     struct iommu_device *iommu_dev,
					     void *arg)
{
	struct device_domain_info *info;

	info = dev_iommu_priv_get(dev);
	if (!info)
		return 0;

	if (dev_iommu_preserved_state(dev))
		return 0;

	if (dev_is_pci(dev))
		pci_for_each_dma_alias(to_pci_dev(dev),
				       clear_unpreserved_alias_cb, info);
	else
		clear_unpreserved_context(info, info->bus, info->devfn);

	return 0;
}

/**
 * clear_unpreserved_context_entries() - Clear context entries for unpreserved devices
 * @iommu: Target IOMMU
 *
 * Clear the context entries of unpreserved devices during shutdown before kexec.
 */
void clear_unpreserved_context_entries(struct intel_iommu *iommu)
{
	struct iommu_dev_iter iter = {
		.fn = clear_unpreserve_context_entry_fn,
		.iommu = &iommu->iommu,
		.arg = NULL,

	};

	/*
	 * Clear context entries for unpreserved devices because during kexec
	 * reboot and shutdown the devices do not go through the release flow,
	 * so there might be stale entries in the root table and context tables.
	 *
	 * Note that the error can be ignored as the iterator function does not
	 * fail.
	 */
	iommu_for_each_dev(&iter);

	/*
	 * New unpreserved context tables for unpreserved devices might have
	 * been added after preservation, so the root table entries for
	 * unpreserved context tables need to be removed.
	 */
	clear_unpreserved_context_root_entries(iommu,
					       iommu_preserved_state(&iommu->iommu));

	/*
	 * Some devices might not have teardown/detached properly depending on
	 * whether a proper device remove is done before kexec is triggered.
	 * Also unpreserved context tables and entries are removed during
	 * shutdown. So issue global invalidations to remove references to
	 * unpreserved tables and entries.
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
	int ret;

	if (WARN_ON(!ser->domain_iommu_ser.iommu_phys))
		return 0;

	iommu_hw_ser = phys_to_virt(ser->domain_iommu_ser.iommu_phys);
	if (iommu_hw_ser->type != IOMMU_INTEL)
		return 0;

	/* Only allocate domain ID from associated IOMMU HW unit */
	if (iommu_hw_ser->intel.phys_addr != iommu->reg_phys)
		return 0;

	guard(mutex)(&iommu->did_lock);

	/*
	 * The domain IDs are reclaimed while the IOMMU HW unit is being
	 * restored and not registered with the IOMMU core. So if the ID already
	 * exists, it is safe to assume that a preserved device sharing the same
	 * domain ID reclaimed it.
	 */
	if (ida_exists(&iommu->domain_ida, id))
		return 0;

	ret = ida_alloc_range(&iommu->domain_ida, id, id, GFP_KERNEL);
	if (ret < 0)
		return ret;

	return 0;
}

/**
 * intel_iommu_liveupdate_restore_root_table() - Restore root table and reclaim domain IDs
 * @iommu: Target IOMMU
 * @iommu_ser: Serialized IOMMU hardware state from previous kernel
 *
 * Restores the preserved root table and context tables for the IOMMU hardware
 * instance across Live Update, and reclaims all domain IDs previously allocated
 * to preserved devices so they are not reused.
 */
void intel_iommu_liveupdate_restore_root_table(struct intel_iommu *iommu,
					       struct iommu_hw_ser *iommu_ser)
{
	if (!iommu_ser->intel.restored)
		iommu_restore_pages(iommu_ser->intel.root_table);

	iommu->root_entry = __va(iommu_ser->intel.root_table);

	if (!iommu_ser->intel.restored)
		restore_iommu_context(iommu);

	iommu_ser->intel.restored = 1;
	BUG_ON(iommu_for_each_preserved_device(_restore_used_domain_ids, iommu));
}

static void domain_detach_reattached_iommu(struct dmar_domain *domain,
					   struct intel_iommu *iommu)
{
	struct iommu_domain_info *info;

	guard(mutex)(&iommu->did_lock);
	info = xa_load(&domain->iommu_array, iommu->seq_id);
	if (--info->refcnt == 0) {
		xa_erase(&domain->iommu_array, iommu->seq_id);
		kfree(info);
	}
}

static int domain_reattach_iommu(struct dmar_domain *domain,
				 struct intel_iommu *iommu,
				 struct iommu_device_ser *device_ser)
{
	struct iommu_domain_info *info, *curr;
	struct iommu_domain_ser *domain_ser;
	struct iommu_hw_ser *iommu_hw_ser;
	int restored_did;
	int ret;

	if (!iommu_domain_restored_state(&domain->domain))
		return -EINVAL;

	if (!device_ser->domain_iommu_ser.domain_phys ||
	    !device_ser->domain_iommu_ser.iommu_phys)
		return -EINVAL;

	domain_ser = phys_to_virt(device_ser->domain_iommu_ser.domain_phys);
	if (domain_ser->restored_domain != &domain->domain)
		return -EINVAL;

	iommu_hw_ser = phys_to_virt(device_ser->domain_iommu_ser.iommu_phys);
	if (iommu_hw_ser->type != IOMMU_INTEL ||
	    iommu_hw_ser->intel.phys_addr != iommu->reg_phys)
		return -EINVAL;

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

/**
 * intel_iommu_restore_device() - Restore device domain attachment after live update
 * @domain: Restored domain
 * @dev: Restored device
 *
 * Return: 0 on success, or negative error code.
 */
int intel_iommu_restore_device(struct iommu_domain *domain,
			       struct device *dev)
{
	struct iommu_device_ser *device_ser = dev_iommu_restored_state(dev);
	struct device_domain_info *info = dev_iommu_priv_get(dev);
	struct dmar_domain *dmar_domain = to_dmar_domain(domain);
	struct intel_iommu *iommu = info->iommu;
	unsigned long flags;
	int ret;

	if (!device_ser)
		return -EINVAL;

	if (dev_is_real_dma_subdevice(dev))
		return -EOPNOTSUPP;

	ret = domain_reattach_iommu(dmar_domain, iommu, device_ser);
	if (ret)
		return ret;

	info->domain = dmar_domain;
	info->domain_attached = true;
	spin_lock_irqsave(&dmar_domain->lock, flags);
	list_add(&info->link, &dmar_domain->devices);
	spin_unlock_irqrestore(&dmar_domain->lock, flags);

	ret = cache_tag_assign_domain(dmar_domain, dev, IOMMU_NO_PASID);
	if (ret)
		goto err;

	ret = iopf_for_domain_set(domain, dev);
	if (ret)
		goto err;

	return 0;

err:
	/*
	 * Detach the restored domain from device and iommu on failure, but keep
	 * the hardware state intact.
	 */
	info->domain_attached = false;
	cache_tag_unassign_domain(info->domain, dev, IOMMU_NO_PASID);
	spin_lock_irqsave(&info->domain->lock, flags);
	list_del(&info->link);
	spin_unlock_irqrestore(&info->domain->lock, flags);

	domain_detach_reattached_iommu(info->domain, iommu);
	info->domain = NULL;
	return ret;
}

int intel_iommu_detach_restored_device(struct device *dev)
{
	struct device_domain_info *info = dev_iommu_priv_get(dev);
	struct intel_iommu *iommu = info->iommu;
	struct iommu_domain *domain;
	unsigned long flags;

	if (!info->domain_attached || !info->domain)
		return -EINVAL;

	domain = &info->domain->domain;
	if (!iommu_domain_restored_state(domain))
		return -EINVAL;

	iopf_for_domain_remove(domain, dev);
	cache_tag_unassign_domain(info->domain, dev, IOMMU_NO_PASID);
	info->domain_attached = false;

	spin_lock_irqsave(&info->domain->lock, flags);
	list_del(&info->link);
	spin_unlock_irqrestore(&info->domain->lock, flags);

	domain_detach_reattached_iommu(info->domain, iommu);
	info->domain = NULL;

	return 0;
}

enum pasid_lu_op {
	PASID_LU_OP_PRESERVE = 1,
	PASID_LU_OP_UNPRESERVE,
	PASID_LU_OP_RESTORE,
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

	while (i > 0) {
		table = get_pasid_table_from_pde(&dir[--i]);
		if (!table)
			continue;

		pasid_lu_do_op(table, PASID_LU_OP_UNPRESERVE);
	}

	return ret;
}

/**
 * intel_iommu_preserve_device() - Intel IOMMU callback to preserve device state
 * @dev: Target device
 * @device_ser: Struct to populate with serialized device state
 *
 * Return: 0 on success, or negative error code.
 */
int intel_iommu_preserve_device(struct device *dev,
				struct iommu_device_ser *device_ser)
{
	struct device_domain_info *info = dev_iommu_priv_get(dev);
	struct pasid_table *pasid_table;
	int ret;

	if (!dev_is_pci(dev)) {
		dev_err(dev, "Cannot preserve non-PCI device\n");
		return -EOPNOTSUPP;
	}

	if (dev_is_real_dma_subdevice(dev))
		return -EOPNOTSUPP;

	if (!info || !info->domain)
		return -EINVAL;

	if (info->ats_supported)
		return -EOPNOTSUPP;

	ret = preserve_iommu_context_tables(info);
	if (ret)
		return ret;

	device_ser->domain_iommu_ser.attachment_id = domain_id_iommu(info->domain,
								     info->iommu);

	if (!sm_supported(info->iommu))
		return 0;

	pasid_table = intel_pasid_get_table(dev);
	if (!pasid_table)
		return -EINVAL;

	ret = pasid_lu_handle_pd(pasid_table->table,
				 pasid_table->max_pasid,
				 PASID_LU_OP_PRESERVE);
	if (ret)
		return ret;

	device_ser->intel.pasid_table = virt_to_phys(pasid_table->table);
	device_ser->intel.max_pasid = pasid_table->max_pasid;
	return 0;
}

/**
 * intel_iommu_unpreserve_device() - Intel IOMMU callback to unpreserve device state
 * @dev: Target device
 * @device_ser: Struct containing serialized device state
 */
void intel_iommu_unpreserve_device(struct device *dev,
				   struct iommu_device_ser *device_ser)
{
	struct device_domain_info *info = dev_iommu_priv_get(dev);
	struct pasid_table *pasid_table;

	if (!dev_is_pci(dev))
		return;

	if (!info)
		return;

	if (!sm_supported(info->iommu))
		return;

	/*
	 * The context tables preserved during device preservation, in the
	 * preserve_device() callback, might be shared with other devices, so
	 * those are unpreserved in the iommu unpreserve() callback.
	 */
	if (!device_ser->intel.pasid_table)
		return;

	pasid_table = intel_pasid_get_table(dev);
	if (!pasid_table)
		return;

	pasid_lu_handle_pd(pasid_table->table,
			   pasid_table->max_pasid,
			   PASID_LU_OP_UNPRESERVE);
}

/**
 * intel_iommu_preserve() - Intel IOMMU callback to preserve hardware state
 * @iommu_dev: Generic IOMMU device handle
 * @ser: Struct to populate with serialized hardware state
 *
 * Return: 0 on success, or negative error code.
 */
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

/**
 * intel_iommu_unpreserve() - Intel IOMMU callback to unpreserve hardware state
 * @iommu_dev: Generic IOMMU device handle
 * @ser: Struct containing serialized hardware state
 */
void intel_iommu_unpreserve(struct iommu_device *iommu_dev,
			    struct iommu_hw_ser *ser)
{
	struct intel_iommu *iommu;

	iommu = container_of(iommu_dev, struct intel_iommu, iommu);

	unpreserve_iommu_context_tables(iommu, ser);
	iommu_unpreserve_pages(iommu->root_entry);
}

/**
 * intel_pasid_restore_table() - Restore preserved PASID table for a device
 * @dev: Restored device
 * @max_pasid: Maximum supported PASID
 *
 * Return: Pointer to restored PASID table directory, or NULL if not preserved.
 */
void *intel_pasid_restore_table(struct device *dev, u64 max_pasid)
{
	struct iommu_device_ser *ser = dev_iommu_restored_state(dev);

	if (!ser || !ser->intel.pasid_table)
		return NULL;

	/*
	 * MAX PASID of a device should not change as it is read from
	 * capabilities.
	 */
	BUG_ON(ser->intel.max_pasid != max_pasid);

	if (ser->intel.restored)
		goto out;

	BUG_ON(pasid_lu_handle_pd(phys_to_virt(ser->intel.pasid_table),
				  ser->intel.max_pasid,
				  PASID_LU_OP_RESTORE));
	ser->intel.restored = 1;

out:
	return phys_to_virt(ser->intel.pasid_table);
}
