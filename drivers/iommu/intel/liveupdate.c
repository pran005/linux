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
	/*
	 * The context tables preserved during device preservation, in the
	 * preserve_device() callback, might be shared with other devices, so
	 * those are unpreserved in the iommu unpreserve() callback. So this
	 * callback is kept empty.
	 *
	 * Once device PASID tables are preserved, the unpreservation of PASID
	 * tables will be added here.
	 */
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
