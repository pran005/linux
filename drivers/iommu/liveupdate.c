// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2026, Google LLC
 * Author: Samiullah Khawaja <skhawaja@google.com>
 */

/**
 * DOC: IOMMU Live Update
 *
 * The IOMMU subsystem participates in the Live Update process to preserve its
 * IOMMU domains and IOMMU specific state of preserved devices.
 *
 * File-Lifecycle-Bound (FLB) Data
 * ===============================
 *
 * Preserved state of IOMMU HW needs to be restored during boot when the IOMMU is
 * initialized and registered. The preserved IOMMU domains also need to be
 * restored and associated with the preserved devices early during boot. For
 * this reason, IOMMU subsystem uses LUO File-Lifecycle-Bound Data to store some
 * state globally.
 *
 * During preservation of IOMMUFD into LUO, some of the state is stored in the
 * IOMMU FLB so it can be restored during boot. Once the FDs are retrieved from LUO
 * the restored state can be reassociated with the relevant IOMMUFDs.
 *
 * The FLB also contains the state of IOMMU HW that might be shared between
 * multiple devices, domains and iommufds. This is restored early during boot
 * and no re-association of this state is needed later.
 *
 * As the state is preserved using KHO, the FLB handler callbacks are called by
 * LUO only when the KHO is enabled. So there is no need to check whether KHO is
 * enabled in the callback implementation.
 *
 */

#define pr_fmt(fmt)    "iommu: liveupdate: " fmt

#include <linux/errno.h>
#include <linux/generic_pt/iommu.h>
#include <linux/iommu-liveupdate.h>
#include <linux/iommu.h>
#include <linux/kexec_handover.h>
#include <linux/liveupdate.h>
#include <linux/pci.h>

#include "iommu-priv.h"

#define iommu_max_objs_per_page(_array) \
	((PAGE_SIZE - sizeof(struct iommu_array_hdr_ser)) / sizeof((_array)->objects[0]))

struct iommu_flb_obj {
	struct mutex lock;
	struct iommu_flb_ser *ser;

	struct iommu_hw_array_ser *curr_iommu_array;
	struct iommu_domain_array_ser *curr_domain_array;
	struct iommu_device_array_ser *curr_device_array;
};

static void *iommu_liveupdate_restore_array(u64 array_phys)
{
	struct iommu_array_hdr_ser *array_hdr;
	void *vaddr = array_phys ? phys_to_virt(array_phys) : NULL;

	while (array_phys) {
		/*
		 * Failure to restore preserved IOMMU state is considered fatal.
		 *
		 * This is because the IOMMU translations for preserved IOMMUs
		 * were kept enabled in the previous kernel and the preserved
		 * devices have their IOMMU domains still present. Not being
		 * able to restore means that the memory mapped into preserved
		 * domains might be already corrupted by the preserved devices.
		 *
		 * There is no way to confirm the integrity of the memory that
		 * was mapped. BUG_ON is the safest option at this point.
		 */
		BUG_ON(!kho_restore_folio(array_phys));
		array_hdr = phys_to_virt(array_phys);
		array_phys = array_hdr->next_array_phys;
	}

	return vaddr;
}

static void iommu_liveupdate_unpreserve_free(u64 array_phys)
{
	struct iommu_array_hdr_ser *array_hdr;

	while (array_phys) {
		array_hdr = phys_to_virt(array_phys);
		array_phys = array_hdr->next_array_phys;
		kho_unpreserve_free(array_hdr);
	}
}

static void iommu_liveupdate_folio_put(u64 array_phys)
{
	struct iommu_array_hdr_ser *array_hdr;

	while (array_phys) {
		array_hdr = phys_to_virt(array_phys);
		array_phys = array_hdr->next_array_phys;
		folio_put(virt_to_folio(array_hdr));
	}
}

static void iommu_liveupdate_flb_free(struct iommu_flb_obj *obj)
{
	iommu_liveupdate_unpreserve_free(obj->ser->iommu_domain_array_phys);
	iommu_liveupdate_unpreserve_free(obj->ser->device_array_phys);
	iommu_liveupdate_unpreserve_free(obj->ser->iommu_array_phys);

	kho_unpreserve_free(obj->ser);
	mutex_destroy(&obj->lock);
	kfree(obj);
}

static int iommu_liveupdate_flb_preserve(struct liveupdate_flb_op_args *argp)
{
	struct iommu_flb_obj *obj;
	struct iommu_flb_ser *ser;
	void *mem;

	/* obj exists only in the current kernel to track preserved state */
	obj = kzalloc_obj(*obj, GFP_KERNEL);
	if (!obj)
		return -ENOMEM;

	mutex_init(&obj->lock);

	/* mem is allocated via KHO and will survive the kexec */
	mem = kho_alloc_preserve(sizeof(*ser));
	if (IS_ERR(mem))
		goto err_free_obj;

	ser = mem;
	obj->ser = ser;
	ser->version = IOMMU_LUO_FLB_VERSION;

	mem = kho_alloc_preserve(PAGE_SIZE);
	if (IS_ERR(mem))
		goto err_free_ser;

	obj->curr_domain_array = mem;
	ser->iommu_domain_array_phys = virt_to_phys(obj->curr_domain_array);

	mem = kho_alloc_preserve(PAGE_SIZE);
	if (IS_ERR(mem))
		goto err_free_domains;

	obj->curr_device_array = mem;
	ser->device_array_phys = virt_to_phys(obj->curr_device_array);

	mem = kho_alloc_preserve(PAGE_SIZE);
	if (IS_ERR(mem))
		goto err_free_devices;

	obj->curr_iommu_array = mem;
	ser->iommu_array_phys = virt_to_phys(obj->curr_iommu_array);

	argp->obj = obj;
	argp->data = virt_to_phys(ser);
	return 0;

err_free_devices:
	kho_unpreserve_free(obj->curr_device_array);
err_free_domains:
	kho_unpreserve_free(obj->curr_domain_array);
err_free_ser:
	kho_unpreserve_free(obj->ser);
err_free_obj:
	mutex_destroy(&obj->lock);
	kfree(obj);
	return PTR_ERR(mem);
}

static void iommu_liveupdate_flb_unpreserve(struct liveupdate_flb_op_args *argp)
{
	iommu_liveupdate_flb_free(argp->obj);
}

static void iommu_liveupdate_flb_finish(struct liveupdate_flb_op_args *argp)
{
	struct iommu_flb_obj *obj = argp->obj;

	iommu_liveupdate_folio_put(obj->ser->iommu_domain_array_phys);
	iommu_liveupdate_folio_put(obj->ser->device_array_phys);
	iommu_liveupdate_folio_put(obj->ser->iommu_array_phys);

	folio_put(virt_to_folio(obj->ser));
	mutex_destroy(&obj->lock);
	kfree(obj);
}

static int iommu_liveupdate_flb_retrieve(struct liveupdate_flb_op_args *argp)
{
	struct iommu_flb_obj *obj;
	struct iommu_flb_ser *ser;

	obj = kzalloc_obj(*obj, GFP_KERNEL);
	if (!obj) {
		/*
		 * If retrieve fails, the finish path won't be called as
		 * can_finish() will fail, preventing the restore.
		 */
		return -ENOMEM;
	}

	/* Data must be present and valid from the previous kernel */
	BUG_ON(!kho_restore_folio(argp->data));

	mutex_init(&obj->lock);
	ser = phys_to_virt(argp->data);
	obj->ser = ser;

	obj->curr_domain_array = iommu_liveupdate_restore_array(ser->iommu_domain_array_phys);
	obj->curr_device_array = iommu_liveupdate_restore_array(ser->device_array_phys);
	obj->curr_iommu_array = iommu_liveupdate_restore_array(ser->iommu_array_phys);
	argp->obj = obj;
	return 0;
}

static struct liveupdate_flb_ops iommu_flb_ops = {
	.preserve = iommu_liveupdate_flb_preserve,
	.unpreserve = iommu_liveupdate_flb_unpreserve,
	.retrieve = iommu_liveupdate_flb_retrieve,
	.finish = iommu_liveupdate_flb_finish,
};

static struct liveupdate_flb iommu_flb = {
	.compatible = IOMMU_LUO_FLB_COMPATIBLE,
	.ops = &iommu_flb_ops,
};

/**
 * iommu_liveupdate_register_flb() - Register IOMMU Live Update FLB
 * @handler: Live Update file handler to associate FLB with
 *
 * Register a Live Update FLB for IOMMU state preservation with the file
 * handler.
 *
 * Return: 0 on success, or negative error code.
 */
int iommu_liveupdate_register_flb(struct liveupdate_file_handler *handler)
{
	return liveupdate_register_flb(handler, &iommu_flb);
}
EXPORT_SYMBOL(iommu_liveupdate_register_flb);

/**
 * iommu_liveupdate_unregister_flb() - Unregister IOMMU Live Update FLB
 * @handler: Live Update file handler to associate FLB with
 */
void iommu_liveupdate_unregister_flb(struct liveupdate_file_handler *handler)
{
	liveupdate_unregister_flb(handler, &iommu_flb);
}
EXPORT_SYMBOL(iommu_liveupdate_unregister_flb);

static int alloc_object_ser(void **curr_array_ptr, u64 max_objs)
{
	struct iommu_array_hdr_ser *curr_array = *curr_array_ptr;
	struct iommu_array_hdr_ser *next_array;

	/*
	 * The objects marked as deleted are not reused to avoid traversal of
	 * linked-list and arrays.
	 */
	if (curr_array->nr_objects >= max_objs) {
		next_array = kho_alloc_preserve(PAGE_SIZE);
		if (IS_ERR(next_array))
			return PTR_ERR(next_array);

		curr_array->next_array_phys = virt_to_phys(next_array);
		*curr_array_ptr = next_array;
		curr_array = next_array;
	}

	return curr_array->nr_objects++;
}

static struct iommu_domain_ser *alloc_iommu_domain_ser(struct iommu_flb_obj *flb)
{
	int idx;

	idx = alloc_object_ser((void **) &flb->curr_domain_array,
			       iommu_max_objs_per_page(flb->curr_domain_array));
	if (idx < 0)
		return ERR_PTR(idx);

	flb->curr_domain_array->objects[idx].hdr.ref_count = 1;
	return &flb->curr_domain_array->objects[idx];
}

/**
 * iommu_preserve_domain() - Preserve an IOMMU domain across live update
 * @domain: Domain to preserve
 * @ser: Pointer to receive the virtual serialized domain state handle
 *
 * Return: 0 on success, or negative error code.
 */
int iommu_preserve_domain(struct iommu_domain *domain, struct iommu_domain_ser **ser)
{
	struct pt_iommu *pt = iommupt_from_domain(domain);
	struct iommu_domain_ser *domain_ser;
	struct iommu_flb_obj *flb_obj;
	int ret;

	if (!pt || !pt->ops->preserve || !pt->ops->unpreserve)
		return -EOPNOTSUPP;

	ret = liveupdate_flb_get_outgoing(&iommu_flb, (void **)&flb_obj);
	if (ret)
		return ret;

	mutex_lock(&flb_obj->lock);
	if (domain->preserved_state) {
		ret = -EBUSY;
		goto out_unlock;
	}

	domain_ser = alloc_iommu_domain_ser(flb_obj);
	if (IS_ERR(domain_ser)) {
		ret = PTR_ERR(domain_ser);
		goto out_unlock;
	}

	ret = pt->ops->preserve(pt, domain_ser);
	if (ret) {
		domain_ser->hdr.flags |= IOMMU_SER_FLAG_DELETED;
		goto out_unlock;
	}

	domain->preserved_state = domain_ser;
	*ser = domain_ser;
	ret = 0;
out_unlock:
	mutex_unlock(&flb_obj->lock);
	liveupdate_flb_put_outgoing(&iommu_flb);
	return ret;
}
EXPORT_SYMBOL_GPL(iommu_preserve_domain);

/**
 * iommu_unpreserve_domain() - Unpreserve a preserved IOMMU domain
 * @domain: Domain to unpreserve
 */
void iommu_unpreserve_domain(struct iommu_domain *domain)
{
	struct pt_iommu *pt = iommupt_from_domain(domain);
	struct iommu_domain_ser *domain_ser;
	struct iommu_flb_obj *flb_obj;
	int ret;

	if (WARN_ON(!pt || !pt->ops->unpreserve))
		return;

	ret = liveupdate_flb_get_outgoing(&iommu_flb, (void **)&flb_obj);
	if (WARN_ON(ret))
		return;

	mutex_lock(&flb_obj->lock);
	if (!domain->preserved_state)
		goto out_unlock;

	/*
	 * There is no check for attached devices here. The correctness relies
	 * on the Live Update Orchestrator's session lifecycle. All resources
	 * (iommufd, vfio devices) are preserved within a single session. If the
	 * session is torn down, the .unpreserve callbacks for all files will be
	 * invoked, ensuring a consistent cleanup without needing explicit
	 * refcounting for the serialized objects here.
	 */
	domain_ser = domain->preserved_state;
	pt->ops->unpreserve(pt, domain_ser);
	domain_ser->hdr.flags |= IOMMU_SER_FLAG_DELETED;
	domain->preserved_state = NULL;
out_unlock:
	mutex_unlock(&flb_obj->lock);
	liveupdate_flb_put_outgoing(&iommu_flb);
}
EXPORT_SYMBOL_GPL(iommu_unpreserve_domain);

static struct iommu_hw_ser *alloc_iommu_hw_ser(struct iommu_flb_obj *flb)
{
	int idx;

	idx = alloc_object_ser((void **)&flb->curr_iommu_array,
			       iommu_max_objs_per_page(flb->curr_iommu_array));
	if (idx < 0)
		return ERR_PTR(idx);

	flb->curr_iommu_array->objects[idx].hdr.ref_count = 1;
	return &flb->curr_iommu_array->objects[idx];
}

static int iommu_preserve_locked(struct iommu_device *iommu,
				 struct iommu_flb_obj *flb_obj)
{
	struct iommu_hw_ser *iommu_hw_ser;
	int ret;

	if (!iommu->ops->preserve || !iommu->ops->unpreserve)
		return -EOPNOTSUPP;

	lockdep_assert_held(&flb_obj->lock);
	if (iommu->outgoing_preserved_state) {
		iommu->outgoing_preserved_state->hdr.ref_count++;
		return 0;
	}

	iommu_hw_ser = alloc_iommu_hw_ser(flb_obj);
	if (IS_ERR(iommu_hw_ser))
		return PTR_ERR(iommu_hw_ser);

	ret = iommu->ops->preserve(iommu, iommu_hw_ser);
	if (ret) {
		iommu_hw_ser->hdr.flags |= IOMMU_SER_FLAG_DELETED;
		return ret;
	}

	iommu->outgoing_preserved_state = iommu_hw_ser;
	return ret;
}

static void iommu_unpreserve_locked(struct iommu_device *iommu,
				    struct iommu_flb_obj *flb_obj)
{
	struct iommu_hw_ser *iommu_hw_ser = iommu->outgoing_preserved_state;

	lockdep_assert_held(&flb_obj->lock);
	if (WARN_ON(!iommu_hw_ser))
		return;

	if (WARN_ON_ONCE(!iommu->ops->preserve ||
			 !iommu->ops->unpreserve))
		return;

	iommu_hw_ser->hdr.ref_count--;
	if (iommu_hw_ser->hdr.ref_count)
		return;

	iommu->outgoing_preserved_state = NULL;
	iommu->ops->unpreserve(iommu, iommu_hw_ser);
	iommu_hw_ser->hdr.flags |= IOMMU_SER_FLAG_DELETED;
}

static struct iommu_device_ser *alloc_iommu_device_ser(struct iommu_flb_obj *flb)
{
	int idx;

	idx = alloc_object_ser((void **)&flb->curr_device_array,
			       iommu_max_objs_per_page(flb->curr_device_array));
	if (idx < 0)
		return ERR_PTR(idx);

	flb->curr_device_array->objects[idx].hdr.ref_count = 1;
	return &flb->curr_device_array->objects[idx];
}

/**
 * iommu_preserve_device() - Preserve device state across live update
 * @domain: Associated IOMMU domain
 * @dev: Device to preserve
 * @dma_owner_token: Token to identify DMA owner of this device
 *
 * Return: 0 on success, or negative error code.
 */
int iommu_preserve_device(struct iommu_domain *domain,
			  struct device *dev, u64 dma_owner_token)
{
	struct iommu_device_ser *device_ser;
	struct iommu_flb_obj *flb_obj;
	struct dev_iommu *iommu;
	struct pci_dev *pdev;
	int ret;

	if (!dev_is_pci(dev))
		return -EOPNOTSUPP;

	if (!iommu_group_dma_owner_claimed(dev->iommu_group))
		return -EINVAL;

	pdev = to_pci_dev(dev);
	iommu = dev->iommu;
	if (!iommu->iommu_dev->ops->preserve_device ||
	    !iommu->iommu_dev->ops->unpreserve_device ||
	    !iommu->iommu_dev->ops->preserve ||
	    !iommu->iommu_dev->ops->unpreserve)
		return -EOPNOTSUPP;

	ret = liveupdate_flb_get_outgoing(&iommu_flb, (void **)&flb_obj);
	if (ret)
		return ret;

	mutex_lock(&flb_obj->lock);
	if (!domain->preserved_state) {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (dev_iommu_preserved_state(dev)) {
		ret = -EBUSY;
		goto out_unlock;
	}

	device_ser = alloc_iommu_device_ser(flb_obj);
	if (IS_ERR(device_ser)) {
		ret = PTR_ERR(device_ser);
		goto out_unlock;
	}

	ret = iommu_preserve_locked(iommu->iommu_dev, flb_obj);
	if (ret) {
		device_ser->hdr.flags |= IOMMU_SER_FLAG_DELETED;
		goto out_unlock;
	}

	device_ser->domain_iommu_ser.domain_phys = virt_to_phys(domain->preserved_state);
	device_ser->domain_iommu_ser.iommu_phys = virt_to_phys(iommu->iommu_dev->outgoing_preserved_state);
	device_ser->devid = pci_dev_id(pdev);
	device_ser->pci_domain_nr = pci_domain_nr(pdev->bus);
	device_ser->dma_owner_token = dma_owner_token;

	ret = iommu->iommu_dev->ops->preserve_device(dev, device_ser);
	if (!ret) {
		WRITE_ONCE(dev->iommu->device_ser, device_ser);

		/* Validate that no sibling device was added concurrently */
		if (!iommu_group_is_singleton(dev->iommu_group)) {
			iommu->iommu_dev->ops->unpreserve_device(dev, device_ser);
			WRITE_ONCE(dev->iommu->device_ser, NULL);
			ret = -EOPNOTSUPP;
		}
	}

	if (ret) {
		device_ser->hdr.flags |= IOMMU_SER_FLAG_DELETED;
		iommu_unpreserve_locked(iommu->iommu_dev, flb_obj);
		goto out_unlock;
	}

out_unlock:
	mutex_unlock(&flb_obj->lock);
	liveupdate_flb_put_outgoing(&iommu_flb);
	return ret;
}
EXPORT_SYMBOL_GPL(iommu_preserve_device);

/**
 * iommu_unpreserve_device() - Unpreserve device state
 * @domain: Associated IOMMU domain
 * @dev: Device to unpreserve
 */
void iommu_unpreserve_device(struct iommu_domain *domain, struct device *dev)
{
	struct iommu_device_ser *iommu_device_ser;
	struct iommu_flb_obj *flb_obj;
	struct dev_iommu *iommu;
	int ret;

	if (!dev_is_pci(dev))
		return;

	if (!iommu_group_dma_owner_claimed(dev->iommu_group))
		return;

	iommu = dev->iommu;
	if (WARN_ON(!iommu->iommu_dev->ops->unpreserve_device ||
		    !iommu->iommu_dev->ops->unpreserve))
		return;

	ret = liveupdate_flb_get_outgoing(&iommu_flb, (void **)&flb_obj);
	if (WARN_ON(ret))
		return;

	mutex_lock(&flb_obj->lock);
	iommu_device_ser = dev_iommu_preserved_state(dev);
	if (WARN_ON(!iommu_device_ser))
		goto out_unlock;

	iommu_device_ser->hdr.flags |= IOMMU_SER_FLAG_DELETED;
	iommu->iommu_dev->ops->unpreserve_device(dev, iommu_device_ser);
	WRITE_ONCE(dev->iommu->device_ser, NULL);

	iommu_unpreserve_locked(iommu->iommu_dev, flb_obj);
out_unlock:
	mutex_unlock(&flb_obj->lock);
	liveupdate_flb_put_outgoing(&iommu_flb);
}
EXPORT_SYMBOL_GPL(iommu_unpreserve_device);
