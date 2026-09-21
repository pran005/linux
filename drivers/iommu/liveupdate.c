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
#include <linux/iommu-liveupdate.h>
#include <linux/iommu.h>
#include <linux/kexec_handover.h>
#include <linux/liveupdate.h>

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
