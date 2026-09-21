/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2026, Google LLC
 * Author: Samiullah Khawaja <skhawaja@google.com>
 */

#ifndef _LINUX_IOMMU_LIVEUPDATE_H
#define _LINUX_IOMMU_LIVEUPDATE_H

#include <linux/device.h>
#include <linux/iommu.h>
#include <linux/liveupdate.h>
#include <linux/kho/abi/iommu.h>

#ifdef CONFIG_IOMMU_LIVEUPDATE
int iommu_liveupdate_register_flb(struct liveupdate_file_handler *handler);
void iommu_liveupdate_unregister_flb(struct liveupdate_file_handler *handler);

/**
 * dev_iommu_preserved_state() - Get preserved state of a device
 * @dev: Target device
 *
 * Return: Pointer to preserved device state, or NULL if not preserved.
 */
static inline void *dev_iommu_preserved_state(struct device *dev)
{
	struct iommu_device_ser *ser;

	if (!dev->iommu)
		return NULL;

	ser = READ_ONCE(dev->iommu->device_ser);
	if (ser && !(ser->hdr.flags & IOMMU_SER_FLAG_INCOMING))
		return ser;

	return NULL;
}

int iommu_preserve_domain(struct iommu_domain *domain, struct iommu_domain_ser **ser);
void iommu_unpreserve_domain(struct iommu_domain *domain);
int iommu_preserve_device(struct iommu_domain *domain,
			  struct device *dev, u64 dma_owner_token);
void iommu_unpreserve_device(struct iommu_domain *domain, struct device *dev);

/**
 * iommu_preserved_state() - Get preserved state of an IOMMU instance
 * @iommu: IOMMU hardware instance
 *
 * Return: Pointer to preserved state, or NULL if not preserved.
 */
static inline void *iommu_preserved_state(struct iommu_device *iommu)
{
	return iommu->outgoing_preserved_state;
}
#else
static inline int iommu_liveupdate_register_flb(struct liveupdate_file_handler *handler)
{
	return 0;
}

static inline void iommu_liveupdate_unregister_flb(struct liveupdate_file_handler *handler)
{
}

static inline void *dev_iommu_preserved_state(struct device *dev)
{
	return NULL;
}

static inline int iommu_preserve_domain(struct iommu_domain *domain, struct iommu_domain_ser **ser)
{
	return -EOPNOTSUPP;
}

static inline void iommu_unpreserve_domain(struct iommu_domain *domain)
{
}

static inline int iommu_preserve_device(struct iommu_domain *domain,
					struct device *dev, u64 dma_owner_token)
{
	return -EOPNOTSUPP;
}

static inline void iommu_unpreserve_device(struct iommu_domain *domain, struct device *dev)
{
}

static inline void *iommu_preserved_state(struct iommu_device *iommu)
{
	return NULL;
}
#endif
#endif /* _LINUX_IOMMU_LIVEUPDATE_H */
