/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2026, Google LLC
 * Author: Samiullah Khawaja <skhawaja@google.com>
 */

#ifndef _LINUX_IOMMU_LIVEUPDATE_H
#define _LINUX_IOMMU_LIVEUPDATE_H

#include <linux/iommu.h>
#include <linux/liveupdate.h>
#include <linux/kho/abi/iommu.h>

#ifdef CONFIG_IOMMU_LIVEUPDATE
int iommu_liveupdate_register_flb(struct liveupdate_file_handler *handler);
void iommu_liveupdate_unregister_flb(struct liveupdate_file_handler *handler);
#else
static inline int iommu_liveupdate_register_flb(struct liveupdate_file_handler *handler)
{
	return 0;
}

static inline void iommu_liveupdate_unregister_flb(struct liveupdate_file_handler *handler)
{
}
#endif
#endif /* _LINUX_IOMMU_LIVEUPDATE_H */
