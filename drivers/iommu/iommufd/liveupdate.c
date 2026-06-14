// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2026, Google LLC
 * Author: Samiullah Khawaja <skhawaja@google.com>
 */

#define pr_fmt(fmt) "iommufd: " fmt

#include <linux/file.h>
#include <linux/iommufd.h>
#include <linux/liveupdate.h>

#include "iommufd_private.h"

int iommufd_hwpt_liveupdate_mark_preserve(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_liveupdate_mark_preserve *cmd = ucmd->cmd;
	struct iommufd_hwpt_paging *hwpt_target;
	struct iommufd_hwpt_paging *hwpt_paging;
	struct iommufd_ctx *ictx = ucmd->ictx;
	struct iommufd_object *obj;
	unsigned long index;
	int rc = 0;

	hwpt_target = iommufd_get_hwpt_paging(ucmd, cmd->hwpt_id);
	if (IS_ERR(hwpt_target))
		return PTR_ERR(hwpt_target);

	mutex_lock(&ictx->liveupdate_mutex);

	xa_lock(&ictx->objects);
	xa_for_each_marked(&ictx->objects, index, obj, IOMMUFD_OBJ_LIVEUPDATE_MARK) {
		if (WARN_ON_ONCE(obj->type != IOMMUFD_OBJ_HWPT_PAGING))
			continue;

		hwpt_paging = to_hwpt_paging(container_of(obj, struct iommufd_hw_pagetable, obj));
		if (hwpt_paging->liveupdate_token == cmd->hwpt_token) {
			rc = -EADDRINUSE;
			goto out_unlock;
		}
	}

	__xa_set_mark(&ictx->objects, hwpt_target->common.obj.id, IOMMUFD_OBJ_LIVEUPDATE_MARK);

	if (hwpt_target->liveupdate_token != 0)
		pr_warn_ratelimited("Overwriting HWPT liveupdate token from: %llu to %llu\n",
				    hwpt_target->liveupdate_token, cmd->hwpt_token);
	hwpt_target->liveupdate_token = cmd->hwpt_token;

out_unlock:
	xa_unlock(&ictx->objects);
	mutex_unlock(&ictx->liveupdate_mutex);
	iommufd_put_object(ictx, &hwpt_target->common.obj);
	return rc;
}
