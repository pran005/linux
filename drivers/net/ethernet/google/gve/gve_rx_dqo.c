// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/* Google virtual Ethernet (gve) driver
 *
 * Copyright (C) 2015-2021 Google, Inc.
 */

#include "gve.h"
#include "gve_dqo.h"
#include "gve_adminq.h"
#include "gve_utils.h"
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <net/ip6_checksum.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/page_pool/helpers.h>
#include <net/page_pool/types.h>
#include <net/netdev_rx_queue.h>

void gve_free_page_dqo(struct gve_priv *priv, struct gve_rx_buf_state_dqo *bs,
		       bool free_page)
{
	if (free_page)
		gve_free_page(&priv->pdev->dev, bs->page_info.netmem, bs->addr,
			      DMA_FROM_DEVICE);
	bs->page_info.netmem = 0;
}

static struct gve_rx_buf_state_dqo *gve_alloc_buf_state(struct gve_rx_ring *rx)
{
	struct gve_rx_buf_state_dqo *buf_state;
	s16 buffer_id;

	buffer_id = rx->dqo.free_buf_states;
	if (unlikely(buffer_id == -1))
		return NULL;

	buf_state = &rx->dqo.buf_states[buffer_id];

	/* Remove buf_state from free list */
	rx->dqo.free_buf_states = buf_state->next;

	/* Point buf_state to itself to mark it as allocated */
	buf_state->next = buffer_id;

	return buf_state;
}

static bool gve_buf_state_is_allocated(struct gve_rx_ring *rx,
				       struct gve_rx_buf_state_dqo *buf_state)
{
	s16 buffer_id = buf_state - rx->dqo.buf_states;

	return buf_state->next == buffer_id;
}

static void gve_free_buf_state(struct gve_rx_ring *rx,
			       struct gve_rx_buf_state_dqo *buf_state)
{
	s16 buffer_id = buf_state - rx->dqo.buf_states;

	buf_state->next = rx->dqo.free_buf_states;
	rx->dqo.free_buf_states = buffer_id;
}

static int gve_alloc_page_dqo(struct gve_rx_ring *rx,
			      struct gve_rx_buf_state_dqo *buf_state)
{
	struct gve_priv *priv = rx->gve;
	u32 idx;

	if (!rx->dqo.qpl) {
		int err;

		err = gve_alloc_page(priv, &priv->pdev->dev,
				     &buf_state->page_info.netmem,
				     &buf_state->addr,
				     DMA_FROM_DEVICE,
				     GFP_ATOMIC,
				     rx);
		if (err)
			return err;
	} else {
		idx = rx->dqo.next_qpl_page_idx;
		if (idx >= priv->rx_pages_per_qpl) {
			net_err_ratelimited("%s: Out of QPL pages\n",
					    priv->dev->name);
			return -ENOMEM;
		}
		buf_state->page_info.netmem = page_to_netmem(rx->dqo.qpl->pages[idx]);
		buf_state->addr = rx->dqo.qpl->page_buses[idx];
		rx->dqo.next_qpl_page_idx++;
	}
	buf_state->addr = page_pool_get_dma_addr_netmem(buf_state->page_info.netmem);
	buf_state->page_info.page_offset = 0;
	buf_state->page_info.page_address =
		netmem_address(buf_state->page_info.netmem);
	buf_state->last_single_ref_offset = 0;

	buf_state->page_info.pagecnt_bias = 1;

	return 0;
}

static void gve_rx_free_hdr_bufs(struct gve_priv *priv, struct gve_rx_ring *rx)
{
	struct device *hdev = &priv->pdev->dev;
	int buf_count = rx->dqo.bufq.mask + 1;

	if (rx->dqo.hdr_bufs.data) {
		dma_free_coherent(hdev, priv->header_buf_size * buf_count,
				  rx->dqo.hdr_bufs.data, rx->dqo.hdr_bufs.addr);
		rx->dqo.hdr_bufs.data = NULL;
	}
}

void gve_rx_stop_ring_dqo(struct gve_priv *priv, int idx)
{
	int ntfy_idx = gve_rx_idx_to_ntfy(priv, idx);

	if (!gve_rx_was_added_to_block(priv, idx))
		return;

	gve_remove_napi(priv, ntfy_idx);
	gve_rx_remove_from_block(priv, idx);
}

static void gve_rx_free_ring_dqo(struct gve_priv *priv, struct gve_rx_ring *rx,
				 struct gve_rx_alloc_rings_cfg *cfg)
{
	struct device *hdev = &priv->pdev->dev;
	size_t completion_queue_slots;
	size_t buffer_queue_slots;
	int idx = rx->q_num;
	size_t size;
	int i;

	completion_queue_slots = rx->dqo.complq.mask + 1;
	buffer_queue_slots = rx->dqo.bufq.mask + 1;

	if (rx->q_resources) {
		dma_free_coherent(hdev, sizeof(*rx->q_resources),
				  rx->q_resources, rx->q_resources_bus);
		rx->q_resources = NULL;
	}

	for (i = 0; i < rx->dqo.num_buf_states; i++) {
		struct gve_rx_buf_state_dqo *bs = &rx->dqo.buf_states[i];
		/* Only free page for RDA. QPL pages are freed in gve_main. */
		if (bs->page_info.netmem && bs->next == i)
			gve_free_page_dqo(priv, bs, !rx->dqo.qpl);
	}

	if (rx->dqo.qpl) {
		gve_unassign_qpl(cfg->qpl_cfg, rx->dqo.qpl->id);
		rx->dqo.qpl = NULL;
	}

	if (rx->dqo.bufq.desc_ring) {
		size = sizeof(rx->dqo.bufq.desc_ring[0]) * buffer_queue_slots;
		dma_free_coherent(hdev, size, rx->dqo.bufq.desc_ring,
				  rx->dqo.bufq.bus);
		rx->dqo.bufq.desc_ring = NULL;
	}

	if (rx->dqo.complq.desc_ring) {
		size = sizeof(rx->dqo.complq.desc_ring[0]) *
			completion_queue_slots;
		dma_free_coherent(hdev, size, rx->dqo.complq.desc_ring,
				  rx->dqo.complq.bus);
		rx->dqo.complq.desc_ring = NULL;
	}

	kvfree(rx->dqo.buf_states);
	rx->dqo.buf_states = NULL;

	gve_rx_free_hdr_bufs(priv, rx);

	if (rx->dqo.pp)
		page_pool_destroy(rx->dqo.pp);

	netif_dbg(priv, drv, priv->dev, "freed rx ring %d\n", idx);
}

static int gve_rx_alloc_hdr_bufs(struct gve_priv *priv, struct gve_rx_ring *rx)
{
	struct device *hdev = &priv->pdev->dev;
	int buf_count = rx->dqo.bufq.mask + 1;

	rx->dqo.hdr_bufs.data = dma_alloc_coherent(hdev, priv->header_buf_size * buf_count,
						   &rx->dqo.hdr_bufs.addr, GFP_KERNEL);
	if (!rx->dqo.hdr_bufs.data)
		return -ENOMEM;

	return 0;
}

void gve_rx_start_ring_dqo(struct gve_priv *priv, int idx)
{
	int ntfy_idx = gve_rx_idx_to_ntfy(priv, idx);

	gve_rx_add_to_block(priv, idx);
	gve_add_napi(priv, ntfy_idx, gve_napi_poll_dqo);
}

static int gve_rx_alloc_ring_dqo(struct gve_priv *priv,
				 struct gve_rx_alloc_rings_cfg *cfg,
				 struct gve_rx_ring *rx,
				 int idx)
{
	struct page_pool_params pp_params = { 0 };
	// TODO is this rx ring important
	// struct gve_rx_ring *rx = &priv->rx[idx];
	struct device *hdev = &priv->pdev->dev;
	size_t size;
	int i;

	const u32 buffer_queue_slots = cfg->raw_addressing ?
		priv->options_dqo_rda.rx_buff_ring_entries : cfg->ring_size;
	const u32 completion_queue_slots = cfg->ring_size;

	netif_dbg(priv, drv, priv->dev, "allocating rx ring DQO\n");

	memset(rx, 0, sizeof(*rx));
	rx->gve = priv;
	rx->q_num = idx;
	rx->dqo.bufq.mask = buffer_queue_slots - 1;
	rx->dqo.complq.num_free_slots = completion_queue_slots;
	rx->dqo.complq.mask = completion_queue_slots - 1;
	rx->ctx.skb_head = NULL;
	rx->ctx.skb_tail = NULL;

	rx->dqo.num_buf_states = cfg->raw_addressing ?
		min_t(s16, S16_MAX, buffer_queue_slots * 8) :
		priv->rx_pages_per_qpl;
	rx->dqo.buf_states = kvcalloc(rx->dqo.num_buf_states,
				      sizeof(rx->dqo.buf_states[0]),
				      GFP_KERNEL);
	if (!rx->dqo.buf_states)
		return -ENOMEM;

	/* Allocate header buffers for header-split */
	if (cfg->enable_header_split)
		if (gve_rx_alloc_hdr_bufs(priv, rx))
			goto err;

	/* Create a page_pool and register it with rxq */
	pp_params.order			= 0;
	pp_params.pool_size		= rx->dqo.num_buf_states;
	pp_params.nid			= NUMA_NO_NODE;
	pp_params.dev			= &priv->pdev->dev;
	pp_params.netdev		= priv->dev;
	pp_params.flags			= PP_FLAG_DMA_MAP;
	pp_params.dma_dir		= DMA_FROM_DEVICE;
	pp_params.queue = __netif_get_rx_queue(priv->dev, rx->q_num);

	rx->dqo.pp = page_pool_create(&pp_params);
	if (IS_ERR(rx->dqo.pp))
		BUG();

	/* Set up linked list of buffer IDs */
	for (i = 0; i < rx->dqo.num_buf_states - 1; i++)
		rx->dqo.buf_states[i].next = i + 1;

	rx->dqo.buf_states[rx->dqo.num_buf_states - 1].next = -1;
	rx->dqo.recycled_buf_states.head = -1;
	rx->dqo.recycled_buf_states.tail = -1;
	rx->dqo.used_buf_states.head = -1;
	rx->dqo.used_buf_states.tail = -1;

	/* Allocate RX completion queue */
	size = sizeof(rx->dqo.complq.desc_ring[0]) *
		completion_queue_slots;
	rx->dqo.complq.desc_ring =
		dma_alloc_coherent(hdev, size, &rx->dqo.complq.bus, GFP_KERNEL);
	if (!rx->dqo.complq.desc_ring)
		goto err;

	/* Allocate RX buffer queue */
	size = sizeof(rx->dqo.bufq.desc_ring[0]) * buffer_queue_slots;
	rx->dqo.bufq.desc_ring =
		dma_alloc_coherent(hdev, size, &rx->dqo.bufq.bus, GFP_KERNEL);
	if (!rx->dqo.bufq.desc_ring)
		goto err;

	if (!cfg->raw_addressing) {
		rx->dqo.qpl = gve_assign_rx_qpl(cfg, rx->q_num);
		if (!rx->dqo.qpl)
			goto err;
		rx->dqo.next_qpl_page_idx = 0;
	}

	rx->q_resources = dma_alloc_coherent(hdev, sizeof(*rx->q_resources),
					     &rx->q_resources_bus, GFP_KERNEL);
	if (!rx->q_resources)
		goto err;

	return 0;

err:
	gve_rx_free_ring_dqo(priv, rx, cfg);
	return -ENOMEM;
}

void gve_rx_write_doorbell_dqo(const struct gve_priv *priv, int queue_idx)
{
	const struct gve_rx_ring *rx = &priv->rx[queue_idx];
	u64 index = be32_to_cpu(rx->q_resources->db_index);

	iowrite32(rx->dqo.bufq.tail, &priv->db_bar2[index]);
}

int gve_rx_alloc_rings_dqo(struct gve_priv *priv,
			   struct gve_rx_alloc_rings_cfg *cfg)
{
	struct gve_rx_ring *rx;
	int err;
	int i;

	if (!cfg->raw_addressing && !cfg->qpls) {
		netif_err(priv, drv, priv->dev,
			  "Cannot alloc QPL ring before allocing QPLs\n");
		return -EINVAL;
	}

	rx = kvcalloc(cfg->qcfg->max_queues, sizeof(struct gve_rx_ring),
		      GFP_KERNEL);
	if (!rx)
		return -ENOMEM;

	for (i = 0; i < cfg->qcfg->num_queues; i++) {
		err = gve_rx_alloc_ring_dqo(priv, cfg, &rx[i], i);
		if (err) {
			netif_err(priv, drv, priv->dev,
				  "Failed to alloc rx ring=%d: err=%d\n",
				  i, err);
			goto err;
		}
	}

	cfg->rx = rx;
	return 0;

err:
	for (i--; i >= 0; i--)
		gve_rx_free_ring_dqo(priv, &rx[i], cfg);
	kvfree(rx);
	return err;
}

void gve_rx_free_rings_dqo(struct gve_priv *priv,
			   struct gve_rx_alloc_rings_cfg *cfg)
{
	struct gve_rx_ring *rx = cfg->rx;
	int i;

	if (!rx)
		return;

	for (i = 0; i < cfg->qcfg->num_queues;  i++)
		gve_rx_free_ring_dqo(priv, &rx[i], cfg);

	kvfree(rx);
	cfg->rx = NULL;
}

void gve_rx_post_buffers_dqo(struct gve_rx_ring *rx)
{
	struct gve_rx_compl_queue_dqo *complq = &rx->dqo.complq;
	struct gve_rx_buf_queue_dqo *bufq = &rx->dqo.bufq;
	struct gve_priv *priv = rx->gve;
	u32 num_avail_slots;
	u32 num_full_slots;
	u32 num_posted = 0;

	num_full_slots = (bufq->tail - bufq->head) & bufq->mask;
	num_avail_slots = bufq->mask - num_full_slots;

	num_avail_slots = min_t(u32, num_avail_slots, complq->num_free_slots);
	while (num_posted < num_avail_slots) {
		struct gve_rx_desc_dqo *desc = &bufq->desc_ring[bufq->tail];
		struct gve_rx_buf_state_dqo *buf_state;

		buf_state = gve_alloc_buf_state(rx);
		if (unlikely(!buf_state))
			break;

		if (unlikely(gve_alloc_page_dqo(rx, buf_state))) {
			u64_stats_update_begin(&rx->statss);
			rx->rx_buf_alloc_fail++;
			u64_stats_update_end(&rx->statss);
			gve_free_buf_state(rx, buf_state);
			break;
		}

		desc->buf_id = cpu_to_le16(buf_state - rx->dqo.buf_states);
		desc->buf_addr = cpu_to_le64(buf_state->addr +
					     buf_state->page_info.page_offset);
		if (rx->dqo.hdr_bufs.data)
			desc->header_buf_addr =
				cpu_to_le64(rx->dqo.hdr_bufs.addr +
					    priv->header_buf_size * bufq->tail);

		bufq->tail = (bufq->tail + 1) & bufq->mask;
		complq->num_free_slots--;
		num_posted++;

		if ((bufq->tail & (GVE_RX_BUF_THRESH_DQO - 1)) == 0)
			gve_rx_write_doorbell_dqo(priv, rx->q_num);
	}

	rx->fill_cnt += num_posted;
}

static void gve_rx_skb_csum(struct sk_buff *skb,
			    const struct gve_rx_compl_desc_dqo *desc,
			    struct gve_ptype ptype)
{
	skb->ip_summed = CHECKSUM_NONE;

	/* HW did not identify and process L3 and L4 headers. */
	if (unlikely(!desc->l3_l4_processed))
		return;

	if (ptype.l3_type == GVE_L3_TYPE_IPV4) {
		if (unlikely(desc->csum_ip_err || desc->csum_external_ip_err))
			return;
	} else if (ptype.l3_type == GVE_L3_TYPE_IPV6) {
		/* Checksum should be skipped if this flag is set. */
		if (unlikely(desc->ipv6_ex_add))
			return;
	}

	if (unlikely(desc->csum_l4_err))
		return;

	switch (ptype.l4_type) {
	case GVE_L4_TYPE_TCP:
	case GVE_L4_TYPE_UDP:
	case GVE_L4_TYPE_ICMP:
	case GVE_L4_TYPE_SCTP:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		break;
	default:
		break;
	}
}

static void gve_rx_skb_hash(struct sk_buff *skb,
			    const struct gve_rx_compl_desc_dqo *compl_desc,
			    struct gve_ptype ptype)
{
	enum pkt_hash_types hash_type = PKT_HASH_TYPE_L2;

	if (ptype.l4_type != GVE_L4_TYPE_UNKNOWN)
		hash_type = PKT_HASH_TYPE_L4;
	else if (ptype.l3_type != GVE_L3_TYPE_UNKNOWN)
		hash_type = PKT_HASH_TYPE_L3;

	skb_set_hash(skb, le32_to_cpu(compl_desc->hash), hash_type);
}

static void gve_rx_free_skb(struct gve_rx_ring *rx)
{
	if (!rx->ctx.skb_head)
		return;

	dev_kfree_skb_any(rx->ctx.skb_head);
	rx->ctx.skb_head = NULL;
	rx->ctx.skb_tail = NULL;
}

static bool gve_rx_should_trigger_copy_ondemand(struct gve_rx_ring *rx)
{
	if (!rx->dqo.qpl)
		return false;
	if (rx->dqo.used_buf_states_cnt <
		     (rx->dqo.num_buf_states -
		     GVE_DQO_QPL_ONDEMAND_ALLOC_THRESHOLD))
		return false;
	return true;
}

static int gve_rx_copy_ondemand(struct gve_rx_ring *rx,
				struct gve_rx_buf_state_dqo *buf_state,
				u16 buf_len)
{
	struct page *page = alloc_page(GFP_ATOMIC);
	int num_frags;

	if (!page)
		return -ENOMEM;

	memcpy(page_address(page),
	       buf_state->page_info.page_address +
	       buf_state->page_info.page_offset,
	       buf_len);
	num_frags = skb_shinfo(rx->ctx.skb_tail)->nr_frags;
	skb_add_rx_frag(rx->ctx.skb_tail, num_frags, page,
			0, buf_len, PAGE_SIZE);

	u64_stats_update_begin(&rx->statss);
	rx->rx_frag_alloc_cnt++;
	u64_stats_update_end(&rx->statss);
	gve_free_buf_state(rx, buf_state);
	return 0;
}

/* Chains multi skbs for single rx packet.
 * Returns 0 if buffer is appended, -1 otherwise.
 */
static int gve_rx_append_frags(struct napi_struct *napi,
			       struct gve_rx_buf_state_dqo *buf_state,
			       u16 buf_len, struct gve_rx_ring *rx,
			       struct gve_priv *priv)
{
	int num_frags = skb_shinfo(rx->ctx.skb_tail)->nr_frags;

	if (unlikely(num_frags == MAX_SKB_FRAGS)) {
		struct sk_buff *skb;

		skb = napi_alloc_skb(napi, 0);
		if (!skb)
			return -1;

		skb_mark_for_recycle(skb);

		if (rx->ctx.skb_tail == rx->ctx.skb_head)
			skb_shinfo(rx->ctx.skb_head)->frag_list = skb;
		else
			rx->ctx.skb_tail->next = skb;
		rx->ctx.skb_tail = skb;
		num_frags = 0;
	}
	if (rx->ctx.skb_tail != rx->ctx.skb_head) {
		rx->ctx.skb_head->len += buf_len;
		rx->ctx.skb_head->data_len += buf_len;
		rx->ctx.skb_head->truesize += priv->data_buffer_size_dqo;
	}

	/* Trigger ondemand page allocation if we are running low on buffers */
	if (gve_rx_should_trigger_copy_ondemand(rx))
		return gve_rx_copy_ondemand(rx, buf_state, buf_len);

	skb_add_rx_frag_netmem(rx->ctx.skb_tail, num_frags,
			buf_state->page_info.netmem,
			buf_state->page_info.page_offset,
			buf_len, priv->data_buffer_size_dqo);
	gve_dec_pagecnt_bias(&buf_state->page_info);

	gve_free_buf_state(rx, buf_state);
	return 0;
}

/* Returns 0 if descriptor is completed successfully.
 * Returns -EINVAL if descriptor is invalid.
 * Returns -ENOMEM if data cannot be copied to skb.
 */
static int gve_rx_dqo(struct napi_struct *napi, struct gve_rx_ring *rx,
		      const struct gve_rx_compl_desc_dqo *compl_desc,
		      u32 desc_idx, int queue_idx)
{
	const u16 buffer_id = le16_to_cpu(compl_desc->buf_id);
	const bool hbo = compl_desc->header_buffer_overflow;
	const bool eop = compl_desc->end_of_packet != 0;
	const bool hsplit = compl_desc->split_header;
	struct gve_rx_buf_state_dqo *buf_state;
	struct gve_priv *priv = rx->gve;
	u16 buf_len;
	u16 hdr_len;

	if (unlikely(buffer_id >= rx->dqo.num_buf_states)) {
		net_err_ratelimited("%s: Invalid RX buffer_id=%u\n",
				    priv->dev->name, buffer_id);
		return -EINVAL;
	}
	buf_state = &rx->dqo.buf_states[buffer_id];
	if (unlikely(!gve_buf_state_is_allocated(rx, buf_state))) {
		net_err_ratelimited("%s: RX buffer_id is not allocated: %u\n",
				    priv->dev->name, buffer_id);
		return -EINVAL;
	}

	if (unlikely(compl_desc->rx_error)) {
		gve_free_buf_state(rx, buf_state);
		gve_free_page_dqo(priv, buf_state, true);
		return -EINVAL;
	}

	buf_len = compl_desc->packet_len;
	hdr_len = compl_desc->header_len;

	/* Page might have not been used for awhile and was likely last written
	 * by a different thread.
	 */
	if (!netmem_is_net_iov(buf_state->page_info.netmem))
		prefetch(netmem_to_page(buf_state->page_info.netmem));

	if (!hsplit && !rx->ctx.skb_head &&
	    netmem_is_net_iov(buf_state->page_info.netmem)) {
		/* !hsplit indicates the packet is not split, and the header went
		 * to the packet buffer. If the packet buffer is a dma_buf
		 * page, those can't be easily mapped into the kernel space to
		 * access the header required to process the packet.
		 *
		 * In the future we may be able to map the dma_buf page to
		 * kernel space to access the header for dma_buf providers that
		 * support that, but for now, simply drop the packet. We expect
		 * the TCP packets that we care about to be header split
		 * anyway.
		 */
		rx->rx_devmem_dropped++;

		gve_free_buf_state(rx, buf_state);
		gve_free_page_dqo(priv, buf_state, true);
		return -EFAULT;
	}

	/* Copy the header into the skb in the case of header split */
	if (hsplit) {
		int unsplit = 0;

		if (hdr_len && !hbo) {
			rx->ctx.skb_head = gve_rx_copy_data(priv->dev, napi,
							    rx->dqo.hdr_bufs.data +
							    desc_idx * priv->header_buf_size,
							    hdr_len);
			if (unlikely(!rx->ctx.skb_head))
				goto error;
			rx->ctx.skb_tail = rx->ctx.skb_head;
		} else {
			unsplit = 1;
		}

		skb_mark_for_recycle(rx->ctx.skb_head);

		u64_stats_update_begin(&rx->statss);
		rx->rx_hsplit_pkt++;
		rx->rx_hsplit_unsplit_pkt += unsplit;
		rx->rx_hsplit_bytes += hdr_len;
		u64_stats_update_end(&rx->statss);
	}

	/* Sync the portion of dma buffer for CPU to read. */
	dma_sync_single_range_for_cpu(&priv->pdev->dev, buf_state->addr,
				      buf_state->page_info.page_offset,
				      buf_len, DMA_FROM_DEVICE);

	/* Append to current skb if one exists. */
	if (rx->ctx.skb_head) {
		if (unlikely(gve_rx_append_frags(napi, buf_state, buf_len, rx,
						 priv)) != 0) {
			goto error;
		}
		return 0;
	}

	/* We can't copy dma-buf pages. Ignore any copybreak setting. */
	if (eop && buf_len <= priv->rx_copybreak &&
	    (!netmem_is_net_iov(buf_state->page_info.netmem) || !buf_len)) {
		rx->ctx.skb_head = gve_rx_copy(priv->dev, napi,
					       &buf_state->page_info, buf_len);
		if (unlikely(!rx->ctx.skb_head))
			goto error;
		rx->ctx.skb_tail = rx->ctx.skb_head;

		skb_mark_for_recycle(rx->ctx.skb_head);

		u64_stats_update_begin(&rx->statss);
		rx->rx_copied_pkt++;
		rx->rx_copybreak_pkt++;
		u64_stats_update_end(&rx->statss);

		gve_free_buf_state(rx, buf_state);
		gve_free_page_dqo(priv, buf_state, true);
		return 0;
	}

	rx->ctx.skb_head = napi_get_frags(napi);
	if (unlikely(!rx->ctx.skb_head))
		goto error;
	rx->ctx.skb_tail = rx->ctx.skb_head;

	skb_mark_for_recycle(rx->ctx.skb_head);

	if (gve_rx_should_trigger_copy_ondemand(rx)) {
		if (gve_rx_copy_ondemand(rx, buf_state, buf_len) < 0)
			goto error;
		return 0;
	}

	skb_add_rx_frag_netmem(rx->ctx.skb_head, 0, buf_state->page_info.netmem,
			buf_state->page_info.page_offset, buf_len,
			priv->data_buffer_size_dqo);
	gve_dec_pagecnt_bias(&buf_state->page_info);

	gve_free_buf_state(rx, buf_state);
	return 0;

error:
	gve_free_buf_state(rx, buf_state);
	gve_free_page_dqo(priv, buf_state, true);
	return -ENOMEM;
}

static int gve_rx_complete_rsc(struct sk_buff *skb,
			       const struct gve_rx_compl_desc_dqo *desc,
			       struct gve_ptype ptype)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);

	/* Only TCP is supported right now. */
	if (ptype.l4_type != GVE_L4_TYPE_TCP)
		return -EINVAL;

	switch (ptype.l3_type) {
	case GVE_L3_TYPE_IPV4:
		shinfo->gso_type = SKB_GSO_TCPV4;
		break;
	case GVE_L3_TYPE_IPV6:
		shinfo->gso_type = SKB_GSO_TCPV6;
		break;
	default:
		return -EINVAL;
	}

	shinfo->gso_size = le16_to_cpu(desc->rsc_seg_len);
	return 0;
}

/* Returns 0 if skb is completed successfully, -1 otherwise. */
static int gve_rx_complete_skb(struct gve_rx_ring *rx, struct napi_struct *napi,
			       const struct gve_rx_compl_desc_dqo *desc,
			       netdev_features_t feat)
{
	struct gve_ptype ptype =
		rx->gve->ptype_lut_dqo->ptypes[desc->packet_type];
	int err;

	skb_record_rx_queue(rx->ctx.skb_head, rx->q_num);

	if (feat & NETIF_F_RXHASH)
		gve_rx_skb_hash(rx->ctx.skb_head, desc, ptype);

	if (feat & NETIF_F_RXCSUM)
		gve_rx_skb_csum(rx->ctx.skb_head, desc, ptype);

	/* RSC packets must set gso_size otherwise the TCP stack will complain
	 * that packets are larger than MTU.
	 */
	if (desc->rsc) {
		err = gve_rx_complete_rsc(rx->ctx.skb_head, desc, ptype);
		if (err < 0)
			return err;
	}

	if (skb_headlen(rx->ctx.skb_head) == 0) {
		if (!napi_get_frags(napi)->readable)
			rx->rx_devmem_pkt++;
		napi_gro_frags(napi);
	} else {
		if (!rx->ctx.skb_head->readable)
			rx->rx_devmem_pkt++;
		napi_gro_receive(napi, rx->ctx.skb_head);
	}

	return 0;
}

int gve_rx_poll_dqo(struct gve_notify_block *block, int budget)
{
	struct napi_struct *napi = &block->napi;
	netdev_features_t feat = napi->dev->features;

	struct gve_rx_ring *rx = block->rx;
	struct gve_rx_compl_queue_dqo *complq = &rx->dqo.complq;

	u32 work_done = 0;
	u64 bytes = 0;
	int err;

	while (work_done < budget) {
		struct gve_rx_compl_desc_dqo *compl_desc =
			&complq->desc_ring[complq->head];
		u32 pkt_bytes;

		/* No more new packets */
		if (compl_desc->generation == complq->cur_gen_bit)
			break;

		/* Prefetch the next two descriptors. */
		prefetch(&complq->desc_ring[(complq->head + 1) & complq->mask]);
		prefetch(&complq->desc_ring[(complq->head + 2) & complq->mask]);

		/* Do not read data until we own the descriptor */
		dma_rmb();

		err = gve_rx_dqo(napi, rx, compl_desc, complq->head, rx->q_num);
		if (err < 0) {
			gve_rx_free_skb(rx);
			u64_stats_update_begin(&rx->statss);
			if (err == -ENOMEM)
				rx->rx_skb_alloc_fail++;
			else if (err == -EINVAL)
				rx->rx_desc_err_dropped_pkt++;
			u64_stats_update_end(&rx->statss);
		}

		complq->head = (complq->head + 1) & complq->mask;
		complq->num_free_slots++;

		/* When the ring wraps, the generation bit is flipped. */
		complq->cur_gen_bit ^= (complq->head == 0);

		/* Receiving a completion means we have space to post another
		 * buffer on the buffer queue.
		 */
		{
			struct gve_rx_buf_queue_dqo *bufq = &rx->dqo.bufq;

			bufq->head = (bufq->head + 1) & bufq->mask;
		}

		/* Free running counter of completed descriptors */
		rx->cnt++;

		if (!rx->ctx.skb_head)
			continue;

		if (!compl_desc->end_of_packet)
			continue;

		work_done++;
		pkt_bytes = rx->ctx.skb_head->len;
		/* The ethernet header (first ETH_HLEN bytes) is snipped off
		 * by eth_type_trans.
		 */
		if (skb_headlen(rx->ctx.skb_head))
			pkt_bytes += ETH_HLEN;

		/* gve_rx_complete_skb() will consume skb if successful */
		if (gve_rx_complete_skb(rx, napi, compl_desc, feat) != 0) {
			gve_rx_free_skb(rx);
			u64_stats_update_begin(&rx->statss);
			rx->rx_desc_err_dropped_pkt++;
			u64_stats_update_end(&rx->statss);
			continue;
		}

		bytes += pkt_bytes;
		rx->ctx.skb_head = NULL;
		rx->ctx.skb_tail = NULL;
	}

	gve_rx_post_buffers_dqo(rx);

	u64_stats_update_begin(&rx->statss);
	rx->rpackets += work_done;
	rx->rbytes += bytes;
	u64_stats_update_end(&rx->statss);

	return work_done;
}
