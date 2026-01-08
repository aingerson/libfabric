/*
 * Copyright (c) 2015-2018 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "rxd.h"
#include <inttypes.h>


static int rxd_tree_compare(struct ofi_rbmap *map, void *key, void *data)
{
	struct rxd_av *av;
	uint8_t addr[RXD_NAME_LENGTH];
	size_t len = RXD_NAME_LENGTH;
	struct rxd_peer *peer;
	int ret;

	memset(addr, 0, len);
	av = container_of(map, struct rxd_av, rbmap);

	peer = ofi_bufpool_get_ibuf(av->peers, (size_t) data);

	ret = fi_av_lookup(av->dg_av, peer->dg_addr, addr, &len);
	if (ret)
		return -1;

	return memcmp(key, addr, len);
}

/*
 * The RXD code is agnostic wrt the datagram address format, but we need
 * to know the size of the address in order to iterate over them.  Because
 * the datagram AV may be configured for asynchronous operation, open a
 * temporary one to insert/lookup the address to get the size.  I agree it's
 * goofy.
 */
static int rxd_av_set_addrlen(struct rxd_av *av, const void *addr)
{
	struct rxd_domain *domain;
	struct fid_av *tmp_av;
	struct fi_av_attr attr;
	uint8_t tmp_addr[RXD_NAME_LENGTH];
	fi_addr_t fiaddr;
	size_t len;
	int ret;

	FI_INFO(&rxd_prov, FI_LOG_AV, "determine dgram address len\n");
	memset(&attr, 0, sizeof attr);
	attr.count = 1;

	domain = container_of(av->util_av.domain, struct rxd_domain, util_domain);
	ret = fi_av_open(domain->dg_domain, &attr, &tmp_av, NULL);
	if (ret) {
		FI_WARN(&rxd_prov, FI_LOG_AV, "failed to open av: %d (%s)\n",
			-ret, fi_strerror(-ret));
		return ret;
	}

	ret = fi_av_insert(tmp_av, addr, 1, &fiaddr, 0, NULL);
	if (ret != 1) {
		FI_WARN(&rxd_prov, FI_LOG_AV, "addr insert failed: %d (%s)\n",
			-ret, fi_strerror(-ret));
		ret = -FI_EINVAL;
		goto close;
	}

	len = sizeof tmp_addr;
	ret = fi_av_lookup(tmp_av, fiaddr, tmp_addr, &len);
	if (ret) {
		FI_WARN(&rxd_prov, FI_LOG_AV, "addr lookup failed: %d (%s)\n",
			-ret, fi_strerror(-ret));
		goto close;
	}

	FI_INFO(&rxd_prov, FI_LOG_AV, "set dgram address len: %zu\n", len);
	av->dg_addrlen = len;
close:
	fi_close(&tmp_av->fid);
	return ret;
}

struct rxd_peer *rxd_insert_rxd_dg_addr(struct rxd_av *av, const void *addr)
{
	struct rxd_peer *peer;
	struct ofi_rbnode *node;
	int ret;

	peer = ofi_ibuf_alloc(av->peers);
	if (!peer)
		return NULL;

	peer->rxd_addr = (uint64_t) ofi_buf_index(peer);

	ret = fi_av_insert(av->dg_av, addr, 1, &peer->dg_addr, 0, NULL);
	if (ret != 1) {
		ofi_ibuf_free(peer);
		return NULL;
	}

	ofi_rbmap_insert(&av->rbmap, (void *) addr,
			 (void *) peer->rxd_addr, &node);

	return peer;
}

static int rxd_av_insert(struct fid_av *av_fid, const void *addr, size_t count,
			fi_addr_t *fi_addr, uint64_t flags, void *context)
{
	struct rxd_av *av;
	int i = 0, ret = 0, success_cnt = 0;
	int *sync_err = NULL;
	struct ofi_rbnode *node;
	struct rxd_peer *peer;

	av = container_of(av_fid, struct rxd_av, util_av.av_fid);
	ret = ofi_verify_av_insert(&av->util_av, flags, context);
	if (ret)
		return ret;

	if (flags & FI_SYNC_ERR) {
		sync_err = context;
		memset(sync_err, 0, sizeof(*sync_err) * count);
	}

	ofi_genlock_lock(&av->util_av.lock);
	if (!av->dg_addrlen) {
		ret = rxd_av_set_addrlen(av, addr);
		if (ret)
			goto out;
	}

	for (; i < count; i++, addr = (uint8_t *) addr + av->dg_addrlen) {
		node = ofi_rbmap_find(&av->rbmap, (void *) addr);
		if (node) {
			peer = ofi_bufpool_get_ibuf(av->peers, (uint64_t) node->data);
		} else {
			peer = rxd_insert_rxd_dg_addr(av, addr);
			if (!peer)
				break;
		}

		ret = ofi_av_insert_addr(&av->util_av, &peer->rxd_addr,
					 &peer->fi_addr);
		if (ret)
			break;

		if (fi_addr)
			fi_addr[i] = peer->fi_addr;

		success_cnt++;
	}

	if (ret) {
		FI_WARN(&rxd_prov, FI_LOG_AV,
			"failed to insert address %d: %d (%s)\n",
			i, -ret, fi_strerror(-ret));
		if (fi_addr)
			fi_addr[i] = FI_ADDR_NOTAVAIL;
		else if (sync_err)
			sync_err[i] = -ret;
		i++;
	}
out:
	av->dg_av_used += success_cnt;
	ofi_genlock_unlock(&av->util_av.lock);

	for (; i < count; i++) {
		if (fi_addr)
			fi_addr[i] = FI_ADDR_NOTAVAIL;
		else if (sync_err)
			sync_err[i] = FI_ECANCELED;
	}


	return success_cnt;
}

static int rxd_av_insertsvc(struct fid_av *av, const char *node,
			   const char *service, fi_addr_t *fi_addr,
			   uint64_t flags, void *context)
{
	return -FI_ENOSYS;
}

static int rxd_av_insertsym(struct fid_av *av_fid, const char *node, size_t nodecnt,
			   const char *service, size_t svccnt, fi_addr_t *fi_addr,
			   uint64_t flags, void *context)
{
	return -FI_ENOSYS;
}

static int rxd_av_remove(struct fid_av *av_fid, fi_addr_t *fi_addr, size_t count,
			uint64_t flags)
{
	int ret = 0;
	size_t i;
	uint64_t rxd_addr;
	struct rxd_av *av;
	struct rxd_peer *peer;

	av = container_of(av_fid, struct rxd_av, util_av.av_fid);
	ofi_genlock_lock(&av->util_av.lock);
	for (i = 0; i < count; i++) {
		rxd_addr = (uint64_t) ofi_av_get_addr(&av->util_av, fi_addr[i]);
		if (!rxd_addr) {
			ret = -FI_EINVAL;
			break;
		}

		peer = ofi_bufpool_get_ibuf(av->peers, rxd_addr);
		ret = ofi_av_remove_addr(&av->util_av, *fi_addr);
		if (ret) {
			FI_WARN(&rxd_prov, FI_LOG_AV,
				"Unable to remove address from AV\n");
			break;
		}
		peer->fi_addr = FI_ADDR_UNSPEC;
	}

	if (ret)
		FI_WARN(&rxd_prov, FI_LOG_AV, "Unable to remove address from AV\n");

	ofi_genlock_unlock(&av->util_av.lock);
	return ret;
}

static const char *rxd_av_straddr(struct fid_av *av, const void *addr,
				  char *buf, size_t *len)
{
	struct rxd_av *rxd_av;
	rxd_av = container_of(av, struct rxd_av, util_av.av_fid);
	return rxd_av->dg_av->ops->straddr(rxd_av->dg_av, addr, buf, len);
}

static int rxd_av_lookup(struct fid_av *av, fi_addr_t fi_addr, void *addr,
			 size_t *addrlen)
{
	struct rxd_av *rxd_av;
	uint64_t rxd_addr;
	struct rxd_peer *peer;

	rxd_av = container_of(av, struct rxd_av, util_av.av_fid);

	rxd_addr = (uint64_t) ofi_av_get_addr(&rxd_av->util_av, fi_addr);
	peer = ofi_bufpool_get_ibuf(rxd_av->peers, rxd_addr);

	return fi_av_lookup(rxd_av->dg_av, peer->dg_addr, addr, addrlen);
}

static struct fi_ops_av rxd_av_ops = {
	.size = sizeof(struct fi_ops_av),
	.insert = rxd_av_insert,
	.insertsvc = rxd_av_insertsvc,
	.insertsym = rxd_av_insertsym,
	.remove = rxd_av_remove,
	.lookup = rxd_av_lookup,
	.straddr = rxd_av_straddr,
};

static int rxd_av_close(struct fid *fid)
{
	struct rxd_av *av;
	struct ofi_rbnode *node;
	uint64_t rxd_addr;
	struct rxd_peer *peer;
	int ret;

	av = container_of(fid, struct rxd_av, util_av.av_fid);

	ret = ofi_av_close(&av->util_av);
	if (ret)
		return ret;

	while ((node = ofi_rbmap_get_root(&av->rbmap))) {
		rxd_addr = (uint64_t) node->data;
		peer = ofi_bufpool_get_ibuf(av->peers, rxd_addr);
		ret = fi_av_remove(av->dg_av, &peer->dg_addr, 1, 0);
		if (ret)
			FI_WARN(&rxd_prov, FI_LOG_AV,
				"failed to remove dg addr: %d (%s)\n",
				-ret, fi_strerror(-ret));

		ofi_ibuf_free(peer);
		ofi_rbmap_delete(&av->rbmap, node);
	}
	ofi_rbmap_cleanup(&av->rbmap);

	ret = fi_close(&av->dg_av->fid);
	if (ret)
		return ret;

	//Free reserved 0 entry
	ofi_ibuf_free(ofi_bufpool_get_ibuf(av->peers, 0));
	ofi_bufpool_destroy(av->peers);

	free(av);
	return 0;
}

static struct fi_ops rxd_av_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = rxd_av_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static void rxd_peer_init_fn(struct ofi_bufpool_region *region, void *buf)
{
	struct rxd_peer *peer = (struct rxd_peer *) buf;

	peer->dg_addr = FI_ADDR_UNSPEC;
	peer->fi_addr = FI_ADDR_UNSPEC;
}

int rxd_av_create(struct fid_domain *domain_fid, struct fi_av_attr *attr,
		   struct fid_av **av_fid, void *context)
{
	int ret;
	struct rxd_av *av;
	struct rxd_domain *domain;
	struct util_av_attr util_attr;
	struct fi_av_attr av_attr;
	struct ofi_bufpool_attr pool_attr = {0};

	if (!attr)
		return -FI_EINVAL;

	if (attr->name)
		return -FI_ENOSYS;

	//TODO implement dynamic AV sizing
	attr->count = roundup_power_of_two(attr->count ?
					   attr->count : rxd_env.max_peers);
	domain = container_of(domain_fid, struct rxd_domain, util_domain.domain_fid);
	av = calloc(1, sizeof(*av));
	if (!av)
		return -FI_ENOMEM;

	util_attr.addrlen = sizeof(uint64_t);
	util_attr.context_len = 0;
	util_attr.flags = 0;
	attr->type = domain->util_domain.av_type != FI_AV_UNSPEC ?
		     domain->util_domain.av_type : FI_AV_TABLE;

	ret = ofi_av_init(&domain->util_domain, attr, &util_attr,
			  &av->util_av, context);
	if (ret)
		goto err1;

	ofi_rbmap_init(&av->rbmap, rxd_tree_compare);

	av_attr = *attr;
	av_attr.count = 0;
	av_attr.flags = 0;
	ret = fi_av_open(domain->dg_domain, &av_attr, &av->dg_av, context);
	if (ret)
		goto err2;

	pool_attr.size = sizeof(struct rxd_peer);
	pool_attr.alignment = 16;
	pool_attr.max_cnt = 0;
	pool_attr.chunk_cnt = 16;
	pool_attr.flags = OFI_BUFPOOL_INDEXED | OFI_BUFPOOL_NO_TRACK;
	pool_attr.init_fn = &rxd_peer_init_fn;

	ret = ofi_bufpool_create_attr(&pool_attr, &av->peers);
	if (ret)
		goto err3;

	//Force allocation of entry 0 to reserve for NULL/ADDR_UNSPEC check
	(void) ofi_ibuf_alloc_at(av->peers, 0);

	av->util_av.av_fid.fid.ops = &rxd_av_fi_ops;
	av->util_av.av_fid.ops = &rxd_av_ops;
	*av_fid = &av->util_av.av_fid;
	return 0;

err3:
	(void) fi_close(&av->dg_av->fid);
err2:
	(void) ofi_av_close(&av->util_av);
err1:
	free(av);
	return ret;
}
