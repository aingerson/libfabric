/*
 * Copyright (c) 2021 Intel Corporation. All rights reserved.
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

#include "ofi_prov.h"
#include "ofi_iov.h"
#include "ofi_atomic.h"
#include "hook_prov.h"
#include "hook_ze.h"

static int hook_ze_iov_compare(struct ofi_rbmap *map, void *key, void *data)
{
	struct hook_ze_desc *desc = data;
	struct iovec *iov = key;

	if (ofi_iov_shifted_left(iov, &desc->iov))
		return -1;
	if (ofi_iov_shifted_right(iov, &desc->iov))
		return 1;

	return 0;
}

static int hook_ze_add_region(struct hook_ze_domain *domain,
				const struct iovec *iov, void **data)
{
	struct hook_ze_desc *desc;
	struct fi_mr_attr attr = {0};
	int ret = 0;

	desc = ofi_buf_alloc(domain->mr_pool);
	if (!desc)
		return -FI_ENOMEM;

	desc->iov = *iov;
	desc->iface = ze_is_addr_valid(iov->iov_base, &desc->device,
				       &desc->flags) ? FI_HMEM_ZE : FI_HMEM_SYSTEM;

	//TODO should we check for MR_LOCAL? or assume only HMEM? (same in delete)
	if (desc->iface == FI_HMEM_SYSTEM && !(domain->mr_mode & FI_MR_LOCAL)) {
		desc->desc = NULL;
		goto out;
	}

	//TODO figure out access and key?
	attr.mr_iov = iov;
	attr.iov_count = 1;
	attr.access = FI_SEND | FI_RECV | FI_READ | FI_WRITE |
		      FI_REMOTE_READ | FI_REMOTE_WRITE;
	attr.offset = 0;
	attr.requested_key = (uint64_t) desc;
	attr.iface = desc->iface;

	ret = fi_mr_regattr(domain->hook_domain.hdomain, &attr, desc->flags,
			    &desc->mr_fid);
	if (ret) {
		ofi_buf_free(desc);
		return ret;
	}

	desc->desc = fi_mr_desc(desc->mr_fid);
out:
	*data = desc;
	dlist_insert_tail(&desc->entry, &domain->mr_list);
	return 0;
}

static void hook_ze_delete_region(struct hook_ze_domain *domain,
				    struct hook_ze_desc *desc)
{
	struct ofi_rbnode *node;

	node = ofi_rbmap_find(&domain->rbmap, (void *) &desc->iov);
	if (!node)
		return;

	ofi_rbmap_delete(&domain->rbmap, node);

	if (desc->iface == FI_HMEM_SYSTEM && !(domain->mr_mode & FI_MR_LOCAL))
		goto out;

	fi_close(&(desc->mr_fid)->fid);
out:
	ofi_buf_free(desc);
}

static int hook_ze_cache_mr(struct hook_ep *ep, const struct iovec *iov,
			      size_t count, void **desc)
{
	struct hook_ze_domain *domain;
	struct ofi_rbnode *node;
	struct iovec mr_iov;
	int ret, i;

	domain = container_of(ep->domain, struct hook_ze_domain, hook_domain);
	for (i = 0; i < count; i++) {
		mr_iov = iov[i];
		ret = ofi_rbmap_insert(&domain->rbmap, &mr_iov, &desc[i], &node);
		if (!ret) {
			ret = hook_ze_add_region(domain, &mr_iov, &node->data);
			if (ret) {
				ofi_rbmap_delete(&domain->rbmap, node);
				return ret;
			}
		} else if (ret != -FI_EALREADY) {
			return ret;
		}
		desc[i] = ((struct hook_ze_desc *) (node->data))->desc;
	}
	return 0;
}

/*
 * atomic ops
 */

static ssize_t hook_ze_atomic_write(struct fid_ep *ep,
		const void *buf, size_t count, void *desc,
		fi_addr_t dest_addr, uint64_t addr, uint64_t key,
		enum fi_datatype datatype, enum fi_op op, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc;
	struct iovec iov;
	int ret;

	iov.iov_base = (void *) buf;
	iov.iov_len = count * ofi_datatype_size(datatype);

	ret = hook_ze_cache_mr(myep, &iov, 1, &hook_desc);
	if (ret)
		return ret;

	return fi_atomic(myep->hep, buf, count, hook_desc, dest_addr,
			 addr, key, datatype, op, context);
}

static ssize_t hook_ze_atomic_writev(struct fid_ep *ep,
		const struct fi_ioc *ioc, void **desc, size_t count,
		fi_addr_t dest_addr, uint64_t addr, uint64_t key,
		enum fi_datatype datatype, enum fi_op op, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	struct iovec iov[HOOK_ZE_IOV_LIMIT];
	int ret;

	ofi_ioc_to_iov(ioc, iov, count, ofi_datatype_size(datatype));
	ret = hook_ze_cache_mr(myep, iov, count, hook_desc);
	if (ret)
		return ret;

	return fi_atomicv(myep->hep, ioc, hook_desc, count, dest_addr,
			  addr, key, datatype, op, context);
}

//TODO duplicate and change const iov/msg

static ssize_t hook_ze_atomic_writemsg(struct fid_ep *ep,
		const struct fi_msg_atomic *msg, uint64_t flags)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	struct iovec iov[HOOK_ZE_IOV_LIMIT];
	struct fi_msg_atomic mymsg = *msg;
	int ret;

	ofi_ioc_to_iov(msg->msg_iov, iov, msg->iov_count,
		       ofi_datatype_size(msg->datatype));
	ret = hook_ze_cache_mr(myep, iov, msg->iov_count, hook_desc);
	if (ret)
		return ret;

	mymsg.desc = hook_desc;
	return fi_atomicmsg(myep->hep, &mymsg, flags);
}

static ssize_t hook_ze_atomic_inject(struct fid_ep *ep,
		const void *buf, size_t count,
		fi_addr_t dest_addr, uint64_t addr, uint64_t key,
		enum fi_datatype datatype, enum fi_op op)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);

	return fi_inject_atomic(myep->hep, buf, count, dest_addr,
				addr, key, datatype, op);
}

static ssize_t hook_ze_atomic_readwrite(struct fid_ep *ep,
		const void *buf, size_t count, void *desc,
		void *result, void *result_desc,
		fi_addr_t dest_addr, uint64_t addr, uint64_t key,
		enum fi_datatype datatype, enum fi_op op, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc, *hook_desc_res;
	struct iovec iov;
	int ret;

	iov.iov_base = (void *) buf;
	iov.iov_len = count * ofi_datatype_size(datatype);
	ret = hook_ze_cache_mr(myep, &iov, 1, &hook_desc);
	if (ret)
		return ret;

	iov.iov_base = result;
	ret = hook_ze_cache_mr(myep, &iov, 1, &hook_desc_res);
	if (ret)
		return ret;

	return fi_fetch_atomic(myep->hep, buf, count, &hook_desc,
			       result, &hook_desc_res, dest_addr,
			       addr, key, datatype, op, context);
}

static ssize_t hook_ze_atomic_readwritev(struct fid_ep *ep,
		const struct fi_ioc *ioc, void **desc, size_t count,
		struct fi_ioc *resultv, void **result_desc,
		size_t result_count, fi_addr_t dest_addr,
		uint64_t addr, uint64_t key, enum fi_datatype datatype,
		enum fi_op op, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	void *hook_desc_res[HOOK_ZE_IOV_LIMIT];
	struct iovec iov[HOOK_ZE_IOV_LIMIT];
	int ret;

	ofi_ioc_to_iov(ioc, iov, count, ofi_datatype_size(datatype));
	ret = hook_ze_cache_mr(myep, iov, count, hook_desc);
	if (ret)
		return ret;

	ofi_ioc_to_iov(resultv, iov, result_count, ofi_datatype_size(datatype));
	ret = hook_ze_cache_mr(myep, iov, result_count, hook_desc_res);
	if (ret)
		return ret;

	return fi_fetch_atomicv(myep->hep, ioc, hook_desc, count,
				resultv, hook_desc_res, result_count,
				dest_addr, addr, key, datatype, op, context);
}

static ssize_t hook_ze_atomic_readwritemsg(struct fid_ep *ep,
		const struct fi_msg_atomic *msg,
		struct fi_ioc *resultv, void **result_desc,
		size_t result_count, uint64_t flags)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	void *hook_desc_res[HOOK_ZE_IOV_LIMIT];
	struct iovec iov[HOOK_ZE_IOV_LIMIT];
	struct fi_msg_atomic mymsg = *msg;
	int ret;

	ofi_ioc_to_iov(msg->msg_iov, iov, msg->iov_count,
		       ofi_datatype_size(msg->datatype));
	ret = hook_ze_cache_mr(myep, iov, msg->iov_count, hook_desc);
	if (ret)
		return ret;

	ofi_ioc_to_iov(resultv, iov, result_count,
		       ofi_datatype_size(msg->datatype));
	ret = hook_ze_cache_mr(myep, iov, result_count, hook_desc_res);
	if (ret)
		return ret;

	mymsg.desc = hook_desc;
	return fi_fetch_atomicmsg(myep->hep, &mymsg, resultv, hook_desc_res,
				  result_count, flags);
}

static ssize_t hook_ze_atomic_compwrite(struct fid_ep *ep,
		const void *buf, size_t count, void *desc,
		const void *compare, void *compare_desc,
		void *result, void *result_desc,
		fi_addr_t dest_addr, uint64_t addr, uint64_t key,
		enum fi_datatype datatype, enum fi_op op, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc, *hook_desc_comp, *hook_desc_res;
	struct iovec iov;
	int ret;

	iov.iov_len = count * ofi_datatype_size(datatype);

	iov.iov_base = (void *) buf;
	ret = hook_ze_cache_mr(myep, &iov, 1, &hook_desc);
	if (ret)
		return ret;

	iov.iov_base = (void *) compare;
	ret = hook_ze_cache_mr(myep, &iov, 1, &hook_desc_comp);
	if (ret)
		return ret;

	iov.iov_base = result;
	ret = hook_ze_cache_mr(myep, &iov, 1, &hook_desc_res);
	if (ret)
		return ret;

	return fi_compare_atomic(myep->hep, buf, count, hook_desc,
				 compare, hook_desc_comp, result, hook_desc_res,
				 dest_addr, addr, key, datatype, op, context);
}

static ssize_t hook_ze_atomic_compwritev(struct fid_ep *ep,
		const struct fi_ioc *ioc, void **desc, size_t count,
		const struct fi_ioc *comparev, void **compare_desc,
		size_t compare_count, struct fi_ioc *resultv,
		void **result_desc, size_t result_count,
		fi_addr_t dest_addr, uint64_t addr, uint64_t key,
		enum fi_datatype datatype, enum fi_op op, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	void *hook_desc_comp[HOOK_ZE_IOV_LIMIT];
	void *hook_desc_res[HOOK_ZE_IOV_LIMIT];
	struct iovec iov[HOOK_ZE_IOV_LIMIT];
	int ret;

	ofi_ioc_to_iov(ioc, iov, count, ofi_datatype_size(datatype));
	ret = hook_ze_cache_mr(myep, iov, count, hook_desc);
	if (ret)
		return ret;

	ofi_ioc_to_iov(comparev, iov, compare_count, ofi_datatype_size(datatype));
	ret = hook_ze_cache_mr(myep, iov, compare_count, hook_desc_comp);
	if (ret)
		return ret;

	ofi_ioc_to_iov(resultv, iov, result_count, ofi_datatype_size(datatype));
	ret = hook_ze_cache_mr(myep, iov, result_count, hook_desc_res);
	if (ret)
		return ret;

	return fi_compare_atomicv(myep->hep, ioc, desc, count,
				  comparev, hook_desc_comp, compare_count,
				  resultv, hook_desc_res, result_count, dest_addr,
				  addr, key, datatype, op, context);
}

static ssize_t hook_ze_atomic_compwritemsg(struct fid_ep *ep,
		const struct fi_msg_atomic *msg,
		const struct fi_ioc *comparev, void **compare_desc,
		size_t compare_count, struct fi_ioc *resultv,
		void **result_desc, size_t result_count,
		uint64_t flags)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	void *hook_desc_comp[HOOK_ZE_IOV_LIMIT];
	void *hook_desc_res[HOOK_ZE_IOV_LIMIT];
	struct iovec iov[HOOK_ZE_IOV_LIMIT];
	struct fi_msg_atomic mymsg = *msg;
	int ret;

	ofi_ioc_to_iov(msg->msg_iov, iov, msg->iov_count,
		       ofi_datatype_size(msg->datatype));
	ret = hook_ze_cache_mr(myep, iov, msg->iov_count, hook_desc);
	if (ret)
		return ret;

	ofi_ioc_to_iov(comparev, iov, compare_count,
		       ofi_datatype_size(msg->datatype));
	ret = hook_ze_cache_mr(myep, iov, compare_count, hook_desc_comp);
	if (ret)
		return ret;

	ofi_ioc_to_iov(resultv, iov, result_count,
		       ofi_datatype_size(msg->datatype));
	ret = hook_ze_cache_mr(myep, iov, result_count, hook_desc_res);
	if (ret)
		return ret;

	mymsg.desc = hook_desc;
	return fi_compare_atomicmsg(myep->hep, &mymsg,
				    comparev, hook_desc_comp, compare_count,
				    resultv, hook_desc_res, result_count, flags);
}

static int hook_ze_atomic_writevalid(struct fid_ep *ep,
		enum fi_datatype datatype, enum fi_op op, size_t *count)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);

	return fi_atomicvalid(myep->hep, datatype, op, count);
}

static int hook_ze_atomic_readwritevalid(struct fid_ep *ep,
		enum fi_datatype datatype, enum fi_op op, size_t *count)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);

	return fi_fetch_atomicvalid(myep->hep, datatype, op, count);
}

static int hook_ze_atomic_compwritevalid(struct fid_ep *ep,
		enum fi_datatype datatype, enum fi_op op, size_t *count)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);

	return fi_compare_atomicvalid(myep->hep, datatype, op, count);
}

struct fi_ops_atomic hook_ze_atomic_ops = {
	.size = sizeof(struct fi_ops_atomic),
	.write = hook_ze_atomic_write,
	.writev = hook_ze_atomic_writev,
	.writemsg = hook_ze_atomic_writemsg,
	.inject = hook_ze_atomic_inject,
	.readwrite = hook_ze_atomic_readwrite,
	.readwritev = hook_ze_atomic_readwritev,
	.readwritemsg = hook_ze_atomic_readwritemsg,
	.compwrite = hook_ze_atomic_compwrite,
	.compwritev = hook_ze_atomic_compwritev,
	.compwritemsg = hook_ze_atomic_compwritemsg,
	.writevalid = hook_ze_atomic_writevalid,
	.readwritevalid = hook_ze_atomic_readwritevalid,
	.compwritevalid = hook_ze_atomic_compwritevalid,
};


/*
 * non-tagged message ops
 */

static ssize_t hook_ze_msg_recv(struct fid_ep *ep, void *buf, size_t len,
		void *desc, fi_addr_t src_addr, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc;
	struct iovec iov;
	int ret;

	iov.iov_base = buf;
	iov.iov_len = len;
	ret = hook_ze_cache_mr(myep, &iov, 1, &hook_desc);
	if (ret)
		return ret;

	return fi_recv(myep->hep, buf, len, hook_desc, src_addr, context);
}

static ssize_t hook_ze_msg_recvv(struct fid_ep *ep, const struct iovec *iov,
		void **desc, size_t count, fi_addr_t src_addr, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	int ret;

	ret = hook_ze_cache_mr(myep, iov, count, hook_desc);
	if (ret)
		return ret;

	return fi_recvv(myep->hep, iov, hook_desc, count, src_addr, context);
}

static ssize_t hook_ze_msg_recvmsg(struct fid_ep *ep,
		const struct fi_msg *msg, uint64_t flags)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	struct fi_msg mymsg = *msg;
	int ret;

	ret = hook_ze_cache_mr(myep, msg->msg_iov, msg->iov_count, hook_desc);
	if (ret)
		return ret;

	mymsg.desc = hook_desc;
	return fi_recvmsg(myep->hep, &mymsg, flags);
}

static ssize_t hook_ze_msg_send(struct fid_ep *ep, const void *buf,
		size_t len, void *desc, fi_addr_t dest_addr, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc;
	struct iovec iov;
	int ret;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;
	ret = hook_ze_cache_mr(myep, &iov, 1, &hook_desc);
	if (ret)
		return ret;

	return fi_send(myep->hep, buf, len, hook_desc, dest_addr, context);
}

static ssize_t hook_ze_msg_sendv(struct fid_ep *ep, const struct iovec *iov,
		void **desc, size_t count, fi_addr_t dest_addr, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	int ret;

	ret = hook_ze_cache_mr(myep, iov, count, hook_desc);
	if (ret)
		return ret;

	return fi_sendv(myep->hep, iov, hook_desc, count, dest_addr, context);
}

static ssize_t hook_ze_msg_sendmsg(struct fid_ep *ep,
		const struct fi_msg *msg, uint64_t flags)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	struct fi_msg mymsg = *msg;
	int ret;

	ret = hook_ze_cache_mr(myep, msg->msg_iov, msg->iov_count, hook_desc);
	if (ret)
		return ret;

	mymsg.desc = hook_desc;
	return fi_sendmsg(myep->hep, &mymsg, flags);
}

static ssize_t hook_ze_msg_inject(struct fid_ep *ep, const void *buf,
		size_t len, fi_addr_t dest_addr)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);

	return fi_inject(myep->hep, buf, len, dest_addr);
}

static ssize_t hook_ze_msg_senddata(struct fid_ep *ep, const void *buf,
		size_t len, void *desc, uint64_t data, fi_addr_t dest_addr,
		void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc;
	struct iovec iov;
	int ret;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;
	ret = hook_ze_cache_mr(myep, &iov, 1, &hook_desc);
	if (ret)
		return ret;

	return fi_senddata(myep->hep, buf, len, hook_desc, data, dest_addr,
			   context);
}

static ssize_t hook_ze_msg_injectdata(struct fid_ep *ep, const void *buf,
		size_t len, uint64_t data, fi_addr_t dest_addr)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);

	return fi_injectdata(myep->hep, buf, len, data, dest_addr);
}

static struct fi_ops_msg hook_ze_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = hook_ze_msg_recv,
	.recvv = hook_ze_msg_recvv,
	.recvmsg = hook_ze_msg_recvmsg,
	.send = hook_ze_msg_send,
	.sendv = hook_ze_msg_sendv,
	.sendmsg = hook_ze_msg_sendmsg,
	.inject = hook_ze_msg_inject,
	.senddata = hook_ze_msg_senddata,
	.injectdata = hook_ze_msg_injectdata,
};


/*
 * rma ops
 */

static ssize_t hook_ze_rma_read(struct fid_ep *ep, void *buf, size_t len,
		void *desc, fi_addr_t src_addr, uint64_t addr, uint64_t key,
		void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc;
	struct iovec iov;
	int ret;

	iov.iov_base = buf;
	iov.iov_len = len;
	ret = hook_ze_cache_mr(myep, &iov, 1, &hook_desc);
	if (ret)
		return ret;

	return fi_read(myep->hep, buf, len, hook_desc, src_addr, addr,
		       key, context);
}

static ssize_t hook_ze_rma_readv(struct fid_ep *ep, const struct iovec *iov,
		void **desc, size_t count, fi_addr_t src_addr, uint64_t addr,
		uint64_t key, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	int ret;

	ret = hook_ze_cache_mr(myep, iov, count, hook_desc);
	if (ret)
		return ret;

	return fi_readv(myep->hep, iov, hook_desc, count, src_addr,
			addr, key, context);
}

static ssize_t hook_ze_rma_readmsg(struct fid_ep *ep,
		const struct fi_msg_rma *msg, uint64_t flags)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	struct fi_msg_rma mymsg = *msg;
	int ret;

	ret = hook_ze_cache_mr(myep, msg->msg_iov, msg->iov_count, hook_desc);
	if (ret)
		return ret;

	mymsg.desc = hook_desc;
	return fi_readmsg(myep->hep, &mymsg, flags);
}

static ssize_t hook_ze_rma_write(struct fid_ep *ep, const void *buf,
		size_t len, void *desc, fi_addr_t dest_addr, uint64_t addr,
		uint64_t key, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc;
	struct iovec iov;
	int ret;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;
	ret = hook_ze_cache_mr(myep, &iov, 1, &hook_desc);
	if (ret)
		return ret;

	return fi_write(myep->hep, buf, len, hook_desc, dest_addr,
			addr, key, context);
}

static ssize_t hook_ze_rma_writev(struct fid_ep *ep, const struct iovec *iov,
		void **desc, size_t count, fi_addr_t dest_addr, uint64_t addr,
		uint64_t key, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	int ret;

	ret = hook_ze_cache_mr(myep, iov, count, hook_desc);
	if (ret)
		return ret;

	return fi_writev(myep->hep, iov, hook_desc, count, dest_addr,
			 addr, key, context);
}

static ssize_t hook_ze_rma_writemsg(struct fid_ep *ep,
		const struct fi_msg_rma *msg, uint64_t flags)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	struct fi_msg_rma mymsg = *msg;
	int ret;

	ret = hook_ze_cache_mr(myep, msg->msg_iov, msg->iov_count, hook_desc);
	if (ret)
		return ret;

	mymsg.desc = hook_desc;
	return fi_writemsg(myep->hep, &mymsg, flags);
}

static ssize_t hook_ze_rma_inject(struct fid_ep *ep, const void *buf,
		size_t len, fi_addr_t dest_addr, uint64_t addr, uint64_t key)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);

	return fi_inject_write(myep->hep, buf, len, dest_addr, addr, key);
}

static ssize_t hook_ze_rma_writedata(struct fid_ep *ep, const void *buf,
		size_t len, void *desc, uint64_t data, fi_addr_t dest_addr,
		uint64_t addr, uint64_t key, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc;
	struct iovec iov;
	int ret;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;
	ret = hook_ze_cache_mr(myep, &iov, 1, &hook_desc);
	if (ret)
		return ret;

	return fi_writedata(myep->hep, buf, len, hook_desc, data,
			    dest_addr, addr, key, context);
}

static ssize_t hook_ze_rma_injectdata(struct fid_ep *ep, const void *buf,
		size_t len, uint64_t data, fi_addr_t dest_addr, uint64_t addr,
		uint64_t key)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);

	return fi_inject_writedata(myep->hep, buf, len, data, dest_addr,
				   addr, key);
}

static struct fi_ops_rma hook_ze_rma_ops = {
	.size = sizeof(struct fi_ops_rma),
	.read = hook_ze_rma_read,
	.readv = hook_ze_rma_readv,
	.readmsg = hook_ze_rma_readmsg,
	.write = hook_ze_rma_write,
	.writev = hook_ze_rma_writev,
	.writemsg = hook_ze_rma_writemsg,
	.inject = hook_ze_rma_inject,
	.writedata = hook_ze_rma_writedata,
	.injectdata = hook_ze_rma_injectdata,
};


/*
 * tagged message ops
 */

static ssize_t hook_ze_tagged_recv(struct fid_ep *ep, void *buf, size_t len,
		void *desc, fi_addr_t src_addr, uint64_t tag, uint64_t ignore,
		void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc;
	struct iovec iov;
	int ret;

	iov.iov_base = buf;
	iov.iov_len = len;
	ret = hook_ze_cache_mr(myep, &iov, 1, &hook_desc);
	if (ret)
		return ret;

	return fi_trecv(myep->hep, buf, len, hook_desc, src_addr,
			tag, ignore, context);
}

static ssize_t hook_ze_tagged_recvv(struct fid_ep *ep, const struct iovec *iov,
		void **desc, size_t count, fi_addr_t src_addr, uint64_t tag,
		uint64_t ignore, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	int ret;

	ret = hook_ze_cache_mr(myep, iov, count, hook_desc);
	if (ret)
		return ret;

	return fi_trecvv(myep->hep, iov, hook_desc, count, src_addr,
			 tag, ignore, context);
}

static ssize_t hook_ze_tagged_recvmsg(struct fid_ep *ep,
		const struct fi_msg_tagged *msg, uint64_t flags)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	struct fi_msg_tagged mymsg = *msg;
	int ret;

	ret = hook_ze_cache_mr(myep, msg->msg_iov, msg->iov_count, hook_desc);
	if (ret)
		return ret;

	mymsg.desc = hook_desc;
	return fi_trecvmsg(myep->hep, &mymsg, flags);
}

static ssize_t hook_ze_tagged_send(struct fid_ep *ep, const void *buf,
		size_t len, void *desc, fi_addr_t dest_addr, uint64_t tag,
		void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc;
	struct iovec iov;
	int ret;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;
	ret = hook_ze_cache_mr(myep, &iov, 1, &hook_desc);
	if (ret)
		return ret;

	return fi_tsend(myep->hep, buf, len, hook_desc, dest_addr, tag,
			context);
}

static ssize_t hook_ze_tagged_sendv(struct fid_ep *ep,
		const struct iovec *iov, void **desc, size_t count,
		fi_addr_t dest_addr, uint64_t tag, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	int ret;

	ret = hook_ze_cache_mr(myep, iov, count, hook_desc);
	if (ret)
		return ret;

	return fi_tsendv(myep->hep, iov, hook_desc, count, dest_addr,
			 tag, context);
}

static ssize_t hook_ze_tagged_sendmsg(struct fid_ep *ep,
		const struct fi_msg_tagged *msg, uint64_t flags)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc[HOOK_ZE_IOV_LIMIT];
	struct fi_msg_tagged mymsg = *msg;
	int ret;

	ret = hook_ze_cache_mr(myep, msg->msg_iov, msg->iov_count, hook_desc);
	if (ret)
		return ret;

	mymsg.desc = hook_desc;
	return fi_tsendmsg(myep->hep, &mymsg, flags);
}

static ssize_t hook_ze_tagged_inject(struct fid_ep *ep, const void *buf,
		size_t len, fi_addr_t dest_addr, uint64_t tag)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);

	return fi_tinject(myep->hep, buf, len, dest_addr, tag);
}

static ssize_t hook_ze_tagged_senddata(struct fid_ep *ep, const void *buf,
		size_t len, void *desc, uint64_t data, fi_addr_t dest_addr,
		uint64_t tag, void *context)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);
	void *hook_desc;
	struct iovec iov;
	int ret;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;
	ret = hook_ze_cache_mr(myep, &iov, 1, &hook_desc);
	if (ret)
		return ret;

	return fi_tsenddata(myep->hep, buf, len, hook_desc, data,
			    dest_addr, tag, context);
}

static ssize_t hook_ze_tagged_injectdata(struct fid_ep *ep, const void *buf,
		size_t len, uint64_t data, fi_addr_t dest_addr, uint64_t tag)
{
	struct hook_ep *myep = container_of(ep, struct hook_ep, ep);

	return fi_tinjectdata(myep->hep, buf, len, data, dest_addr, tag);
}

static struct fi_ops_tagged hook_ze_tagged_ops = {
	.size = sizeof(struct fi_ops_tagged),
	.recv = hook_ze_tagged_recv,
	.recvv = hook_ze_tagged_recvv,
	.recvmsg = hook_ze_tagged_recvmsg,
	.send = hook_ze_tagged_send,
	.sendv = hook_ze_tagged_sendv,
	.sendmsg = hook_ze_tagged_sendmsg,
	.inject = hook_ze_tagged_inject,
	.senddata = hook_ze_tagged_senddata,
	.injectdata = hook_ze_tagged_injectdata,
};


/*
 * completion queue ops
 */

static ssize_t hook_ze_cq_read(struct fid_cq *cq, void *buf, size_t count)
{
	struct hook_cq *mycq = container_of(cq, struct hook_cq, cq);

	return fi_cq_read(mycq->hcq, buf, count);
}

static ssize_t hook_ze_cq_readerr(struct fid_cq *cq,
		struct fi_cq_err_entry *buf, uint64_t flags)
{
	struct hook_cq *mycq = container_of(cq, struct hook_cq, cq);

	return fi_cq_readerr(mycq->hcq, buf, flags);
}

static ssize_t hook_ze_cq_readfrom(struct fid_cq *cq, void *buf, size_t count,
		fi_addr_t *src_addr)
{
	struct hook_cq *mycq = container_of(cq, struct hook_cq, cq);

	return fi_cq_readfrom(mycq->hcq, buf, count, src_addr);
}

static ssize_t hook_ze_cq_sread(struct fid_cq *cq, void *buf, size_t count,
		const void *cond, int timeout)
{
	struct hook_cq *mycq = container_of(cq, struct hook_cq, cq);

	return fi_cq_sread(mycq->hcq, buf, count, cond, timeout);
}

static ssize_t hook_ze_cq_sreadfrom(struct fid_cq *cq, void *buf, size_t count,
		fi_addr_t *src_addr, const void *cond, int timeout)
{
	struct hook_cq *mycq = container_of(cq, struct hook_cq, cq);

	return fi_cq_sreadfrom(mycq->hcq, buf, count, src_addr, cond, timeout);
}

static int hook_ze_cq_signal(struct fid_cq *cq)
{
	struct hook_cq *mycq = container_of(cq, struct hook_cq, cq);

	return fi_cq_signal(mycq->hcq);
}

struct fi_ops_cq hook_ze_cq_ops = {
	.size = sizeof(struct fi_ops_cq),
	.read = hook_ze_cq_read,
	.readfrom = hook_ze_cq_readfrom,
	.readerr = hook_ze_cq_readerr,
	.sread = hook_ze_cq_sread,
	.sreadfrom = hook_ze_cq_sreadfrom,
	.signal = hook_ze_cq_signal,
	.strerror = hook_cq_strerror,
};


/*
 * counter ops
 */

static uint64_t hook_ze_cntr_read(struct fid_cntr *cntr)
{
	struct hook_cntr *mycntr = container_of(cntr, struct hook_cntr, cntr);

	return fi_cntr_read(mycntr->hcntr);
}

static uint64_t hook_ze_cntr_readerr(struct fid_cntr *cntr)
{
	struct hook_cntr *mycntr = container_of(cntr, struct hook_cntr, cntr);

	return fi_cntr_readerr(mycntr->hcntr);
}

static int hook_ze_cntr_add(struct fid_cntr *cntr, uint64_t value)
{
	struct hook_cntr *mycntr = container_of(cntr, struct hook_cntr, cntr);

	return fi_cntr_add(mycntr->hcntr, value);
}

static int hook_ze_cntr_set(struct fid_cntr *cntr, uint64_t value)
{
	struct hook_cntr *mycntr = container_of(cntr, struct hook_cntr, cntr);

	return fi_cntr_set(mycntr->hcntr, value);
}

static int hook_ze_cntr_wait(struct fid_cntr *cntr, uint64_t threshold, int timeout)
{
	struct hook_cntr *mycntr = container_of(cntr, struct hook_cntr, cntr);

	return fi_cntr_wait(mycntr->hcntr, threshold, timeout);
}

static int hook_ze_cntr_adderr(struct fid_cntr *cntr, uint64_t value)
{
	struct hook_cntr *mycntr = container_of(cntr, struct hook_cntr, cntr);

	return fi_cntr_adderr(mycntr->hcntr, value);
}

static int hook_ze_cntr_seterr(struct fid_cntr *cntr, uint64_t value)
{
	struct hook_cntr *mycntr = container_of(cntr, struct hook_cntr, cntr);

	return fi_cntr_seterr(mycntr->hcntr, value);
}

struct fi_ops_cntr hook_ze_cntr_ops = {
	.size = sizeof(struct fi_ops_cntr),
	.read = hook_ze_cntr_read,
	.readerr = hook_ze_cntr_readerr,
	.add = hook_ze_cntr_add,
	.set = hook_ze_cntr_set,
	.wait = hook_ze_cntr_wait,
	.adderr = hook_ze_cntr_adderr,
	.seterr = hook_ze_cntr_seterr,
};


//TODO figure out what we should do with app mr reg calls
//ignore? pass-through? cache?
/*
 * memory region
 */

static int hook_ze_mr_regattr(struct fid *fid, const struct fi_mr_attr *attr,
		uint64_t flags, struct fid_mr **mr)
{
	struct hook_domain *dom = container_of(fid, struct hook_domain, domain.fid);
	struct hook_mr *mymr;
	int ret;

	mymr = calloc(1, sizeof *mymr);
	if (!mymr)
		return -FI_ENOMEM;

	mymr->domain = dom;
	mymr->mr.fid.fclass = FI_CLASS_MR;
	mymr->mr.fid.context = attr->context;
	mymr->mr.fid.ops = &hook_fid_ops;

	ret = fi_mr_regattr(dom->hdomain, attr, flags, &mymr->hmr);
	if (ret) {
		free(mymr);
	} else {
		mymr->mr.mem_desc = mymr->hmr->mem_desc;
		mymr->mr.key = mymr->hmr->key;
		*mr = &mymr->mr;
	}

	return ret;
}

static int hook_ze_mr_regv(struct fid *fid, const struct iovec *iov,
		size_t count, uint64_t access, uint64_t offset,
		uint64_t requested_key, uint64_t flags, struct fid_mr **mr,
		void *context)
{
	struct fi_mr_attr attr;

	attr.mr_iov = iov;
	attr.iov_count = count;
	attr.access = access;
	attr.offset = offset;
	attr.requested_key = requested_key;
	attr.context = context;
	attr.auth_key_size = 0;
	attr.auth_key = NULL;

	return hook_ze_mr_regattr(fid, &attr, flags, mr);
}

static int hook_ze_mr_reg(struct fid *fid, const void *buf, size_t len,
		uint64_t access, uint64_t offset, uint64_t requested_key,
		uint64_t flags, struct fid_mr **mr, void *context)
{
	struct iovec iov;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;
	return hook_ze_mr_regv(fid, &iov, 1, access, offset, requested_key,
				 flags, mr, context);
}

static struct fi_ops_mr hook_ze_mr_ops = {
	.size = sizeof(struct fi_ops_mr),
	.reg = hook_ze_mr_reg,
	.regv = hook_ze_mr_regv,
	.regattr = hook_ze_mr_regattr,
};

/*
 * initialization
 */

static int hook_ze_cq_init(struct fid *fid)
{
	struct fid_cq *cq = container_of(fid, struct fid_cq, fid);
	cq->ops = &hook_ze_cq_ops;
	return 0;
}

static int hook_ze_cntr_init(struct fid *fid)
{
	struct fid_cntr *cntr = container_of(fid, struct fid_cntr, fid);
	cntr->ops = &hook_ze_cntr_ops;
	return 0;
}

static int hook_ze_ep_init(struct fid *fid)
{
	struct fid_ep *ep = container_of(fid, struct fid_ep, fid);
	ep->msg = &hook_ze_msg_ops;
	ep->rma = &hook_ze_rma_ops;
	ep->tagged = &hook_ze_tagged_ops;
	return 0;
}

struct hook_prov_ctx hook_ze_ctx;

static int hook_ze_getinfo(uint32_t version, const char *node, const char *service,
			   uint64_t flags, const struct fi_info *hints,
			   struct fi_info **info)
{
	struct fi_info *ze_hints;
	int ret;

	if (hints && hints->domain_attr) {
		ze_hints = fi_dupinfo(hints);
		ze_hints->domain_attr->mr_mode |= FI_MR_HMEM;
		ret = fi_getinfo(version, node, service, flags, ze_hints, info);
		fi_freeinfo(ze_hints);
		return ret;
	}

	return fi_getinfo(version, node, service, flags, hints, info);
}

static struct fi_ops_fabric hook_ze_fabric_ops;

static int hook_ze_fabric(struct fi_fabric_attr *attr,
			    struct fid_fabric **fabric, void *context)
{
	struct fi_provider *hprov = context;
	struct hook_fabric *fab;

	FI_TRACE(hprov, FI_LOG_FABRIC, "Installing ZE hook\n");
	fab = calloc(1, sizeof *fab);
	if (!fab)
		return -FI_ENOMEM;

	hook_fabric_init(fab, HOOK_ZE, attr->fabric, hprov,
			 &hook_fid_ops, &hook_ze_ctx);
	*fabric = &fab->fabric;
	fab->fabric.ops = &hook_ze_fabric_ops;

	return 0;
}

struct hook_prov_ctx hook_ze_ctx = {
	.prov = {
		.version = FI_VERSION(1,0),
		/* We're a pass-through provider, so the fi_version is always the latest */
		.fi_version = FI_VERSION(FI_MAJOR_VERSION, FI_MINOR_VERSION),
		.name = "ofi_hook_ze",
		.getinfo = hook_ze_getinfo,
		.fabric = hook_ze_fabric,
		.cleanup = NULL,
	},
};

static int hook_ze_domain_close(struct fid *fid)
{
	struct hook_ze_domain *ze_domain;
	struct hook_ze_desc *desc;
	int ret;

	ze_domain = container_of(fid, struct hook_ze_domain, hook_domain.domain);

	while (!dlist_empty(&ze_domain->mr_list)) {
		dlist_pop_front(&ze_domain->mr_list, struct hook_ze_desc,
				desc, entry);
		hook_ze_delete_region(ze_domain, desc);
	}

	ret = fi_close(&ze_domain->hook_domain.hdomain->fid);
	if (ret)
		return ret;

	ofi_rbmap_cleanup(&ze_domain->rbmap);
	ofi_bufpool_destroy(ze_domain->mr_pool);

	free(ze_domain);
	return 0;
} 

static struct fi_ops hook_ze_domain_ops = {
	.size = sizeof(struct fi_ops),
	.close = hook_ze_domain_close,
	.bind = hook_bind,
	.control = hook_control,
	.ops_open = hook_ops_open,
};

static int hook_ze_domain(struct fid_fabric *fabric, struct fi_info *info,
			    struct fid_domain **domain, void *context)
{
	struct hook_ze_domain *ze_domain;
	int ret;

	ze_domain = calloc(1, sizeof(*ze_domain));
	if (!ze_domain)
		return -FI_ENOMEM;

	ret = hook_domain_init(fabric, info, domain, context,
			       &ze_domain->hook_domain);
	if (ret)
		goto out;

	(*domain)->mr = &hook_ze_mr_ops;
	(*domain)->fid.ops = &hook_ze_domain_ops;

	ret = ofi_bufpool_create(&ze_domain->mr_pool,
				 sizeof(struct hook_ze_desc),
				 16, 0, 0, 0);
	if (ret) {
		hook_close(&(*domain)->fid);
		goto out;
	}

	ze_domain->mr_mode = info->domain_attr->mr_mode;
	ofi_rbmap_init(&ze_domain->rbmap, hook_ze_iov_compare);
	dlist_init(&ze_domain->mr_list);

	return 0;
out:
	free(ze_domain);
	return ret;
}

HOOK_ZE_INI
{
	hook_ze_fabric_ops = hook_fabric_ops;
	hook_ze_fabric_ops.domain = hook_ze_domain;

	hook_ze_ctx.ini_fid[FI_CLASS_CQ] = hook_ze_cq_init;
	hook_ze_ctx.ini_fid[FI_CLASS_CNTR] = hook_ze_cntr_init;
	hook_ze_ctx.ini_fid[FI_CLASS_EP] = hook_ze_ep_init;

	return &hook_ze_ctx.prov;
}
