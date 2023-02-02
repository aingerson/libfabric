/*
 * Copyright (c) 2013-2021 Intel Corporation. All rights reserved
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

#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/un.h>

#include "ofi_iov.h"
#include "ofi_hmem.h"
#include "ofi_mr.h"
#include "smr2_signal.h"
#include "smr2.h"
#include "smr2_dsa.h"

extern struct fi_ops_msg smr2_msg_ops, smr2_no_recv_msg_ops, smr2_srx_msg_ops;
extern struct fi_ops_tagged smr2_tag_ops, smr2_no_recv_tag_ops, smr2_srx_tag_ops;
extern struct fi_ops_rma smr2_rma_ops;
extern struct fi_ops_atomic smr2_atomic_ops;
DEFINE_LIST(smr2_sock_name_list);
pthread_mutex_t smr2_sock_list_lock = PTHREAD_MUTEX_INITIALIZER;
int smr2_global_ep_idx = 0;

int smr2_setname(fid_t fid, void *addr, size_t addrlen)
{
	struct smr2_ep *ep;
	char *name;

	if (addrlen > SMR2_NAME_MAX) {
		FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
			"Addrlen exceeds max addrlen (%d)\n", SMR2_NAME_MAX);
		return -FI_EINVAL;
	}

	ep = container_of(fid, struct smr2_ep, util_ep.ep_fid.fid);
	if (ep->region) {
		FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
			"Cannot set name after EP has been enabled\n");
		return -FI_EBUSY;
	}

	name = strdup(addr);
	if (!name)
		return -FI_ENOMEM;

	if (ep->name)
		free((void *) ep->name);
	ep->name = name;
	return 0;
}

int smr2_getname(fid_t fid, void *addr, size_t *addrlen)
{
	struct smr2_ep *ep;
	int ret = 0;

	ep = container_of(fid, struct smr2_ep, util_ep.ep_fid.fid);
	if (!ep->name)
		return -FI_EADDRNOTAVAIL;

	if (!addr || *addrlen == 0 ||
	    snprintf(addr, *addrlen, "%s", ep->name) >= *addrlen)
		ret = -FI_ETOOSMALL;

	*addrlen = strlen(ep->name) + 1;

	if (!ret)
		((char *) addr)[*addrlen - 1] = '\0';

	return ret;
}

static struct fi_ops_cm smr2_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.setname = smr2_setname,
	.getname = smr2_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = fi_no_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
	.shutdown = fi_no_shutdown,
};

int smr2_getopt(fid_t fid, int level, int optname,
	       void *optval, size_t *optlen)
{
	struct smr2_ep *smr2_ep =
		container_of(fid, struct smr2_ep, util_ep.ep_fid);

	if ((level != FI_OPT_ENDPOINT) || (optname != FI_OPT_MIN_MULTI_RECV))
		return -FI_ENOPROTOOPT;

	*(size_t *)optval = smr2_get_smr2_srx(smr2_ep)->min_multi_recv_size;
	*optlen = sizeof(size_t);

	return FI_SUCCESS;
}

int smr2_setopt(fid_t fid, int level, int optname,
	       const void *optval, size_t optlen)
{
	struct smr2_ep *smr2_ep =
		container_of(fid, struct smr2_ep, util_ep.ep_fid);

	if ((level != FI_OPT_ENDPOINT) || (optname != FI_OPT_MIN_MULTI_RECV))
		return -FI_ENOPROTOOPT;

	smr2_get_smr2_srx(smr2_ep)->min_multi_recv_size = *(size_t *)optval;

	return FI_SUCCESS;
}

static int smr2_match_recv_ctx(struct dlist_entry *item, const void *args)
{
	struct smr2_rx_entry *pending_recv;

	pending_recv = container_of(item, struct smr2_rx_entry, peer_entry);
	return pending_recv->peer_entry.context == args;
}

static int smr2_ep_cancel_recv(struct smr2_ep *ep, struct smr2_queue *queue,
			      void *context, uint32_t op)
{
	struct smr2_srx_ctx *srx = smr2_get_smr2_srx(ep);
	struct smr2_rx_entry *recv_entry;
	struct dlist_entry *entry;
	int ret = 0;

	ofi_spin_lock(&srx->lock);
	entry = dlist_remove_first_match(&queue->list, smr2_match_recv_ctx,
					 context);
	if (entry) {
		recv_entry = container_of(entry, struct smr2_rx_entry, peer_entry);
		ret = smr2_write_err_comp(ep->util_ep.rx_cq,
			recv_entry->peer_entry.context,
			smr2_rx_cq_flags(op, recv_entry->peer_entry.flags, 0),
			recv_entry->peer_entry.tag, FI_ECANCELED);
		ofi_freestack_push(srx->recv_fs, recv_entry);
		ret = ret ? ret : 1;
	}

	ofi_spin_unlock(&srx->lock);
	return ret;
}

static ssize_t smr2_ep_cancel(fid_t ep_fid, void *context)
{
	struct smr2_ep *ep;
	int ret;

	ep = container_of(ep_fid, struct smr2_ep, util_ep.ep_fid);

	ret = smr2_ep_cancel_recv(ep, &smr2_get_smr2_srx(ep)->trecv_queue, context,
				 ofi_op_tagged);
	if (ret)
		return (ret < 0) ? ret : 0;

	ret = smr2_ep_cancel_recv(ep, &smr2_get_smr2_srx(ep)->recv_queue, context,
				 ofi_op_msg);
	return (ret < 0) ? ret : 0;
}

static struct fi_ops_ep smr2_ep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = smr2_ep_cancel,
	.getopt = smr2_getopt,
	.setopt = smr2_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

static void smr2_send_name(struct smr2_ep *ep, int64_t id)
{
	struct smr2_region *peer_smr;
	struct smr2_cmd *cmd;
	struct smr2_inject_buf *tx_buf;

	peer_smr = smr2_peer_region(ep->region, id);

	pthread_spin_lock(&peer_smr->lock);

	if (smr2_peer_data(ep->region)[id].name_sent || !peer_smr->cmd_cnt)
		goto out;

	cmd = ofi_cirque_next(smr2_cmd_queue(peer_smr));

	cmd->msg.hdr.op = SMR2_OP_MAX + ofi_ctrl_connreq;
	cmd->msg.hdr.id = id;
	cmd->msg.hdr.data = ep->region->pid;

	tx_buf = smr_freestack_pop(smr2_inject_pool(peer_smr));
	cmd->msg.hdr.src_data = smr2_get_offset(peer_smr, tx_buf);

	cmd->msg.hdr.size = strlen(ep->name) + 1;
	memcpy(tx_buf->data, ep->name, cmd->msg.hdr.size);

	smr2_peer_data(ep->region)[id].name_sent = 1;
	ofi_cirque_commit(smr2_cmd_queue(peer_smr));
	peer_smr->cmd_cnt--;
	smr2_signal(peer_smr);

out:
	pthread_spin_unlock(&peer_smr->lock);
}

int64_t smr2_verify_peer(struct smr2_ep *ep, fi_addr_t fi_addr)
{
	int64_t id;
	int ret;

	id = smr2_addr_lookup(ep->util_ep.av, fi_addr);
	assert(id < SMR2_MAX_PEERS);

	if (smr2_peer_data(ep->region)[id].addr.id >= 0)
		return id;

	if (ep->region->map->peers[id].peer.id < 0) {
		ret = smr2_map_to_region(&smr2_prov, ep->region->map, id);
		if (ret == -ENOENT)
			return -1;

	}

	smr2_send_name(ep, id);

	return -1;
}

static int smr2_match_msg(struct dlist_entry *item, const void *args)
{
	struct smr2_match_attr *attr = (struct smr2_match_attr *)args;
	struct smr2_rx_entry *recv_entry;

	recv_entry = container_of(item, struct smr2_rx_entry, peer_entry);
	return smr2_match_id(recv_entry->peer_entry.addr, attr->id);
}

static int smr2_match_tagged(struct dlist_entry *item, const void *args)
{
	struct smr2_match_attr *attr = (struct smr2_match_attr *)args;
	struct smr2_rx_entry *recv_entry;

	recv_entry = container_of(item, struct smr2_rx_entry, peer_entry);
	return smr2_match_id(recv_entry->peer_entry.addr, attr->id) &&
	       smr2_match_tag(recv_entry->peer_entry.tag, recv_entry->ignore,
			     attr->tag);
}

static void smr2_init_queue(struct smr2_queue *queue,
			   dlist_func_t *match_func)
{
	dlist_init(&queue->list);
	queue->match_func = match_func;
}

void smr2_format_pend_resp(struct smr2_tx_entry *pend, struct smr2_cmd *cmd,
			  void *context, enum fi_hmem_iface iface, uint64_t device,
			  const struct iovec *iov, uint32_t iov_count,
			  uint64_t op_flags, int64_t id, struct smr2_resp *resp)
{
	pend->cmd = *cmd;
	pend->context = context;
	memcpy(pend->iov, iov, sizeof(*iov) * iov_count);
	pend->iov_count = iov_count;
	pend->peer_id = id;
	pend->op_flags = op_flags;
	if (cmd->msg.hdr.op_src != smr2_src_sar) {
		pend->bytes_done = 0;
		resp->status = FI_EBUSY;
	}

	pend->iface = iface;
	pend->device = device;

	resp->msg_id = (uint64_t) (uintptr_t) pend;
}

void smr2_generic_format(struct smr2_cmd *cmd, int64_t peer_id, uint32_t op,
			uint64_t tag, uint64_t data, uint64_t op_flags)
{
	cmd->msg.hdr.op = op;
	cmd->msg.hdr.op_flags = op == ofi_op_read_req ? SMR2_RMA_REQ : 0;
	cmd->msg.hdr.tag = tag;
	cmd->msg.hdr.id = peer_id;
	cmd->msg.hdr.data = data;

	if (op_flags & FI_REMOTE_CQ_DATA)
		cmd->msg.hdr.op_flags |= SMR2_REMOTE_CQ_DATA;
	if (op_flags & FI_COMPLETION)
		cmd->msg.hdr.op_flags |= SMR2_TX_COMPLETION;
}

static void smr2_format_inline(struct smr2_cmd *cmd, enum fi_hmem_iface iface,
		       uint64_t device, const struct iovec *iov, size_t count)
{
	cmd->msg.hdr.op_src = smr2_src_inline;
	cmd->msg.hdr.size = ofi_copy_from_hmem_iov(cmd->msg.data.msg,
						SMR2_MSG_DATA_LEN, iface, device,
						iov, count, 0);
}

static void smr2_format_inject(struct smr2_cmd *cmd, enum fi_hmem_iface iface,
		uint64_t device, const struct iovec *iov, size_t count,
		struct smr2_region *smr, struct smr2_inject_buf *tx_buf)
{
	cmd->msg.hdr.op_src = smr2_src_inject;
	cmd->msg.hdr.src_data = smr2_get_offset(smr, tx_buf);
	cmd->msg.hdr.size = ofi_copy_from_hmem_iov(tx_buf->data, SMR2_INJECT_SIZE,
						   iface, device, iov, count, 0);
}

static void smr2_format_iov(struct smr2_cmd *cmd, const struct iovec *iov,
		size_t count, size_t total_len, struct smr2_region *smr,
		struct smr2_resp *resp)
{
	cmd->msg.hdr.op_src = smr2_src_iov;
	cmd->msg.hdr.src_data = smr2_get_offset(smr, resp);
	cmd->msg.data.iov_count = count;
	cmd->msg.hdr.size = total_len;
	memcpy(cmd->msg.data.iov, iov, sizeof(*iov) * count);
}

static int smr2_format_ze_ipc(struct smr2_ep *ep, int64_t id, struct smr2_cmd *cmd,
		const struct iovec *iov, uint64_t device, size_t total_len,
		struct smr2_region *smr,	 struct smr2_resp *resp,
		struct smr2_tx_entry *pend)
{
	int ret;
	void *base;

	cmd->msg.hdr.op_src = smr2_src_ipc;
	cmd->msg.hdr.src_data = smr2_get_offset(smr, resp);
	cmd->msg.hdr.size = total_len;
	cmd->msg.data.ipc_info.iface = FI_HMEM_ZE;

	if (ep->sock_info->peers[id].state == SMR2_CMAP_INIT)
		smr2_ep_exchange_fds(ep, id);
	if (ep->sock_info->peers[id].state != SMR2_CMAP_SUCCESS)
		return -FI_EAGAIN;

	ret = ze_hmem_get_base_addr(iov[0].iov_base, &base, NULL);
	if (ret)
		return ret;

	ret = ze_hmem_get_shared_handle(ep->sock_info->my_fds[device],
			base, &pend->fd,
			(void **) &cmd->msg.data.ipc_info.ipc_handle);
	if (ret)
		return ret;

	cmd->msg.data.ipc_info.device = device;
	cmd->msg.data.ipc_info.offset = (char *) iov[0].iov_base -
					(char *) base;

	return FI_SUCCESS;
}

static int smr2_format_ipc(struct smr2_cmd *cmd, void *ptr, size_t len,
		struct smr2_region *smr, struct smr2_resp *resp,
		enum fi_hmem_iface iface)
{
	int ret;
	void *base;

	cmd->msg.hdr.op_src = smr2_src_ipc;
	cmd->msg.hdr.src_data = smr2_get_offset(smr, resp);
	cmd->msg.hdr.size = len;
	cmd->msg.data.ipc_info.iface = iface;
	ret = ofi_hmem_get_base_addr(cmd->msg.data.ipc_info.iface, ptr, &base,
				     &cmd->msg.data.ipc_info.base_length);
	if (ret)
		return ret;

	ret = ofi_hmem_get_handle(cmd->msg.data.ipc_info.iface, base,
				   (void **)&cmd->msg.data.ipc_info.ipc_handle);
	if (ret)
		return ret;

	cmd->msg.data.ipc_info.base_addr = (uintptr_t) base;
	cmd->msg.data.ipc_info.offset = (uintptr_t) ptr - (uintptr_t) base;

	return FI_SUCCESS;
}

static int smr2_format_mmap(struct smr2_ep *ep, struct smr2_cmd *cmd,
		const struct iovec *iov, size_t count, size_t total_len,
		struct smr2_tx_entry *pend, struct smr2_resp *resp)
{
	void *mapped_ptr;
	int fd, ret, num;
	uint64_t msg_id;
	struct smr2_ep_name *map_name;

	msg_id = ep->msg_id++;
	map_name = calloc(1, sizeof(*map_name));
	if (!map_name) {
		FI_WARN(&smr2_prov, FI_LOG_EP_CTRL, "calloc error\n");
		return -FI_ENOMEM;
	}

	pthread_mutex_lock(&smr2_ep_list_lock);
	dlist_insert_tail(&map_name->entry, &smr2_ep_name_list);
	pthread_mutex_unlock(&smr2_ep_list_lock);
	num = smr2_mmap_name(map_name->name, ep->name, msg_id);
	if (num < 0) {
		FI_WARN(&smr2_prov, FI_LOG_AV, "generating shm file name failed\n");
		ret = -errno;
		goto remove_entry;
	}

	fd = shm_open(map_name->name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		FI_WARN(&smr2_prov, FI_LOG_EP_CTRL, "shm_open error\n");
		ret = -errno;
		goto remove_entry;
	}

	ret = ftruncate(fd, total_len);
	if (ret < 0) {
		FI_WARN(&smr2_prov, FI_LOG_EP_CTRL, "ftruncate error\n");
		goto unlink_close;
	}

	mapped_ptr = mmap(NULL, total_len, PROT_READ | PROT_WRITE,
			  MAP_SHARED, fd, 0);
	if (mapped_ptr == MAP_FAILED) {
		FI_WARN(&smr2_prov, FI_LOG_EP_CTRL, "mmap error\n");
		ret = -errno;
		goto unlink_close;
	}

	if (cmd->msg.hdr.op != ofi_op_read_req) {
		if (ofi_copy_from_iov(mapped_ptr, total_len, iov, count, 0)
		    != total_len) {
			FI_WARN(&smr2_prov, FI_LOG_EP_CTRL, "copy from iov error\n");
			ret = -FI_EIO;
			goto munmap;
		}
		munmap(mapped_ptr, total_len);
	} else {
		pend->map_ptr = mapped_ptr;
	}

	cmd->msg.hdr.op_src = smr2_src_mmap;
	cmd->msg.hdr.msg_id = msg_id;
	cmd->msg.hdr.src_data = smr2_get_offset(ep->region, resp);
	cmd->msg.hdr.size = total_len;
	pend->map_name = map_name;

	close(fd);
	return 0;

munmap:
	munmap(mapped_ptr, total_len);
unlink_close:
	shm_unlink(map_name->name);
	close(fd);
remove_entry:
	dlist_remove(&map_name->entry);
	free(map_name);
	return ret;
}

size_t smr2_copy_to_sar(struct smr_freestack *sar_pool, struct smr2_resp *resp,
		       struct smr2_cmd *cmd, enum fi_hmem_iface iface,
		       uint64_t device, const struct iovec *iov, size_t count,
		       size_t *bytes_done, int *next)
{
	struct smr2_sar_buf *sar_buf;
	size_t start = *bytes_done;
	int next_sar_buf = 0;

	if (resp->status != SMR2_STATUS_SAR_FREE)
		return 0;

	while ((*bytes_done < cmd->msg.hdr.size) &&
			(next_sar_buf < cmd->msg.data.buf_batch_size)) {
		sar_buf = smr_freestack_get_entry_from_index(
				sar_pool, cmd->msg.data.sar[next_sar_buf]);

		*bytes_done += ofi_copy_from_hmem_iov(
				sar_buf->buf, SMR2_SAR_SIZE, iface,
				device, iov, count, *bytes_done);

		next_sar_buf++;
	}

	resp->status =SMR2_STATUS_SAR_READY;

	return *bytes_done - start;
}

size_t smr2_copy_from_sar(struct smr_freestack *sar_pool, struct smr2_resp *resp,
			 struct smr2_cmd *cmd, enum fi_hmem_iface iface,
			 uint64_t device, const struct iovec *iov, size_t count,
			 size_t *bytes_done, int *next)
{
	struct smr2_sar_buf *sar_buf;
	size_t start = *bytes_done;
	int next_sar_buf = 0;

	if (resp->status != SMR2_STATUS_SAR_READY)
		return 0;

	while ((*bytes_done < cmd->msg.hdr.size) &&
			(next_sar_buf < cmd->msg.data.buf_batch_size)) {
		sar_buf = smr_freestack_get_entry_from_index(
				sar_pool, cmd->msg.data.sar[next_sar_buf]);

		*bytes_done += ofi_copy_to_hmem_iov(
				iface, device, iov, count, *bytes_done,
				sar_buf->buf, SMR2_SAR_SIZE);

		next_sar_buf++;
	}
	resp->status = SMR2_STATUS_SAR_FREE;
	return *bytes_done - start;
}

static int smr2_format_sar(struct smr2_ep *ep, struct smr2_cmd *cmd,
		   enum fi_hmem_iface iface, uint64_t device,
		   const struct iovec *iov, size_t count, size_t total_len,
		   struct smr2_region *smr, struct smr2_region *peer_smr,
		   int64_t id, struct smr2_tx_entry *pending,
		   struct smr2_resp *resp)
{
	int i, ret;
	uint32_t sar_needed;

	if (!peer_smr->sar_cnt)
		return -FI_EAGAIN;

	if (peer_smr->max_sar_buf_per_peer == 0)
		return -FI_EAGAIN;

	sar_needed = (total_len + SMR2_SAR_SIZE - 1) / SMR2_SAR_SIZE;
	cmd->msg.data.buf_batch_size = MIN(SMR2_BUF_BATCH_MAX,
			MIN(peer_smr->max_sar_buf_per_peer, sar_needed));

	for (i = 0; i < cmd->msg.data.buf_batch_size; i++) {
		if (smr_freestack_isempty(smr2_sar_pool(peer_smr))) {
			cmd->msg.data.buf_batch_size = i;
			if (i == 0)
				return -FI_EAGAIN;
			break;
		}

		cmd->msg.data.sar[i] =
			smr_freestack_pop_by_index(smr2_sar_pool(peer_smr));
	}

	resp->status = SMR2_STATUS_SAR_FREE;
	cmd->msg.hdr.op_src = smr2_src_sar;
	cmd->msg.hdr.src_data = smr2_get_offset(smr, resp);
	cmd->msg.hdr.size = total_len;
	pending->bytes_done = 0;
	pending->next = 0;

	if (cmd->msg.hdr.op != ofi_op_read_req) {
		if (smr2_env.use_dsa_sar && iface == FI_HMEM_SYSTEM) {
			ret = smr2_dsa_copy_to_sar(ep, smr2_sar_pool(peer_smr),
					resp, cmd, iov,	count,
					&pending->bytes_done, pending);
			if (ret != FI_SUCCESS) {
				for (i = cmd->msg.data.buf_batch_size - 1;
				     i >= 0; i--) {
					smr_freestack_push_by_index(
					    smr2_sar_pool(peer_smr),
					    cmd->msg.data.sar[i]);
				}
				return -FI_EAGAIN;
			}
		} else {
			smr2_copy_to_sar(smr2_sar_pool(peer_smr), resp, cmd,
					iface, device, iov, count,
					&pending->bytes_done, &pending->next);
		}
	}

	peer_smr->sar_cnt--;
	smr2_peer_data(smr)[id].sar_status = SMR2_STATUS_SAR_READY;

	return 0;
}

int smr2_select_proto(bool use_ipc, bool cma_avail, enum fi_hmem_iface iface,
		     uint32_t op, uint64_t total_len, uint64_t op_flags)
{
	if (op == ofi_op_read_req) {
		if (use_ipc)
			return smr2_src_ipc;
		if (cma_avail && FI_HMEM_SYSTEM)
			return smr2_src_iov;
		return smr2_src_sar;
	}

	if (op_flags & FI_INJECT) {
		if (op_flags & FI_DELIVERY_COMPLETE)
			return smr2_src_sar;
		return total_len <= SMR2_MSG_DATA_LEN ?
				smr2_src_inline : smr2_src_inject;
	}

	if (use_ipc)
		return smr2_src_ipc;

	if (total_len > SMR2_INJECT_SIZE && iface == FI_HMEM_SYSTEM && cma_avail)
		return smr2_src_iov;

	if (op_flags & FI_DELIVERY_COMPLETE)
		return smr2_src_sar;

	if (total_len <= SMR2_MSG_DATA_LEN)
		return smr2_src_inline;

	if (total_len <= SMR2_INJECT_SIZE)
		return smr2_src_inject;

	if (total_len <= smr2_env.sar_threshold || iface != FI_HMEM_SYSTEM)
		return smr2_src_sar;

	return smr2_src_mmap;
}

static ssize_t smr2_do_inline(struct smr2_ep *ep, struct smr2_region *peer_smr, int64_t id,
			     int64_t peer_id, uint32_t op, uint64_t tag, uint64_t data,
			     uint64_t op_flags, enum fi_hmem_iface iface, uint64_t device,
			     const struct iovec *iov, size_t iov_count, size_t total_len,
			     void *context)
{
	struct smr2_cmd *cmd;

	cmd = ofi_cirque_next(smr2_cmd_queue(peer_smr));
	smr2_generic_format(cmd, peer_id, op, tag, data, op_flags);
	smr2_format_inline(cmd, iface, device, iov, iov_count);

	ofi_cirque_commit(smr2_cmd_queue(peer_smr));
	peer_smr->cmd_cnt--;

	return FI_SUCCESS;
}

static ssize_t smr2_do_inject(struct smr2_ep *ep, struct smr2_region *peer_smr, int64_t id,
			     int64_t peer_id, uint32_t op, uint64_t tag, uint64_t data,
			     uint64_t op_flags, enum fi_hmem_iface iface, uint64_t device,
			     const struct iovec *iov, size_t iov_count, size_t total_len,
			     void *context)
{
	struct smr2_cmd *cmd;
	struct smr2_inject_buf *tx_buf;

	cmd = ofi_cirque_next(smr2_cmd_queue(peer_smr));
	tx_buf = smr_freestack_pop(smr2_inject_pool(peer_smr));

	smr2_generic_format(cmd, peer_id, op, tag, data, op_flags);
	smr2_format_inject(cmd, iface, device, iov, iov_count, peer_smr, tx_buf);

	ofi_cirque_commit(smr2_cmd_queue(peer_smr));
	peer_smr->cmd_cnt--;

	return FI_SUCCESS;
}

static ssize_t smr2_do_iov(struct smr2_ep *ep, struct smr2_region *peer_smr, int64_t id,
			  int64_t peer_id, uint32_t op, uint64_t tag, uint64_t data,
			  uint64_t op_flags, enum fi_hmem_iface iface, uint64_t device,
		          const struct iovec *iov, size_t iov_count, size_t total_len,
		          void *context)
{
	struct smr2_cmd *cmd;
	struct smr2_resp *resp;
	struct smr2_tx_entry *pend;

	if (ofi_cirque_isfull(smr2_resp_queue(ep->region)))
		return -FI_EAGAIN;

	cmd = ofi_cirque_next(smr2_cmd_queue(peer_smr));
	resp = ofi_cirque_next(smr2_resp_queue(ep->region));
	pend = ofi_freestack_pop(ep->pend_fs);

	smr2_generic_format(cmd, peer_id, op, tag, data, op_flags);
	smr2_format_iov(cmd, iov, iov_count, total_len, ep->region, resp);
	smr2_format_pend_resp(pend, cmd, context, iface, device, iov,
			     iov_count, op_flags, id, resp);
	ofi_cirque_commit(smr2_resp_queue(ep->region));

	ofi_cirque_commit(smr2_cmd_queue(peer_smr));
	peer_smr->cmd_cnt--;

	return FI_SUCCESS;
}

static ssize_t smr2_do_sar(struct smr2_ep *ep, struct smr2_region *peer_smr, int64_t id,
			  int64_t peer_id, uint32_t op, uint64_t tag, uint64_t data,
			  uint64_t op_flags, enum fi_hmem_iface iface, uint64_t device,
		          const struct iovec *iov, size_t iov_count, size_t total_len,
		          void *context)
{
	struct smr2_cmd *cmd;
	struct smr2_resp *resp;
	struct smr2_tx_entry *pend;
	int ret;

	if (ofi_cirque_isfull(smr2_resp_queue(ep->region)))
		return -FI_EAGAIN;

	cmd = ofi_cirque_next(smr2_cmd_queue(peer_smr));
	resp = ofi_cirque_next(smr2_resp_queue(ep->region));
	pend = ofi_freestack_pop(ep->pend_fs);

	smr2_generic_format(cmd, peer_id, op, tag, data, op_flags);
	ret = smr2_format_sar(ep, cmd, iface, device, iov, iov_count, total_len,
			     ep->region, peer_smr, id, pend, resp);
	if (ret) {
		ofi_freestack_push(ep->pend_fs, pend);
		return ret;
	}

	smr2_format_pend_resp(pend, cmd, context, iface, device, iov,
			     iov_count, op_flags, id, resp);
	ofi_cirque_commit(smr2_resp_queue(ep->region));

	ofi_cirque_commit(smr2_cmd_queue(peer_smr));
	peer_smr->cmd_cnt--;

	return FI_SUCCESS;
}

static ssize_t smr2_do_ipc(struct smr2_ep *ep, struct smr2_region *peer_smr, int64_t id,
			  int64_t peer_id, uint32_t op, uint64_t tag, uint64_t data,
			  uint64_t op_flags, enum fi_hmem_iface iface, uint64_t device,
		          const struct iovec *iov, size_t iov_count, size_t total_len,
		          void *context)
{
	struct smr2_cmd *cmd;
	struct smr2_resp *resp;
	struct smr2_tx_entry *pend;
	int ret = -FI_EAGAIN;

	if (ofi_cirque_isfull(smr2_resp_queue(ep->region)))
		return -FI_EAGAIN;

	cmd = ofi_cirque_next(smr2_cmd_queue(peer_smr));
	resp = ofi_cirque_next(smr2_resp_queue(ep->region));
	pend = ofi_freestack_pop(ep->pend_fs);

	smr2_generic_format(cmd, peer_id, op, tag, data, op_flags);
	if (iface == FI_HMEM_ZE) {
		if (smr2_ze_ipc_enabled(ep->region, peer_smr))
			ret = smr2_format_ze_ipc(ep, id, cmd, iov, device,
					total_len, ep->region, resp, pend);
	} else {
		ret = smr2_format_ipc(cmd, iov[0].iov_base, total_len, ep->region,
				     resp, iface);
	}

	if (ret) {
		FI_WARN_ONCE(&smr2_prov, FI_LOG_EP_CTRL,
			     "unable to use IPC for msg, fallback to using SAR\n");
		ofi_freestack_push(ep->pend_fs, pend);
		return smr2_do_sar(ep, peer_smr, id, peer_id, op, tag, data,
				  op_flags, iface, device, iov, iov_count,
				  total_len, context);
	}

	smr2_format_pend_resp(pend, cmd, context, iface, device, iov,
			     iov_count, op_flags, id, resp);
	ofi_cirque_commit(smr2_resp_queue(ep->region));

	ofi_cirque_commit(smr2_cmd_queue(peer_smr));
	peer_smr->cmd_cnt--;

	return FI_SUCCESS;
}

static ssize_t smr2_do_mmap(struct smr2_ep *ep, struct smr2_region *peer_smr, int64_t id,
			   int64_t peer_id, uint32_t op, uint64_t tag, uint64_t data,
			   uint64_t op_flags, enum fi_hmem_iface iface, uint64_t device,
		           const struct iovec *iov, size_t iov_count, size_t total_len,
		           void *context)
{
	struct smr2_cmd *cmd;
	struct smr2_resp *resp;
	struct smr2_tx_entry *pend;
	int ret;

	if (ofi_cirque_isfull(smr2_resp_queue(ep->region)))
		return -FI_EAGAIN;

	cmd = ofi_cirque_next(smr2_cmd_queue(peer_smr));
	resp = ofi_cirque_next(smr2_resp_queue(ep->region));
	pend = ofi_freestack_pop(ep->pend_fs);

	smr2_generic_format(cmd, peer_id, op, tag, data, op_flags);
	ret = smr2_format_mmap(ep, cmd, iov, iov_count, total_len, pend, resp);
	if (ret) {
		ofi_freestack_push(ep->pend_fs, pend);
		return ret;
	}

	smr2_format_pend_resp(pend, cmd, context, iface, device, iov,
			     iov_count, op_flags, id, resp);
	ofi_cirque_commit(smr2_resp_queue(ep->region));

	ofi_cirque_commit(smr2_cmd_queue(peer_smr));
	peer_smr->cmd_cnt--;

	return FI_SUCCESS;
}

smr2_proto_func smr2_proto_ops[smr2_src_max] = {
	[smr2_src_inline] = &smr2_do_inline,
	[smr2_src_inject] = &smr2_do_inject,
	[smr2_src_iov] = &smr2_do_iov,
	[smr2_src_mmap] = &smr2_do_mmap,
	[smr2_src_sar] = &smr2_do_sar,
	[smr2_src_ipc] = &smr2_do_ipc,
};

static void smr2_cleanup_epoll(struct smr2_sock_info *sock_info)
{
	fd_signal_free(&sock_info->signal);
	ofi_epoll_close(sock_info->epollfd);
}

int smr2_srx_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct smr2_srx_ctx *srx;

	if (flags != FI_RECV || bfid->fclass != FI_CLASS_CQ)
		return -FI_EINVAL;

	srx = container_of(fid, struct smr2_srx_ctx, peer_srx.ep_fid.fid);
	srx->cq = container_of(bfid, struct smr2_cq, util_cq.cq_fid.fid);
	ofi_atomic_inc32(&srx->cq->util_cq.ref);
	return FI_SUCCESS;
}

static void smr2_close_recv_queue(struct smr2_srx_ctx *srx,
				 struct smr2_queue *recv_queue)
{
	struct fi_cq_err_entry err_entry;
	struct smr2_rx_entry *rx_entry;
	int ret;

	while (!dlist_empty(&recv_queue->list)) {
		dlist_pop_front(&recv_queue->list, struct smr2_rx_entry,
				rx_entry, peer_entry);

		memset(&err_entry, 0, sizeof err_entry);
		err_entry.op_context = rx_entry->peer_entry.context;
		err_entry.flags = rx_entry->peer_entry.flags;
		err_entry.tag = rx_entry->peer_entry.tag;
		err_entry.err = FI_ECANCELED;
		err_entry.prov_errno = -FI_ECANCELED;
		ret = srx->cq->peer_cq->owner_ops->writeerr(srx->cq->peer_cq, &err_entry);
		if (ret)
			FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
				"Error writing recv entry error to rx cq\n");

		ofi_freestack_push(srx->recv_fs, rx_entry);
	}
}

static void smr2_close_unexp_queue(struct smr2_srx_ctx *srx,
				 struct smr2_queue *unexp_queue)
{
	struct smr2_rx_entry *rx_entry;

	while (!dlist_empty(&unexp_queue->list)) {
		dlist_pop_front(&unexp_queue->list, struct smr2_rx_entry,
				rx_entry, peer_entry);
		rx_entry->peer_entry.srx->peer_ops->discard_msg(
							&rx_entry->peer_entry);
	}
}

static int smr2_srx_close(struct fid *fid)
{
	struct smr2_srx_ctx *srx;

	srx = container_of(fid, struct smr2_srx_ctx, peer_srx.ep_fid.fid);
	if (!srx)
		return -FI_EINVAL;

	smr2_close_recv_queue(srx, &srx->recv_queue);
	smr2_close_recv_queue(srx, &srx->trecv_queue);

	smr2_close_unexp_queue(srx, &srx->unexp_msg_queue);
	smr2_close_unexp_queue(srx, &srx->unexp_tagged_queue);

	ofi_atomic_dec32(&srx->cq->util_cq.ref);
	smr2_recv_fs_free(srx->recv_fs);
	ofi_spin_destroy(&srx->lock);
	free(srx);

	return FI_SUCCESS;
}

static int smr2_ep_close(struct fid *fid)
{
	struct smr2_ep *ep;

	ep = container_of(fid, struct smr2_ep, util_ep.ep_fid.fid);

	if (smr2_env.use_dsa_sar)
		smr2_dsa_context_cleanup(ep);

	if (ep->sock_info) {
		fd_signal_set(&ep->sock_info->signal);
		pthread_join(ep->sock_info->listener_thread, NULL);
		close(ep->sock_info->listen_sock);
		unlink(ep->sock_info->name);
		smr2_cleanup_epoll(ep->sock_info);
		free(ep->sock_info);
	}

	ofi_endpoint_close(&ep->util_ep);

	if (ep->region)
		smr2_free(ep->region);

	if (ep->util_ep.ep_fid.msg != &smr2_no_recv_msg_ops)
		smr2_srx_close(&ep->srx->fid);

	smr2_cmd_ctx_fs_free(ep->cmd_ctx_fs);
	smr2_pend_fs_free(ep->pend_fs);
	smr2_sar_fs_free(ep->sar_fs);
	ofi_spin_destroy(&ep->tx_lock);

	free((void *)ep->name);
	free(ep);
	return 0;
}

static int smr2_ep_trywait(void *arg)
{
	struct smr2_ep *ep;

	ep = container_of(arg, struct smr2_ep, util_ep.ep_fid.fid);

	smr2_ep_progress(&ep->util_ep);

	return FI_SUCCESS;
}

static int smr2_ep_bind_cq(struct smr2_ep *ep, struct util_cq *cq, uint64_t flags)
{
	int ret;

	ret = ofi_ep_bind_cq(&ep->util_ep, cq, flags);
	if (ret)
		return ret;

	if (flags & FI_RECV)
		ep->rx_comp = cq->domain->info_domain_caps & FI_SOURCE ?
				smr2_rx_src_comp: smr2_rx_comp;

	if (cq->wait) {
		ret = ofi_wait_add_fid(cq->wait, &ep->util_ep.ep_fid.fid, 0,
				       smr2_ep_trywait);
		if (ret)
			return ret;
	}

	ret = fid_list_insert(&cq->ep_list,
			      &cq->ep_list_lock,
			      &ep->util_ep.ep_fid.fid);

	return ret;
}

static int smr2_ep_bind_cntr(struct smr2_ep *ep, struct util_cntr *cntr, uint64_t flags)
{
	int ret;

	ret = ofi_ep_bind_cntr(&ep->util_ep, cntr, flags);
	if (ret)
		return ret;

	if (cntr->wait) {
		ret = ofi_wait_add_fid(cntr->wait, &ep->util_ep.ep_fid.fid, 0,
				       smr2_ep_trywait);
		if (ret)
			return ret;
	}

	return FI_SUCCESS;
}

static int smr2_ep_bind(struct fid *ep_fid, struct fid *bfid, uint64_t flags)
{
	struct smr2_ep *ep;
	struct util_av *av;
	int ret = 0;

	ep = container_of(ep_fid, struct smr2_ep, util_ep.ep_fid.fid);
	switch (bfid->fclass) {
	case FI_CLASS_AV:
		av = container_of(bfid, struct util_av, av_fid.fid);
		ret = ofi_ep_bind_av(&ep->util_ep, av);
		if (ret) {
			FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
				"duplicate AV binding\n");
			return -FI_EINVAL;
		}
		break;
	case FI_CLASS_CQ:
		ret = smr2_ep_bind_cq(ep, container_of(bfid, struct util_cq,
						      cq_fid.fid), flags);
		break;
	case FI_CLASS_EQ:
		break;
	case FI_CLASS_CNTR:
		ret = smr2_ep_bind_cntr(ep, container_of(bfid,
				struct util_cntr, cntr_fid.fid), flags);
		break;
	case FI_CLASS_SRX_CTX:
		ep->srx = container_of(bfid, struct fid_ep, fid);
		break;
	default:
		FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
			"invalid fid class\n");
		ret = -FI_EINVAL;
		break;
	}
	return ret;
}

static int smr2_sendmsg_fd(int sock, int64_t id, int64_t peer_id,
			  int *fds, int nfds)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char *ctrl_buf;
	size_t ctrl_size;
	int ret;

	ctrl_size = sizeof(*fds) * nfds;
	ctrl_buf = calloc(CMSG_SPACE(ctrl_size), 1);
	if (!ctrl_buf)
		return -FI_ENOMEM;

	iov.iov_base = &peer_id;
	iov.iov_len = sizeof(peer_id);

	memset(&msg, 0, sizeof(msg));
	msg.msg_control = ctrl_buf;
	msg.msg_controllen = CMSG_SPACE(ctrl_size);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(ctrl_size);
	memcpy(CMSG_DATA(cmsg), fds, ctrl_size);

	ret = sendmsg(sock, &msg, 0);
	if (ret == sizeof(peer_id)) {
		ret = FI_SUCCESS;
	} else {
		FI_WARN(&smr2_prov, FI_LOG_EP_CTRL, "sendmsg error\n");
		ret = -FI_EIO;
	}

	free(ctrl_buf);
	return ret;
}

static int smr2_recvmsg_fd(int sock, int64_t *peer_id, int *fds, int nfds)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char *ctrl_buf;
	size_t ctrl_size;
	int ret;

	ctrl_size = sizeof(*fds) * nfds;
	ctrl_buf = calloc(CMSG_SPACE(ctrl_size), 1);
	if (!ctrl_buf)
		return -FI_ENOMEM;

	iov.iov_base = peer_id;
	iov.iov_len = sizeof(*peer_id);

	memset(&msg, 0, sizeof(msg));
	msg.msg_control = ctrl_buf;
	msg.msg_controllen = CMSG_SPACE(ctrl_size);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ret = recvmsg(sock, &msg, 0);
	if (ret == sizeof(*peer_id)) {
		ret = FI_SUCCESS;
	} else {
		FI_WARN(&smr2_prov, FI_LOG_EP_CTRL, "recvmsg error\n");
		ret = -FI_EIO;
		goto out;
	}

	assert(!(msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)));
	cmsg = CMSG_FIRSTHDR(&msg);
	assert(cmsg && cmsg->cmsg_len == CMSG_LEN(ctrl_size) &&
	       cmsg->cmsg_level == SOL_SOCKET &&
	       cmsg->cmsg_type == SCM_RIGHTS && CMSG_DATA(cmsg));
	memcpy(fds, CMSG_DATA(cmsg), ctrl_size);
out:
	free(ctrl_buf);
	return ret;
}

static void *smr2_start_listener(void *args)
{
	struct smr2_ep *ep = (struct smr2_ep *) args;
	struct sockaddr_un sockaddr;
	struct ofi_epollfds_event events[SMR2_MAX_PEERS + 1];
	int i, ret, poll_fds, sock = -1;
	int peer_fds[ZE_MAX_DEVICES];
	socklen_t len = sizeof(sockaddr);
	int64_t id, peer_id;

	ep->region->flags |= SMR2_FLAG_IPC_SOCK;
	while (1) {
		poll_fds = ofi_epoll_wait(ep->sock_info->epollfd, events,
					  SMR2_MAX_PEERS + 1, -1);

		if (poll_fds < 0) {
			FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
				"epoll error\n");
			continue;
		}

		for (i = 0; i < poll_fds; i++) {
			if (!events[i].data.ptr)
				goto out;

			sock = accept(ep->sock_info->listen_sock,
				      (struct sockaddr *) &sockaddr, &len);
			if (sock < 0) {
				FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
					"accept error\n");
				continue;
			}

			FI_DBG(&smr2_prov, FI_LOG_EP_CTRL,
			       "EP accepted connection request from %s\n",
			       sockaddr.sun_path);

			ret = smr2_recvmsg_fd(sock, &id, peer_fds,
					     ep->sock_info->nfds);
			if (!ret) {
				memcpy(ep->sock_info->peers[id].device_fds,
				       peer_fds, sizeof(*peer_fds) *
				       ep->sock_info->nfds);

				peer_id = smr2_peer_data(ep->region)[id].addr.id;
				ret = smr2_sendmsg_fd(sock, id, peer_id,
						ep->sock_info->my_fds,
						ep->sock_info->nfds);
				ep->sock_info->peers[id].state =
					ret ? SMR2_CMAP_FAILED :
					SMR2_CMAP_SUCCESS;
			}

			close(sock);
			unlink(sockaddr.sun_path);
		}
	}
out:
	close(ep->sock_info->listen_sock);
	unlink(ep->sock_info->name);
	return NULL;
}

static int smr2_init_epoll(struct smr2_sock_info *sock_info)
{
	int ret;

	ret = ofi_epoll_create(&sock_info->epollfd);
	if (ret < 0)
		return ret;

	ret = fd_signal_init(&sock_info->signal);
	if (ret < 0)
		goto err2;

	ret = ofi_epoll_add(sock_info->epollfd,
	                    sock_info->signal.fd[FI_READ_FD],
	                    OFI_EPOLL_IN, NULL);
	if (ret != 0)
		goto err1;

	ret = ofi_epoll_add(sock_info->epollfd, sock_info->listen_sock,
			    OFI_EPOLL_IN, sock_info);
	if (ret != 0)
		goto err1;

	return FI_SUCCESS;
err1:
	ofi_epoll_close(sock_info->epollfd);
err2:
	fd_signal_free(&sock_info->signal);
	return ret;
}

void smr2_ep_exchange_fds(struct smr2_ep *ep, int64_t id)
{
	struct smr2_region *peer_smr = smr2_peer_region(ep->region, id);
	struct sockaddr_un server_sockaddr = {0}, client_sockaddr = {0};
	char *name1, *name2;
	int ret = -1, sock = -1;
	int64_t peer_id;
	int peer_fds[ZE_MAX_DEVICES];

	if (peer_smr->pid == ep->region->pid ||
	    !(peer_smr->flags & SMR2_FLAG_IPC_SOCK))
		goto out;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		goto out;

	if (strcmp(smr2_sock_name(ep->region), smr2_sock_name(peer_smr)) < 1) {
		name1 = smr2_sock_name(ep->region);
		name2 = smr2_sock_name(peer_smr);
	} else {
		name1 = smr2_sock_name(peer_smr);
		name2 = smr2_sock_name(ep->region);
	}
	client_sockaddr.sun_family = AF_UNIX;
	snprintf(client_sockaddr.sun_path, SMR2_SOCK_NAME_MAX, "%s%s:%s",
		 SMR2_ZE_SOCK_PATH, name1, name2);

	ret = bind(sock, (struct sockaddr *) &client_sockaddr,
		  (socklen_t) sizeof(client_sockaddr));
	if (ret == -1) {
		if (errno != EADDRINUSE) {
			FI_WARN(&smr2_prov, FI_LOG_EP_CTRL, "bind error\n");
			ep->sock_info->peers[id].state = SMR2_CMAP_FAILED;
		}
		close(sock);
		return;
	}

	server_sockaddr.sun_family = AF_UNIX;
	snprintf(server_sockaddr.sun_path, SMR2_SOCK_NAME_MAX, "%s%s",
		 SMR2_ZE_SOCK_PATH, smr2_sock_name(peer_smr));

	ret = connect(sock, (struct sockaddr *) &server_sockaddr,
		      sizeof(server_sockaddr));
	if (ret == -1)
		goto cleanup;

	FI_DBG(&smr2_prov, FI_LOG_EP_CTRL, "EP connected to UNIX socket %s\n",
	       server_sockaddr.sun_path);

	peer_id = smr2_peer_data(ep->region)[id].addr.id;
	ret = smr2_sendmsg_fd(sock, id, peer_id, ep->sock_info->my_fds,
			     ep->sock_info->nfds);
	if (ret)
		goto cleanup;

	ret = smr2_recvmsg_fd(sock, &id, peer_fds, ep->sock_info->nfds);
	if (ret)
		goto cleanup;

	memcpy(ep->sock_info->peers[id].device_fds, peer_fds,
	       sizeof(*peer_fds) * ep->sock_info->nfds);

cleanup:
	close(sock);
	unlink(client_sockaddr.sun_path);
out:
	ep->sock_info->peers[id].state = ret ?
		SMR2_CMAP_FAILED : SMR2_CMAP_SUCCESS;
}

static void smr2_init_ipc_socket(struct smr2_ep *ep)
{
	struct smr2_sock_name *sock_name;
	struct sockaddr_un sockaddr = {0};
	int ret;

	ep->sock_info = calloc(1, sizeof(*ep->sock_info));
	if (!ep->sock_info)
		goto err_out;

	ep->sock_info->listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ep->sock_info->listen_sock < 0)
		goto free;

	snprintf(smr2_sock_name(ep->region), SMR2_SOCK_NAME_MAX,
		 "%ld:%d", (long) ep->region->pid, ep->ep_idx);

	sockaddr.sun_family = AF_UNIX;
	snprintf(sockaddr.sun_path, SMR2_SOCK_NAME_MAX,
		 "%s%s", SMR2_ZE_SOCK_PATH, smr2_sock_name(ep->region));

	ret = bind(ep->sock_info->listen_sock, (struct sockaddr *) &sockaddr,
		   (socklen_t) sizeof(sockaddr));
	if (ret)
		goto close;

	ret = listen(ep->sock_info->listen_sock, SMR2_MAX_PEERS);
	if (ret)
		goto close;

	FI_DBG(&smr2_prov, FI_LOG_EP_CTRL, "EP listening on UNIX socket %s\n",
	       sockaddr.sun_path);

	ret = smr2_init_epoll(ep->sock_info);
	if (ret)
		goto close;

	sock_name = calloc(1, sizeof(*sock_name));
	if (!sock_name)
		goto cleanup;

	memcpy(sock_name->name, sockaddr.sun_path, strlen(sockaddr.sun_path));
	memcpy(ep->sock_info->name, sockaddr.sun_path,
	       strlen(sockaddr.sun_path));

	pthread_mutex_lock(&smr2_sock_list_lock);
	dlist_insert_tail(&sock_name->entry, &smr2_sock_name_list);
	pthread_mutex_unlock(&smr2_sock_list_lock);

	ep->sock_info->my_fds = ze_hmem_get_dev_fds(&ep->sock_info->nfds);
	ret = pthread_create(&ep->sock_info->listener_thread, NULL,
			     &smr2_start_listener, ep);
	if (ret)
		goto remove;

	return;

remove:
	pthread_mutex_lock(&smr2_sock_list_lock);
	dlist_remove(&sock_name->entry);
	pthread_mutex_unlock(&smr2_sock_list_lock);
	free(sock_name);
cleanup:
	smr2_cleanup_epoll(ep->sock_info);
close:
	close(ep->sock_info->listen_sock);
	unlink(sockaddr.sun_path);
free:
	free(ep->sock_info);
	ep->sock_info = NULL;
err_out:
	FI_WARN(&smr2_prov, FI_LOG_EP_CTRL, "Unable to initialize IPC socket."
		"Defaulting to SAR for device transfers\n");
}

bool smr2_adjust_multi_recv(struct smr2_srx_ctx *srx,
			   struct fi_peer_rx_entry *rx_entry, size_t len)
{
	size_t left;
	void *new_base;

	left = rx_entry->iov[0].iov_len - len;

	new_base = (void *) ((uintptr_t) rx_entry->iov[0].iov_base + len);
	rx_entry->iov[0].iov_len = left;
	rx_entry->iov[0].iov_base = new_base;
	rx_entry->size = left;

	return left < srx->min_multi_recv_size;
}

static int smr2_get_msg(struct fid_peer_srx *srx, fi_addr_t addr,
		       size_t size, struct fi_peer_rx_entry **rx_entry)
{
	struct smr2_rx_entry *smr2_entry;
	struct smr2_srx_ctx *srx_ctx;
	struct smr2_match_attr match_attr;
	struct dlist_entry *dlist_entry;
	struct smr2_rx_entry *owner_entry;
	int ret;

	srx_ctx = srx->ep_fid.fid.context;
	ofi_spin_lock(&srx_ctx->lock);

	match_attr.id = addr;

	dlist_entry = dlist_find_first_match(&srx_ctx->recv_queue.list,
					     srx_ctx->recv_queue.match_func,
					     &match_attr);
	if (!dlist_entry) {
		smr2_entry = smr2_alloc_rx_entry(srx_ctx);
		if (!smr2_entry) {
			ret = -FI_ENOMEM;
		} else {
			smr2_entry->peer_entry.owner_context = NULL;
			smr2_entry->peer_entry.addr = addr;
			smr2_entry->peer_entry.size = size;
			smr2_entry->peer_entry.srx = srx;
			*rx_entry = &smr2_entry->peer_entry;
			ret = -FI_ENOENT;
		}
		goto out;
	}

	*rx_entry = (struct fi_peer_rx_entry *) dlist_entry;

	if ((*rx_entry)->flags & FI_MULTI_RECV) {
		owner_entry = container_of(*rx_entry, struct smr2_rx_entry, peer_entry);
		smr2_entry = smr2_get_recv_entry(srx_ctx, owner_entry->iov, owner_entry->desc,
					     owner_entry->peer_entry.count, addr,
					     owner_entry->peer_entry.context,
					     owner_entry->peer_entry.tag,
					     owner_entry->ignore,
					     owner_entry->peer_entry.flags & (~FI_MULTI_RECV));
		if (!smr2_entry) {
			ret = -FI_ENOMEM;
			goto out;
		}

		if (smr2_adjust_multi_recv(srx_ctx, &owner_entry->peer_entry, size))
			dlist_remove(dlist_entry);

		smr2_entry->peer_entry.owner_context = owner_entry;
		*rx_entry = &smr2_entry->peer_entry;
		owner_entry->multi_recv_ref++;
	} else {
		dlist_remove(dlist_entry);
	}

	(*rx_entry)->srx = srx;
	ret = FI_SUCCESS;
out:
	ofi_spin_unlock(&srx_ctx->lock);
	return ret;
}

static int smr2_get_tag(struct fid_peer_srx *srx, fi_addr_t addr,
			uint64_t tag, struct fi_peer_rx_entry **rx_entry)
{
	struct smr2_rx_entry *smr2_entry;
	struct smr2_srx_ctx *srx_ctx;
	struct smr2_match_attr match_attr;
	struct dlist_entry *dlist_entry;
	int ret;

	srx_ctx = srx->ep_fid.fid.context;
	ofi_spin_lock(&srx_ctx->lock);

	match_attr.id = addr;
	match_attr.tag = tag;

	dlist_entry = dlist_find_first_match(&srx_ctx->trecv_queue.list,
					     srx_ctx->trecv_queue.match_func,
					     &match_attr);
	if (!dlist_entry) {
		smr2_entry = smr2_alloc_rx_entry(srx_ctx);
		if (!smr2_entry) {
			ret = -FI_ENOMEM;
		} else {
			smr2_entry->peer_entry.owner_context = NULL;
			smr2_entry->peer_entry.addr = addr;
			smr2_entry->peer_entry.tag = tag;
			smr2_entry->peer_entry.srx = srx;
			*rx_entry = &smr2_entry->peer_entry;
			ret = -FI_ENOENT;
		}
		goto out;
	}
	dlist_remove(dlist_entry);

	*rx_entry = (struct fi_peer_rx_entry *) dlist_entry;
	(*rx_entry)->srx = srx;
	ret = FI_SUCCESS;
out:
	ofi_spin_unlock(&srx_ctx->lock);
	return ret;
}

static int smr2_queue_msg(struct fi_peer_rx_entry *rx_entry)
{
	struct smr2_srx_ctx *srx_ctx = rx_entry->srx->ep_fid.fid.context;

	ofi_spin_lock(&srx_ctx->lock);
	dlist_insert_tail((struct dlist_entry *) rx_entry,
			  &srx_ctx->unexp_msg_queue.list);
	ofi_spin_unlock(&srx_ctx->lock);
	return 0;
}

static int smr2_queue_tag(struct fi_peer_rx_entry *rx_entry)
{
	struct smr2_srx_ctx *srx_ctx = rx_entry->srx->ep_fid.fid.context;

	ofi_spin_lock(&srx_ctx->lock);
	dlist_insert_tail((struct dlist_entry *) rx_entry,
			  &srx_ctx->unexp_tagged_queue.list);
	ofi_spin_unlock(&srx_ctx->lock);
	return 0;
}

static void smr2_free_entry(struct fi_peer_rx_entry *entry)
{
	struct smr2_srx_ctx *srx = (struct smr2_srx_ctx *) entry->srx->ep_fid.fid.context;
	struct smr2_rx_entry *smr2_entry, *owner_entry;

	ofi_spin_lock(&srx->lock);
	smr2_entry = container_of(entry, struct smr2_rx_entry, peer_entry);
	if (entry->owner_context) {
		owner_entry = container_of(entry->owner_context,
					   struct smr2_rx_entry, peer_entry);
		if (!--owner_entry->multi_recv_ref &&
		    owner_entry->peer_entry.size < srx->min_multi_recv_size) {
			if (smr2_rx_comp(srx->cq, owner_entry->peer_entry.context,
					FI_MULTI_RECV, 0, NULL,
					0, 0, FI_ADDR_NOTAVAIL)) {
				FI_WARN(&smr2_prov, FI_LOG_EP_CTRL,
					"unable to write rx MULTI_RECV completion\n");
			}
			ofi_freestack_push(srx->recv_fs, owner_entry);
		}
	}

	ofi_freestack_push(srx->recv_fs, smr2_entry);
	ofi_spin_unlock(&srx->lock);
}

static struct fi_ops_srx_owner smr2_srx_owner_ops = {
	.size = sizeof(struct fi_ops_srx_owner),
	.get_msg = smr2_get_msg,
	.get_tag = smr2_get_tag,
	.queue_msg = smr2_queue_msg,
	.queue_tag = smr2_queue_tag,
	.free_entry = smr2_free_entry,
};

static int smr2_discard(struct fi_peer_rx_entry *rx_entry)
{
	struct smr2_cmd_ctx *cmd_ctx = rx_entry->peer_context;

	ofi_freestack_push(cmd_ctx->ep->cmd_ctx_fs, cmd_ctx);
	return FI_SUCCESS;
}

struct fi_ops_srx_peer smr2_srx_peer_ops = {
	.size = sizeof(struct fi_ops_srx_peer),
	.start_msg = smr2_unexp_start,
	.start_tag = smr2_unexp_start,
	.discard_msg = smr2_discard,
	.discard_tag = smr2_discard,
};

static struct fi_ops smr2_srx_fid_ops = {
	.size = sizeof(struct fi_ops),
	.close = smr2_srx_close,
	.bind = smr2_srx_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_ep smr2_srx_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = smr2_ep_cancel,
	.getopt = fi_no_getopt,
	.setopt = fi_no_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

static int smr2_ep_srx_context(struct smr2_domain *domain, size_t rx_size,
			      struct fid_ep **rx_ep)
{
	struct smr2_srx_ctx *srx;
	int ret = FI_SUCCESS;

	srx = calloc(1, sizeof(*srx));
	if (!srx)
		return -FI_ENOMEM;

	ret = ofi_spin_init(&srx->lock);
	if (ret)
		goto err;

	smr2_init_queue(&srx->recv_queue, smr2_match_msg);
	smr2_init_queue(&srx->trecv_queue, smr2_match_tagged);
	smr2_init_queue(&srx->unexp_msg_queue, smr2_match_msg);
	smr2_init_queue(&srx->unexp_tagged_queue, smr2_match_tagged);

	srx->recv_fs = smr2_recv_fs_create(rx_size, NULL, NULL);

	srx->min_multi_recv_size = SMR2_INJECT_SIZE;
	srx->dir_recv = domain->util_domain.info_domain_caps & FI_DIRECTED_RECV;

	srx->peer_srx.owner_ops = &smr2_srx_owner_ops;
	srx->peer_srx.peer_ops = &smr2_srx_peer_ops;

	srx->peer_srx.ep_fid.fid.fclass = FI_CLASS_SRX_CTX;
	srx->peer_srx.ep_fid.fid.context = srx;
	srx->peer_srx.ep_fid.fid.ops = &smr2_srx_fid_ops;
	srx->peer_srx.ep_fid.ops = &smr2_srx_ops;

	srx->peer_srx.ep_fid.msg = &smr2_srx_msg_ops;
	srx->peer_srx.ep_fid.tagged = &smr2_srx_tag_ops;
	*rx_ep = &srx->peer_srx.ep_fid;

	return FI_SUCCESS;

err:
	free(srx);
	return ret;
}

int smr2_srx_context(struct fid_domain *domain, struct fi_rx_attr *attr,
		    struct fid_ep **rx_ep, void *context)
{
	struct smr2_domain *smr2_domain;

	smr2_domain = container_of(domain, struct smr2_domain, util_domain.domain_fid);

	if (attr->op_flags & FI_PEER) {
		smr2_domain->srx = ((struct fi_peer_srx_context *) (context))->srx;
		smr2_domain->srx->peer_ops = &smr2_srx_peer_ops;
		return FI_SUCCESS;
	}
	return smr2_ep_srx_context(smr2_domain, attr->size, rx_ep);
}

static int smr2_ep_ctrl(struct fid *fid, int command, void *arg)
{
	struct smr2_attr attr;
	struct smr2_domain *domain;
	struct smr2_ep *ep;
	struct smr2_av *av;
	int ret;

	ep = container_of(fid, struct smr2_ep, util_ep.ep_fid.fid);
	av = container_of(ep->util_ep.av, struct smr2_av, util_av);

	switch (command) {
	case FI_ENABLE:
		if ((ofi_needs_rx(ep->util_ep.caps) && !ep->util_ep.rx_cq) ||
		    (ofi_needs_tx(ep->util_ep.caps) && !ep->util_ep.tx_cq))
			return -FI_ENOCQ;
		if (!ep->util_ep.av)
			return -FI_ENOAV;

		attr.name = smr2_no_prefix(ep->name);
		attr.rx_count = ep->rx_size;
		attr.tx_count = ep->tx_size;
		attr.flags = ep->util_ep.caps & FI_HMEM ?
				SMR2_FLAG_HMEM_ENABLED : 0;

		ret = smr2_create(&smr2_prov, av->smr2_map, &attr, &ep->region);
		if (ret)
			return ret;

		if (ep->util_ep.caps & FI_HMEM || smr2_env.disable_cma) {
			ep->region->cma_cap_peer = SMR2_CMA_CAP_OFF;
			ep->region->cma_cap_self = SMR2_CMA_CAP_OFF;
			if (ep->util_ep.caps & FI_HMEM) {
				if (ze_hmem_p2p_enabled())
					smr2_init_ipc_socket(ep);
			}
		}

		if (!ep->srx) {
			domain = container_of(ep->util_ep.domain,
					      struct smr2_domain,
					      util_domain.domain_fid);
			ret = smr2_ep_srx_context(domain, ep->rx_size,
						 &ep->srx);
			if (ret)
				return ret;
			ret = smr2_srx_bind(&ep->srx->fid,
					   &ep->util_ep.rx_cq->cq_fid.fid,
					   FI_RECV);
			if (ret)
				return ret;
		} else {
			ep->util_ep.ep_fid.msg = &smr2_no_recv_msg_ops;
			ep->util_ep.ep_fid.tagged = &smr2_no_recv_tag_ops;
		}
		smr2_exchange_all_peers(ep->region);

		if (smr2_env.use_dsa_sar)
			smr2_dsa_context_init(ep);

		break;
	default:
		return -FI_ENOSYS;
	}
	return ret;
}

static struct fi_ops smr2_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = smr2_ep_close,
	.bind = smr2_ep_bind,
	.control = smr2_ep_ctrl,
	.ops_open = fi_no_ops_open,
};

static int smr2_endpoint_name(struct smr2_ep *ep, char *name, char *addr,
			     size_t addrlen)
{
	memset(name, 0, SMR2_NAME_MAX);
	if (!addr || addrlen > SMR2_NAME_MAX)
		return -FI_EINVAL;

	pthread_mutex_lock(&smr2_ep_list_lock);
	ep->ep_idx = smr2_global_ep_idx++;
	pthread_mutex_unlock(&smr2_ep_list_lock);

	if (strstr(addr, SMR2_PREFIX))
		snprintf(name, SMR2_NAME_MAX - 1, "%s:%d:%d", addr, getuid(),
			 ep->ep_idx);
	else
		snprintf(name, SMR2_NAME_MAX - 1, "%s", addr);

	return 0;
}

static void smr2_init_sig_handlers(void)
{
	static bool sig_init = false;

	pthread_mutex_lock(&smr2_ep_list_lock);
	if (sig_init)
		goto out;

	/* Signal handlers to cleanup tmpfs files on an unclean shutdown */
	assert(SIGBUS < SIGRTMIN && SIGSEGV < SIGRTMIN
	       && SIGTERM < SIGRTMIN && SIGINT < SIGRTMIN);
	smr2_reg_sig_handler(SIGBUS);
	smr2_reg_sig_handler(SIGSEGV);
	smr2_reg_sig_handler(SIGTERM);
	smr2_reg_sig_handler(SIGINT);

	sig_init = true;
out:
	pthread_mutex_unlock(&smr2_ep_list_lock);
}

int smr2_endpoint(struct fid_domain *domain, struct fi_info *info,
		  struct fid_ep **ep_fid, void *context)
{
	struct smr2_ep *ep;
	int ret;
	char name[SMR2_NAME_MAX];

	smr2_init_sig_handlers();

	ep = calloc(1, sizeof(*ep));
	if (!ep)
		return -FI_ENOMEM;

	ret = smr2_endpoint_name(ep, name, info->src_addr, info->src_addrlen);
	if (ret)
		goto ep;
	ret = smr2_setname(&ep->util_ep.ep_fid.fid, name, SMR2_NAME_MAX);
	if (ret)
		goto ep;

	ret = ofi_spin_init(&ep->tx_lock);
	if (ret)
		goto name;

	ep->rx_size = info->rx_attr->size;
	ep->tx_size = info->tx_attr->size;
	ret = ofi_endpoint_init(domain, &smr2_util_prov, info, &ep->util_ep, context,
				smr2_ep_progress);
	if (ret)
		goto lock;

	ep->util_ep.ep_fid.msg = &smr2_msg_ops;
	ep->util_ep.ep_fid.tagged = &smr2_tag_ops;

	ep->cmd_ctx_fs = smr2_cmd_ctx_fs_create(info->rx_attr->size, NULL, NULL);
	ep->pend_fs = smr2_pend_fs_create(info->tx_attr->size, NULL, NULL);
	ep->sar_fs = smr2_sar_fs_create(info->rx_attr->size, NULL, NULL);

	dlist_init(&ep->sar_list);

	ep->util_ep.ep_fid.fid.ops = &smr2_ep_fi_ops;
	ep->util_ep.ep_fid.ops = &smr2_ep_ops;
	ep->util_ep.ep_fid.cm = &smr2_cm_ops;
	ep->util_ep.ep_fid.rma = &smr2_rma_ops;
	ep->util_ep.ep_fid.atomic = &smr2_atomic_ops;

	*ep_fid = &ep->util_ep.ep_fid;
	return 0;

lock:
	ofi_spin_destroy(&ep->tx_lock);
name:
	free((void *)ep->name);
ep:
	free(ep);
	return ret;
}
