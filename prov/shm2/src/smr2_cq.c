/*
 * Copyright (c) 2013-2017 Intel Corporation. All rights reserved.
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

#include "smr2.h"

static int smr2_peer_cq_close(struct fid *fid)
{
	free(container_of(fid, struct fid_peer_cq, fid));
	return 0;
}

static int smr2_cq_close(struct fid *fid)
{
	int ret;
	struct smr2_cq *smr2_cq;

	smr2_cq = container_of(fid, struct smr2_cq, util_cq.cq_fid.fid);

	ret = ofi_cq_cleanup(&smr2_cq->util_cq);
	if (ret)
		return ret;

	if (!(smr2_cq->util_cq.flags & FI_PEER))
		fi_close(&smr2_cq->peer_cq->fid);

	free(smr2_cq);
	return 0;
}

static struct fi_ops smr2_cq_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = smr2_cq_close,
	.bind = fi_no_bind,
	.control = ofi_cq_control,
	.ops_open = fi_no_ops_open,
};

static ssize_t smr2_peer_cq_write(struct fid_peer_cq *cq, void *context, uint64_t flags,
		size_t len, void *buf, uint64_t data, uint64_t tag,
		fi_addr_t src)
{
	struct smr2_cq *smr2_cq;
	int ret;

	smr2_cq = cq->fid.context;

	if (src == FI_ADDR_NOTAVAIL)
		ret = ofi_cq_write(&smr2_cq->util_cq, context, flags, len,
				   buf, data, tag);
	else
		ret = ofi_cq_write_src(&smr2_cq->util_cq, context, flags, len,
				       buf, data, tag, src);

	if (smr2_cq->util_cq.wait)
		smr2_cq->util_cq.wait->signal(smr2_cq->util_cq.wait);

	return ret;
}

static ssize_t smr2_peer_cq_writeerr(struct fid_peer_cq *cq,
				    const struct fi_cq_err_entry *err_entry)
{
	return ofi_cq_write_error(&((struct smr2_cq *)
				  (cq->fid.context))->util_cq, err_entry);
}

static struct fi_ops_cq_owner smr2_peer_cq_owner_ops = {
	.size = sizeof(struct fi_ops_cq_owner),
	.write = &smr2_peer_cq_write,
	.writeerr = &smr2_peer_cq_writeerr,
};

static struct fi_ops smr2_peer_cq_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = smr2_peer_cq_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static int smr2_init_peer_cq(struct smr2_cq *smr2_cq)
{
	smr2_cq->peer_cq = calloc(1, sizeof(*smr2_cq->peer_cq));
	if (!smr2_cq->peer_cq)
		return -FI_ENOMEM;

	smr2_cq->peer_cq->fid.fclass = FI_CLASS_PEER_CQ;
	smr2_cq->peer_cq->fid.context = smr2_cq;
	smr2_cq->peer_cq->fid.ops = &smr2_peer_cq_fi_ops;
	smr2_cq->peer_cq->owner_ops = &smr2_peer_cq_owner_ops;

	return 0;
}

static ssize_t smr2_cq_read(struct fid_cq *cq_fid, void *buf, size_t count)
{
	return ofi_cq_readfrom(cq_fid, buf, count, NULL);
}

static struct fi_ops_cq smr2_peer_cq_ops = {
	.size = sizeof(struct fi_ops_cq),
	.read = smr2_cq_read,
	.readfrom = fi_no_cq_readfrom,
	.readerr = fi_no_cq_readerr,
	.sread = fi_no_cq_sread,
	.sreadfrom = fi_no_cq_sreadfrom,
	.signal = fi_no_cq_signal,
	.strerror = fi_no_cq_strerror,
};

int smr2_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		struct fid_cq **cq_fid, void *context)
{
	struct smr2_cq *smr2_cq;
	int ret;

	switch (attr->wait_obj) {
	case FI_WAIT_UNSPEC:
		attr->wait_obj = FI_WAIT_YIELD;
		/* fall through */
	case FI_WAIT_NONE:
	case FI_WAIT_YIELD:
		break;
	default:
		FI_INFO(&smr2_prov, FI_LOG_CQ, "CQ wait not yet supported\n");
		return -FI_ENOSYS;
	}

	smr2_cq = calloc(1, sizeof(*smr2_cq));
	if (!smr2_cq)
		return -FI_ENOMEM;

	ret = ofi_cq_init(&smr2_prov, domain, attr, &smr2_cq->util_cq,
			  &ofi_cq_progress, context);
	if (ret)
		goto free;

	if (attr->flags & FI_PEER) {
		smr2_cq->peer_cq = ((struct fi_peer_cq_context *) context)->cq;
		smr2_cq->util_cq.cq_fid.ops = &smr2_peer_cq_ops;
	} else {
		ret = smr2_init_peer_cq(smr2_cq);
		if (ret)
			goto cleanup;
	}

	smr2_cq->util_cq.cq_fid.fid.ops = &smr2_cq_fi_ops;
	(*cq_fid) = &smr2_cq->util_cq.cq_fid;
	return 0;

cleanup:
	(void) ofi_cq_cleanup(&smr2_cq->util_cq);
free:
	free(smr2_cq);
	return ret;
}
