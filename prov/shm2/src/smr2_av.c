/*
 * Copyright (c) 2015-2020 Intel Corporation. All rights reserved.
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

#include "smr2.h"

static int smr2_av_close(struct fid *fid)
{
	int ret;
	struct util_av *av;
	struct smr2_av *smr2_av;

	av = container_of(fid, struct util_av, av_fid);
	smr2_av = container_of(av, struct smr2_av, util_av);

	ret = ofi_av_close(av);
	if (ret)
		return ret;

	smr2_map_free(smr2_av->smr2_map);
	free(av);
	return 0;
}

/*
 * Input address: smr name (string)
 * output address: index (fi_addr_t), the output from util_av
 */
static int smr2_av_insert(struct fid_av *av_fid, const void *addr, size_t count,
			 fi_addr_t *fi_addr, uint64_t flags, void *context)
{
	struct util_av *util_av;
	struct util_ep *util_ep;
	struct smr2_av *smr2_av;
	struct smr2_ep *smr2_ep;
	struct dlist_entry *av_entry;
	fi_addr_t util_addr;
	int64_t shm_id = -1;
	int i, ret;
	int succ_count = 0;

	util_av = container_of(av_fid, struct util_av, av_fid);
	smr2_av = container_of(util_av, struct smr2_av, util_av);

	for (i = 0; i < count; i++, addr = (char *) addr + strlen(addr) + 1) {
		FI_INFO(&smr2_prov, FI_LOG_AV, "%s\n", (const char *) addr);

		util_addr = FI_ADDR_NOTAVAIL;
		if (smr2_av->used < SMR2_MAX_PEERS) {
			ret = smr2_map_add(&smr2_prov, smr2_av->smr2_map,
					  addr, &shm_id);
			if (!ret) {
				ofi_mutex_lock(&util_av->lock);
				ret = ofi_av_insert_addr(util_av, &shm_id,
							 &util_addr);
				ofi_mutex_unlock(&util_av->lock);
			}
		} else {
			FI_WARN(&smr2_prov, FI_LOG_AV,
				"AV insert failed. The maximum number of AV "
				"entries shm supported has been reached.\n");
			ret = -FI_ENOMEM;
		}

		FI_INFO(&smr2_prov, FI_LOG_AV, "fi_addr: %" PRIu64 "\n", util_addr);
		if (fi_addr)
			fi_addr[i] = util_addr;

		if (ret) {
			if (util_av->eq)
				ofi_av_write_event(util_av, i, -ret, context);
			if (shm_id >= 0)
				smr2_map_del(smr2_av->smr2_map, shm_id);
			continue;
		} else {
			assert(shm_id >= 0 && shm_id < SMR2_MAX_PEERS);
			if (flags & FI_AV_USER_ID) {
				assert(fi_addr);
				smr2_av->smr2_map->peers[shm_id].fiaddr = fi_addr[i];
			} else {
				smr2_av->smr2_map->peers[shm_id].fiaddr = util_addr;
			}
			succ_count++;
			smr2_av->used++;
		}

		assert(smr2_av->smr2_map->num_peers > 0);

		dlist_foreach(&util_av->ep_list, av_entry) {
			util_ep = container_of(av_entry, struct util_ep, av_entry);
			smr2_ep = container_of(util_ep, struct smr2_ep, util_ep);
			smr2_map_to_endpoint(smr2_ep->region, shm_id);
			smr2_ep->region->max_sar_buf_per_peer =
				SMR2_MAX_PEERS / smr2_av->smr2_map->num_peers;
		}
	}

	if (!(flags & FI_EVENT))
		return succ_count;

	ofi_av_write_event(util_av, succ_count, 0, context);
	return 0;
}

static int smr2_av_remove(struct fid_av *av_fid, fi_addr_t *fi_addr, size_t count,
			 uint64_t flags)
{
	struct util_av *util_av;
	struct util_ep *util_ep;
	struct smr2_av *smr2_av;
	struct smr2_ep *smr2_ep;
	struct dlist_entry *av_entry;
	int i, ret = 0;
	int64_t id;

	util_av = container_of(av_fid, struct util_av, av_fid);
	smr2_av = container_of(util_av, struct smr2_av, util_av);

	ofi_mutex_lock(&util_av->lock);
	for (i = 0; i < count; i++) {
		FI_INFO(&smr2_prov, FI_LOG_AV, "%" PRIu64 "\n", fi_addr[i]);
		id = smr2_addr_lookup(util_av, fi_addr[i]);
		ret = ofi_av_remove_addr(util_av, fi_addr[i]);
		if (ret) {
			FI_WARN(&smr2_prov, FI_LOG_AV,
				"Unable to remove address from AV\n");
			break;
		}

		smr2_map_del(smr2_av->smr2_map, id);
		dlist_foreach(&util_av->ep_list, av_entry) {
			util_ep = container_of(av_entry, struct util_ep, av_entry);
			smr2_ep = container_of(util_ep, struct smr2_ep, util_ep);
			smr2_unmap_from_endpoint(smr2_ep->region, id);
			if (smr2_av->smr2_map->num_peers > 0)
				smr2_ep->region->max_sar_buf_per_peer =
					SMR2_MAX_PEERS /
					smr2_av->smr2_map->num_peers;
			else
				smr2_ep->region->max_sar_buf_per_peer =
					SMR2_BUF_BATCH_MAX;
		}
		smr2_av->used--;
	}

	ofi_mutex_unlock(&util_av->lock);
	return ret;
}

static int smr2_av_lookup(struct fid_av *av, fi_addr_t fi_addr, void *addr,
			 size_t *addrlen)
{
	struct util_av *util_av;
	struct smr2_av *smr2_av;
	int64_t id;
	char *name;

	util_av = container_of(av, struct util_av, av_fid);
	smr2_av = container_of(util_av, struct smr2_av, util_av);

	id = smr2_addr_lookup(util_av, fi_addr);
	name = smr2_av->smr2_map->peers[id].peer.name;

	strncpy((char *) addr, name, *addrlen);

	((char *) addr)[MIN(*addrlen - 1, strlen(name))] = '\0';
	*addrlen = strlen(name) + 1;
	return 0;
}

static const char *smr2_av_straddr(struct fid_av *av, const void *addr,
				  char *buf, size_t *len)
{
	/* the input address is a string format */
	if (buf)
		strncpy(buf, (const char *)addr, *len);

	*len = strlen((const char *)addr) + 1;
	return buf;
}

static struct fi_ops smr2_av_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = smr2_av_close,
	.bind = ofi_av_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_av smr2_av_ops = {
	.size = sizeof(struct fi_ops_av),
	.insert = smr2_av_insert,
	.insertsvc = fi_no_av_insertsvc,
	.insertsym = fi_no_av_insertsym,
	.remove = smr2_av_remove,
	.lookup = smr2_av_lookup,
	.straddr = smr2_av_straddr,
};

int smr2_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
		struct fid_av **av, void *context)
{
	struct util_domain *util_domain;
	struct util_av_attr util_attr;
	struct smr2_av *smr2_av;
	int ret;

	if (!attr) {
		FI_INFO(&smr2_prov, FI_LOG_AV, "invalid attr\n");
		return -FI_EINVAL;
	}

	if (attr->name) {
		FI_INFO(&smr2_prov, FI_LOG_AV, "shared AV not supported\n");
		return -FI_ENOSYS;
	}

	if (attr->type == FI_AV_UNSPEC)
		attr->type = FI_AV_TABLE;

	util_domain = container_of(domain, struct util_domain, domain_fid);

	smr2_av = calloc(1, sizeof *smr2_av);
	if (!smr2_av)
		return -FI_ENOMEM;

	util_attr.addrlen = sizeof(int64_t);
	util_attr.context_len = 0;
	util_attr.flags = 0;
	if (attr->count > SMR2_MAX_PEERS) {
		FI_INFO(&smr2_prov, FI_LOG_AV,
			"count %d exceeds max peers\n", (int) attr->count);
		ret = -FI_ENOSYS;
		goto out;
	}

	ret = ofi_av_init(util_domain, attr, &util_attr, &smr2_av->util_av, context);
	if (ret)
		goto out;

	smr2_av->used = 0;
	*av = &smr2_av->util_av.av_fid;
	(*av)->fid.ops = &smr2_av_fi_ops;
	(*av)->ops = &smr2_av_ops;

	ret = smr2_map_create(&smr2_prov, SMR2_MAX_PEERS,
			     util_domain->info_domain_caps & FI_HMEM ?
			     SMR2_FLAG_HMEM_ENABLED : 0, &smr2_av->smr2_map);
	if (ret)
		goto close;

	return 0;

close:
	ofi_av_close(&smr2_av->util_av);
out:
	free(smr2_av);
	return ret;
}

