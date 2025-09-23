/*
 * Copyright (c) 2016-2021 Intel Corporation. All rights reserved.
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

#ifndef _OFI_SHM_H_
#define _OFI_SHM_H_

#include "config.h"

#include <stdint.h>
#include <stddef.h>
#include <sys/un.h>

#include <ofi_xpmem.h>
#include <ofi_atom.h>
#include <ofi_proto.h>
#include <ofi_mem.h>
#include <ofi_rbuf.h>
#include <ofi_tree.h>
#include <ofi_hmem.h>
#include <ofi_atomic_queue.h>

#include <rdma/providers/fi_prov.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SMR_VERSION	8

#define SMR_FLAG_ATOMIC	(1 << 0)
#define SMR_FLAG_DEBUG	(1 << 1)
#define SMR_FLAG_IPC_SOCK (1 << 2)
#define SMR_FLAG_HMEM_ENABLED (1 << 3)

#define SMR_CMD_SIZE		400	/* align with 64-byte cache line */

/* SMR op_src: Specifies data source location */
enum {
	smr_src_inline,	/* command data */
	smr_src_inject,	/* inject buffers */
	smr_src_iov,	/* reference iovec via CMA */
	smr_src_mmap,	/* mmap-based fallback protocol */
	smr_src_sar,	/* segmentation fallback protocol */
	smr_src_ipc,	/* device IPC handle protocol */
	smr_src_max,
};

//reserves 0-255 for defined ops and room for new ops
//256 and beyond reserved for ctrl ops
#define SMR_OP_MAX (1 << 8)

#define SMR_REMOTE_CQ_DATA	(1 << 0)
#define SMR_RMA_REQ		(1 << 1)
#define SMR_TX_COMPLETION	(1 << 2)
#define SMR_RX_COMPLETION	(1 << 3)
#define SMR_MULTI_RECV		(1 << 4)

/* CMA/XPMEM capability. Generic acronym used:
 * VMA: Virtual Memory Address */
enum {
	SMR_VMA_CAP_NA,
	SMR_VMA_CAP_ON,
	SMR_VMA_CAP_OFF,
};

/*
 * Unique smr_op_hdr for smr message protocol:
 *	tx_ctx - source side context (unused by target side)
 *	rx_ctx - target side context (unused by source side)
 * 	id - local shm_id of peer sending msg (for shm lookup)
 * 	op - type of op (ex. ofi_op_msg, defined in ofi_proto.h)
 * 	proto - msg src (ex. smr_src_inline, defined above)
 * 	op_flags - operation flags (ex. SMR_REMOTE_CQ_DATA, defined above)
 * 	proto_data - src of additional op data (inject offset / resp offset)
 * 	cq_data - remote CQ data
 */
struct smr_cmd_hdr {
	uint64_t		tx_ctx;
	uint64_t		rx_ctx;
	int64_t			id;
	uint32_t		op;
	uint16_t		proto;
	uint16_t		op_flags;

	uint64_t		size;
	uint64_t		proto_data;
	uint64_t		status;
	uint64_t		cq_data;
	union {
		uint64_t	tag;
		struct {
			uint8_t	datatype;
			uint8_t	atomic_op;
		};
	};
} __attribute__ ((aligned(16)));

#define SMR_BUF_BATCH_MAX	64
#define SMR_MSG_DATA_LEN	(SMR_CMD_SIZE - (sizeof(struct smr_cmd_hdr) + sizeof(struct smr_cmd_rma)))
#define SMR_IOV_LIMIT		4

struct smr_cmd_rma {
	uint64_t		rma_count;
	union {
		struct fi_rma_iov	rma_iov[SMR_IOV_LIMIT];
		struct fi_rma_ioc	rma_ioc[SMR_IOV_LIMIT];
	};
};

struct smr_cmd_data {
	union {
		uint8_t			msg[SMR_MSG_DATA_LEN];
		struct {
			size_t		iov_count;
			struct iovec	iov[SMR_IOV_LIMIT];
		};
		struct {
			uint32_t	buf_batch_size;
			int16_t		sar[SMR_BUF_BATCH_MAX];
		};
		struct ipc_info		ipc_info;
	};
};
STATIC_ASSERT(sizeof(struct smr_cmd_data) == SMR_MSG_DATA_LEN, smr_cmd_size);

#define SMR_RMA_DATA_LEN	(128 - sizeof(uint64_t))

struct smr_cmd { //176 bytes needed for hdr and rma - data needs to be at least 132 bytes for ipc info (176 + 132 = 308 -> minimum cmd size)
	struct smr_cmd_hdr	hdr; //72
	struct smr_cmd_data	data;
	 /* TODO experiment with moving rma up */
	struct smr_cmd_rma	rma; //104
};


#define SMR_INJECT_SIZE		4096
#define SMR_COMP_INJECT_SIZE	(SMR_INJECT_SIZE / 2)
#define SMR_SAR_SIZE		32768

#define SMR_DIR "/dev/shm/"
#define SMR_NAME_MAX	256
#define SMR_PATH_MAX	(SMR_NAME_MAX + sizeof(SMR_DIR))
#define SMR_SOCK_NAME_MAX sizeof(((struct sockaddr_un *)0)->sun_path)

/* On next version update remove this struct to make id a bool in the smr_peer
 * remove name from smr_peer_data because it is unused.
 */
struct smr_addr {
	char		name[SMR_NAME_MAX];
	int64_t		id;
};

struct smr_peer_data {
	struct smr_addr		addr;
	uint32_t		sar_status;
	uint16_t		name_sent;
	uint16_t		ipc_valid;
	uintptr_t		local_region;
	struct ofi_xpmem_client xpmem;
};

extern struct dlist_entry ep_name_list;
extern pthread_mutex_t ep_list_lock;
extern struct dlist_entry sock_name_list;
extern pthread_mutex_t sock_list_lock;

struct smr_region;

struct smr_ep_name {
	char name[SMR_NAME_MAX];
	struct smr_region *region;
	struct dlist_entry entry;
};

static inline const char *smr_no_prefix(const char *addr)
{
	char *start;

	return (start = strstr(addr, "://")) ? start + 3 : addr;
}

struct smr_peer {
	struct smr_addr		peer;
	fi_addr_t		fiaddr;
	struct smr_region	*region;
	int			pid_fd;
};

#define SMR_MAX_PEERS	256

struct smr_map {
	ofi_spin_t		lock;
	int64_t			cur_id;
	int 			num_peers;
	uint16_t		flags;
	struct ofi_rbmap	rbmap;
	struct smr_peer		peers[SMR_MAX_PEERS];
};

struct smr_region {
	uint8_t		version;
	uint8_t		resv;
	uint16_t	flags;
	int		pid;
	uint8_t		cma_cap_peer;
	uint8_t		cma_cap_self;
	uint8_t		xpmem_cap_self;
	uint8_t		resv2;

	uint32_t	max_sar_buf_per_peer;
	struct ofi_xpmem_pinfo	xpmem_self;
	struct ofi_xpmem_pinfo	xpmem_peer;
	void		*base_addr;
	pthread_spinlock_t	lock; /* lock for shm access
				 if both ep->tx_lock and this lock need to
				 held, then ep->tx_lock needs to be held
				 first */

	struct smr_map	*map;

	size_t		total_size;

	/* offsets from start of smr_region */
	size_t		cmd_queue_offset;
	size_t		cmd_stack_offset;
	size_t		inject_pool_offset;
	size_t		ret_queue_offset;
	size_t		sar_pool_offset;
	size_t		peer_data_offset;
	size_t		name_offset;
	size_t		sock_name_offset;
};

struct smr_inject_buf {
	union {
		uint8_t		data[SMR_INJECT_SIZE];
		struct {
			uint8_t	buf[SMR_COMP_INJECT_SIZE];
			uint8_t comp[SMR_COMP_INJECT_SIZE];
		};
	};
};

enum smr_status {
	SMR_STATUS_SUCCESS = 0, 	/* success*/
	SMR_STATUS_BUSY = FI_EBUSY, 	/* busy */

	SMR_STATUS_OFFSET = 1024, 	/* Beginning of shm-specific codes */
	SMR_STATUS_SAR_EMPTY, 	/* buffer can be written into */
	SMR_STATUS_SAR_FULL, 	/* buffer can be read from */
};

struct smr_sar_buf {
	uint8_t		buf[SMR_SAR_SIZE];
};

/* TODO it is expected that a future patch will expand the smr_cmd
 * structure to also include the rma information, thereby removing the
 * need to have two commands in the cmd_entry. We can also remove the
 * command entry completely and just use the smr_cmd
 */
struct smr_cmd_entry {
	uintptr_t ptr; //cast into smr_cmd *
	struct smr_cmd cmd; //inline command
};

//temporary wrapper until I get it right
struct smr_return_entry {
	uintptr_t ptr;
};

/* Queue of offsets of the command blocks obtained from the command pool
 * freestack
 */
OFI_DECLARE_ATOMIC_Q(struct smr_cmd_entry, smr_cmd_queue);
OFI_DECLARE_ATOMIC_Q(struct smr_return_entry, smr_return_queue);

static inline struct smr_region *smr_peer_region(struct smr_region *smr, int i)
{
	return smr->map->peers[i].region;
}
static inline struct smr_cmd_queue *smr_cmd_queue(struct smr_region *smr)
{
	return (struct smr_cmd_queue *) ((char *) smr + smr->cmd_queue_offset);
}
static inline struct smr_freestack *smr_cmd_stack(struct smr_region *smr)
{
	return (struct smr_freestack *) ((char *) smr + smr->cmd_stack_offset);
}
static inline struct smr_freestack *smr_inject_pool(struct smr_region *smr)
{
	return (struct smr_freestack *) ((char *) smr + smr->inject_pool_offset);
}
static inline struct smr_return_queue *smr_return_queue(struct smr_region *smr)
{
	return (struct smr_return_queue *) ((char *) smr + smr->ret_queue_offset);
}
static inline struct smr_peer_data *smr_peer_data(struct smr_region *smr)
{
	return (struct smr_peer_data *) ((char *) smr + smr->peer_data_offset);
}
static inline struct smr_freestack *smr_sar_pool(struct smr_region *smr)
{
	return (struct smr_freestack *) ((char *) smr + smr->sar_pool_offset);
}
static inline const char *smr_name(struct smr_region *smr)
{
	return (const char *) smr + smr->name_offset;
}

static inline char *smr_sock_name(struct smr_region *smr)
{
	return (char *) smr + smr->sock_name_offset;
}

static inline void smr_set_map(struct smr_region *smr, struct smr_map *map)
{
	smr->map = map;
}

struct smr_attr {
	const char	*name;
	size_t		rx_count;
	size_t		tx_count;
	uint16_t	flags;
};
size_t smr_calculate_size_offsets(size_t tx_count, size_t rx_count,
				  size_t *cmd_offset, size_t *cs_offset,
				  size_t *inject_offset, size_t *rq_offset,
				  size_t *sar_offset,
				  size_t *peer_offset, size_t *name_offset,
				  size_t *sock_offset);
void	smr_cma_check(struct smr_region *region, struct smr_region *peer_region);
void	smr_cleanup(void);
int	smr_map_to_region(const struct fi_provider *prov, struct smr_map *map,
			  int64_t id);
void	smr_map_to_endpoint(struct smr_region *region, int64_t id);
void	smr_unmap_region(const struct fi_provider *prov, struct smr_map *map,
			  int64_t id, bool found);
void	smr_unmap_from_endpoint(struct smr_region *region, int64_t id);
void	smr_exchange_all_peers(struct smr_region *region);
int	smr_map_add(const struct fi_provider *prov, struct smr_map *map,
		    const char *name, int64_t *id);
void	smr_map_del(struct smr_map *map, int64_t id);

struct smr_region *smr_map_get(struct smr_map *map, int64_t id);

int	smr_create(const struct fi_provider *prov, struct smr_map *map,
		   const struct smr_attr *attr, struct smr_region *volatile *smr);
void	smr_free(struct smr_region *smr);

//local cmd in peer space
static inline uintptr_t smr_get_peer_ptr(struct smr_region *my_smr,
			int64_t id, int64_t peer_id,
			uintptr_t local_ptr)
{
	struct smr_region *peer_smr = smr_peer_region(my_smr, id);
	uint64_t offset = local_ptr - (uintptr_t) my_smr;
	return smr_peer_data(peer_smr)[peer_id].local_region + offset;
}

//peer cmd in peer space
static inline uintptr_t smr_get_owner_ptr(struct smr_region *my_smr,
			int64_t id, uintptr_t local_ptr)
{
	struct smr_region *peer_smr = smr_peer_region(my_smr, id);
	uint64_t offset = local_ptr - (uintptr_t) peer_smr;
	return (uintptr_t) peer_smr->base_addr + offset;
}

static inline void smr_return_cmd(struct smr_region *my_smr,
				  struct smr_cmd *cmd)
{
	struct smr_region *peer_smr = smr_peer_region(my_smr, cmd->hdr.id);
	uintptr_t peer_ptr = smr_get_owner_ptr(my_smr, cmd->hdr.id, (uintptr_t) cmd);
	struct smr_return_entry *queue_entry;
	int64_t pos;
	int ret;

	ret = smr_return_queue_next(smr_return_queue(peer_smr), &queue_entry, &pos);
	if (ret == -FI_ENOENT) {
		assert(0);
		//this shouldn't happen (ret queue parallel to fs)
	}

	queue_entry->ptr = peer_ptr;

	smr_return_queue_commit(queue_entry, pos);
}

#ifdef __cplusplus
}
#endif

#endif /* _OFI_SHM_H_ */
