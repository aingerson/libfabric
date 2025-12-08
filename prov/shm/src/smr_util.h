/*
 * Copyright (c) Intel Corporation. All rights reserved.
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

#ifndef _SMR_UTIL_H_
#define _SMR_UTIL_H_

#include "ofi.h"
#include "ofi_atomic_queue.h"
#include "ofi_xpmem.h"

#ifdef __cplusplus
extern "C" {
#endif
#define SMR_VERSION	9

#define SMR_FLAG_HMEM_ENABLED	(1 << 0)
#define SMR_FLAG_CMA_INIT	(1 << 1)
#define SMR_FLAG_XPMEM_ENABLED	(1 << 2)

/* SMR_CMD_SIZE refers to the total bytes dedicated for use in shm headers and
 * data. The entire atomic queue entry will be cache aligned (512) but this also
 * includes the cmd aq header (16) + cmd entry ptr (8)
 * 512 (total entry size) - 16 (aq header) - 8 (entry ptr) = 488
 * This maximizes the inline payload. Increasing this value will increase the
 * atomic queue entry to 576 bytes.
 */
#define SMR_CMD_SIZE		488

/* reserves 0-255 for defined ops and room for new ops
 * 256 and beyond reserved for ctrl ops
 */
#define SMR_OP_MAX (1 << 6)

#define SMR_REMOTE_CQ_DATA	(1 << 0)
#define SMR_RMA_REQ		(1 << 1)
#define SMR_TX_COMPLETION	(1 << 2)
#define SMR_RX_COMPLETION	(1 << 3)
#define SMR_MULTI_RECV		(1 << 4)

enum {
	smr_proto_inline,	/* inline payload */
	smr_proto_inject,	/* inject buffers */
	smr_proto_iov,		/* iovec copy via CMA or xpmem */
	smr_proto_sar,		/* segmentation fallback */
	smr_proto_ipc,		/* device IPC handle */
	smr_proto_max,
};

/*
 * Unique smr_cmd_hdr for smr message protocol:
 *	entry		for internal use managing commands (must be kept first)
 *	tx_ctx		source side context (unused by target side)
 *	rx_ctx		target side context (unused by source side)
 * 	tx_id		local shm_id of peer sending msg (unused by target)
 *	rx_id		remote shm_id of peer sending msg (unused by source)
 * 	op		type of op (ex. ofi_op_msg, defined in ofi_proto.h)
 * 	proto		smr protocol (ex. smr_proto_inline, defined above)
 * 	op_flags	operation flags (ex. SMR_REMOTE_CQ_DATA, defined above)
 * 	size		size of data transfer
 * 	status		returned status of operation
 * 	cq_data		remote CQ data
 * 	tag		tag for FI_TAGGED API only
 * 	datatype	atomic datatype for FI_ATOMIC API only
 * 	atomic_op	atomic operation for FI_ATOMIC API only
 */
struct smr_cmd_hdr {
	uint64_t		entry;
	uint64_t		tx_ctx;
	uint64_t		rx_ctx;
	uint64_t		size;
	int64_t			status;
	uint64_t		cq_data;
	union {
		uint64_t	tag;
		struct {
			uint8_t	datatype;
			uint8_t	atomic_op;
		};
	};
	int16_t			rx_id;
	int16_t			tx_id;
	uint8_t			op;
	uint8_t			proto;
	uint8_t			op_flags;
	uint8_t			resv[1];
};

#ifdef static_assert
static_assert(sizeof(struct smr_cmd_hdr) == 64,
	      "Command header must be 64 bytes to maximize cache performance");
#endif

#define SMR_BUF_BATCH_MAX	64
#define SMR_MSG_DATA_LEN	(SMR_CMD_SIZE - \
				 (sizeof(struct smr_cmd_hdr) + \
				  sizeof(struct smr_cmd_rma)))
#define SMR_IOV_LIMIT		4

struct smr_cmd_rma {
	uint64_t			rma_count;
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

#ifdef static_assert
static_assert(sizeof(struct smr_cmd_data) == SMR_MSG_DATA_LEN,
	      "Unexpected element in smr_cmd_data union");
#endif

struct smr_cmd {
	struct smr_cmd_hdr	hdr;
	struct smr_cmd_data	data;
	struct smr_cmd_rma	rma;
};

#ifdef static_assert
static_assert(sizeof(struct smr_cmd) == SMR_CMD_SIZE,
	      "smr_cmd is not the expected size; please check your cmd fields");
#endif

#define SMR_INJECT_SIZE		4096
#define SMR_COMP_INJECT_SIZE	(SMR_INJECT_SIZE / 2)
#define SMR_SAR_SIZE		32768

#define SMR_DIR "/dev/shm/"
#define SMR_NAME_MAX	256
#define SMR_PATH_MAX	(SMR_NAME_MAX + sizeof(SMR_DIR))

/* On next version update remove this struct to make id a bool in the smr_peer
 * remove name from smr_peer_data because it is unused.
 */
struct smr_addr {
	char		name[SMR_NAME_MAX];
	int64_t		id;
};

struct smr_peer_data {
	int64_t			id;
	uint32_t		sar_status;
	uint16_t		name_sent;
	uint16_t		ipc_valid;
	uintptr_t		local_region;
	struct ofi_xpmem_client xpmem;
} __attribute__ ((aligned(64)));

extern struct dlist_entry ep_name_list;
extern pthread_mutex_t ep_list_lock;

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
	char			name[SMR_NAME_MAX];
	bool			id_assigned;
	fi_addr_t		fiaddr;
	struct smr_region	*region;
	int			pid_fd;
};

#define SMR_MAX_PEERS	256

struct smr_region {
	uint8_t			version;
	uint8_t			resv;
	uint16_t		flags;
	uint8_t			self_vma_caps;
	uint8_t			peer_vma_caps;

	uint16_t		max_sar_buf_per_peer;
	struct ofi_xpmem_pinfo	xpmem_self;
	struct ofi_xpmem_pinfo	xpmem_peer;

	int			pid;
	int			resv2;

	uintptr_t		base_addr;
	pthread_spinlock_t	lock; /* lock for shm access
				 if both ep->tx_lock and this lock need to
				 held, then ep->tx_lock needs to be held
				 first */

	size_t		total_size;

	/* offsets from start of smr_region */
	size_t		cmd_queue_offset;
	size_t		resp_queue_offset;
	size_t		inject_pool_offset;
	size_t		sar_pool_offset;
	size_t		peer_data_offset;
	size_t		name_offset;
};

static inline void smr_set_vma_cap(uint8_t *vma_cap, uint8_t type, bool avail)
{
	(*vma_cap) &= ~(1 << type);
	(*vma_cap) |= (uint8_t) avail << type;
}

static inline uint8_t smr_get_vma_cap(uint8_t vma_cap, uint8_t type)
{
	return vma_cap & (1 << type);
}


struct smr_resp {
	uint64_t	msg_id;
	uint64_t	status;
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
	struct smr_cmd cmd;
	struct smr_cmd rma_cmd;
};

/* Queue of offsets of the command blocks obtained from the command pool
 * freestack
 */
OFI_DECLARE_CIRQUE(struct smr_resp, smr_resp_queue);
OFI_DECLARE_ATOMIC_Q(struct smr_cmd_entry, smr_cmd_queue);

static inline struct smr_cmd_queue *smr_cmd_queue(struct smr_region *smr)
{
	return (struct smr_cmd_queue *) ((char *) smr + smr->cmd_queue_offset);
}
static inline struct smr_resp_queue *smr_resp_queue(struct smr_region *smr)
{
	return (struct smr_resp_queue *) ((char *) smr + smr->resp_queue_offset);
}
static inline struct smr_freestack *smr_inject_pool(struct smr_region *smr)
{
	return (struct smr_freestack *) ((char *) smr + smr->inject_pool_offset);
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

struct smr_attr {
	const char	*name;
	size_t		rx_count;
	size_t		tx_count;
	uint16_t	flags;
};

size_t smr_calculate_size_offsets(size_t tx_count, size_t rx_count,
				  size_t *cmd_offset, size_t *resp_offset,
				  size_t *inject_offset, size_t *sar_offset,
				  size_t *peer_offset, size_t *name_offset);
void	smr_cma_check(struct smr_region *region, struct smr_region *peer_region);
void	smr_cleanup(void);
int	smr_create(const struct fi_provider *prov,
		   const struct smr_attr *attr, struct smr_region *volatile *smr);
void	smr_free(struct smr_region *smr);

#ifdef __cplusplus
}
#endif

#endif /* _SMR_UTIL_H_ */
