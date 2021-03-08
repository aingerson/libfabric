/*
 * Copyright (c) 2021 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL); Version 2, available from the file
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

#ifndef _HOOK_ZE_H_
#define _HOOK_ZE_H_

#include <level_zero/ze_api.h>

#include "ofi_hook.h"
#include "ofi.h"
#include "ofi_util.h"
#include "ofi_mr.h"

//TODO pass this in getinfo and adjust?
#define HOOK_ZE_IOV_LIMIT	4

struct hook_ze_domain {
	struct hook_domain	hook_domain;
	int			mr_mode;
	struct ofi_bufpool	*mr_pool;
	struct ofi_rbmap	rbmap;
	struct dlist_entry	mr_list;
};

struct hook_ze_desc {
	struct fid_mr		*mr_fid;
	void			*desc;
	struct iovec		iov;
	enum fi_hmem_iface	iface;
	struct dlist_entry	entry;
	uint64_t		device;
	uint64_t		flags;
};

#endif /* _HOOK_ZE_H_ */
