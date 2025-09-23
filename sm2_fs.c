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

#ifndef _SMR_STACK_H_
#define _SMR_STACK_H_

#include "ofi.h"
#include "smr_atom.h"

#define SMR_FS_ALIGN_BOUNDARY	16
#define CACHE_LINE_SIZE (64)

struct smr_fs_entry {
	uintptr_t	next;
};

struct smr_fs {
	uint64_t		entry_base_offset;
	uintptr_t		owner_base;
	size_t			object_size;
	size_t			size;
	int16_t			free;
	int16_t			top;
	int16_t 		entry_next[];
} __attribute__ ((aligned(CACHE_LINE_SIZE)));

static inline long smr_stack_size(int elem_size, int num_elements)
{
	return (sizeof(struct smr_fs) + sizeof(uintptr_t) * num_elements +
			elem_size * num_elements);
}

static inline uintptr_t smr_fs_peer_to_owner_ptr(struct smr_fs *fs,
		struct smr_fs_entry *entry)
{
	return (uintptr_t) fs->owner_base + ((uintptr_t) entry - (uintptr_t) fs);
}

static inline uintptr_t smr_fs_owner_to_peer_ptr(struct smr_fs *fs,
		struct smr_fs_entry *entry)
{
	return (uintptr_t) fs + ((uintptr_t) entry - (uintptr_t) fs->owner_base);
}

/* Push by entry_offset */
static inline void smr_fs_push_by_offset(struct smr_fs *fs,
		uint64_t entry_offset)
{
	struct smr_fs_entry *local_entry = (struct smr_fs_entry *) entry;
	struct smr_fs_entry *owner_entry = (struct smr_fs_entry *)
				smr_fs_peer_to_owner_ptr(fs, local_entry);
	struct smr_fs_entry *prev_local_entry;
	struct smr_fs_entry *prev_owner_entry;

	assert(owner_entry);
	local_entry->next = 0;

	atomic_wmb();
	prev_owner_entry = (struct smr_fs_entry *)
				atomic_swap_ptr(&fs->tail,
						(uintptr_t) owner_entry);
	atomic_rmb();

	assert(prev_owner_entry != owner_entry);

	if (prev_owner_entry) {
		prev_local_entry = (struct smr_fs_entry *)
				smr_fs_owner_to_peer_ptr(fs, prev_owner_entry);
		prev_local_entry->next = (uintptr_t) owner_entry;
	} else {
		fs->head = (uintptr_t) owner_entry;
	}

	atomic_wmb();
}

/* Push by object */
static inline void smr_fs_push(struct smr_fs *fs, uintptr_t local_p)
{
        smr_fs_push_by_offset(fs,
                ((char *) local_p - (char*) fs));
}

static inline void smr_fs_init(struct smr_fs *fs, size_t elem_count,
		size_t fs_object_size)
{
	ssize_t i, next_aligned_addr;
	assert(elem_count == roundup_power_of_two(elem_count));
	fs->size = elem_count;
	fs->free = 0;
	fs->object_size = fs_object_size;
	fs->top = -1;
	fs->owner_base = (uintptr_t) fs;
	fs->entry_base_offset =
		((char*) &fs->entry_next[0] - (char*) fs) +
		fs->size * sizeof(fs->top);
	next_aligned_addr = ofi_get_aligned_size((( (uint64_t) fs) +
			fs->entry_base_offset), SMR_FS_ALIGN_BOUNDARY);
	fs->entry_base_offset = next_aligned_addr - ((uint64_t) fs);
	for (i = elem_count - 1; i >= 0; i--)
		smr_fs_push_by_index(fs, i);
}

static inline int smr_fs_pop_by_index(struct smr_fs *fs)
{
	struct smr_fs_entry *entry, *prev_head;

	if (!fs->head)
		return 0;

	atomic_rmb();

	prev_head = (struct smr_fs_entry *) fs->head;
	entry = (struct smr_fs_entry *) smr_fs_owner_to_peer_ptr(fs, prev_head);
	fs->head = 0;

	assert(entry->next != (uintptr_t) prev_head && entry && entry->next);

	if (!entry->next) {
		atomic_rmb();
		if (!atomic_compare_exchange(&fs->tail, (uintptr_t *) &prev_head,
					     0)) {
			while (!entry->next)
				atomic_rmb();
			fs->head = entry->next;
		}
	} else {
		fs->head = entry->next;
	}
}

static inline size_t smr_fs_pop_by_offset(struct smr_fs *fs)
{
	return (size_t) (fs->entry_base_offset +
		smr_fs_pop_by_index(fs) * fs->object_size);
}

static inline void* smr_fs_pop(struct smr_fs *fs)
{
	return (void *) ( ((char*)fs) + smr_fs_pop_by_offset(fs) );
}
#endif // _SMR_STACK_H_