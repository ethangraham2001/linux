/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2025 Google LLC */
#include <linux/kfuzztest.h>

int __kfuzztest_write_cb_common(struct file *filp, const char __user *buf,
				size_t len, loff_t *off, void *arg,
				size_t arg_size)
{
	if (len != arg_size)
		return -EINVAL;
	if (simple_write_to_buffer((void *)arg, arg_size, off, buf, len) < 0)
		return -EFAULT;
	return 0;
}

static bool __kfuzztest_input_is_valid(struct reloc_region_array *regions,
				       struct reloc_table *rt,
				       void *payload_start, void *payload_end)
{
	size_t payload_size = (char *)payload_end - (char *)payload_start;
	size_t usable_payload_size;
	uint32_t region_end_offset;
	struct reloc_entry reloc;
	struct reloc_region reg;
	uint32_t i;

	if ((char *)payload_start > (char *)payload_end)
		return false;
	if (payload_size < KFUZZTEST_TAIL_POISON_SIZE)
		return false;
	usable_payload_size = payload_size - KFUZZTEST_TAIL_POISON_SIZE;

	for (i = 0; i < regions->num_regions; i++) {
		reg = regions->regions[i];
		if (check_add_overflow(reg.offset, reg.size,
				       &region_end_offset))
			return false;
		if ((size_t)region_end_offset > usable_payload_size)
			return false;
	}

	for (i = 0; i < rt->num_entries; i++) {
		reloc = rt->entries[i];
		if (reloc.region_id >= regions->num_regions)
			return false;
		if (reloc.value != KFUZZTEST_REGIONID_NULL &&
		    reloc.value >= regions->num_regions)
			return false;

		reg = regions->regions[reloc.region_id];
		if (reloc.region_offset % (sizeof(uintptr_t)) ||
		    reloc.region_offset + sizeof(uintptr_t) > reg.size)
			return false;
	}

	return true;
}

int __kfuzztest_parse_input(void *input, size_t input_size,
			    struct reloc_region_array **ret_regions,
			    struct reloc_table **ret_reloc_table,
			    void **ret_payload_start, void **ret_payload_end)
{
	size_t reloc_entries_size, reloc_regions_size;
	size_t reloc_table_size, regions_size;
	struct reloc_region_array *regions;
	void *payload_end, *payload_start;
	struct reloc_table *rt;
	size_t curr_offset = 0;

	if (input_size <
	    sizeof(struct reloc_region_array) + sizeof(struct reloc_table))
		return -EINVAL;

	regions = input;
	if (check_mul_overflow(regions->num_regions,
			       sizeof(struct reloc_region),
			       &reloc_regions_size))
		return -EINVAL;
	if (check_add_overflow(sizeof(*regions), reloc_regions_size,
			       &regions_size))
		return -EINVAL;

	curr_offset = regions_size;
	if (curr_offset > input_size)
		return -EINVAL;
	if (input_size - curr_offset < sizeof(struct reloc_table))
		return -EINVAL;

	rt = (struct reloc_table *)((char *)input + curr_offset);

	if (check_mul_overflow((size_t)rt->num_entries,
			       sizeof(struct reloc_entry), &reloc_entries_size))
		return -EINVAL;
	if (check_add_overflow(sizeof(*rt), reloc_entries_size,
			       &reloc_table_size))
		return -EINVAL;
	if (check_add_overflow(reloc_table_size, rt->payload_offset,
			       &reloc_table_size))
		return -EINVAL;

	if (check_add_overflow(curr_offset, reloc_table_size, &curr_offset))
		return -EINVAL;
	if (curr_offset > input_size)
		return -EINVAL;

	payload_start = (char *)input + curr_offset;
	payload_end = (char *)input + input_size;

	if (!__kfuzztest_input_is_valid(regions, rt, payload_start,
					payload_end))
		return -EINVAL;

	*ret_regions = regions;
	*ret_reloc_table = rt;
	*ret_payload_start = payload_start;
	*ret_payload_end = payload_end;
	return 0;
}
