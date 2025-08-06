/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/kfuzztest.h>

int __kfuzztest_write_cb_common(struct file *filp, const char __user *buf,
				size_t len, loff_t *off, void *arg,
				size_t arg_size)
{
	if (len != arg_size) {
		return -EINVAL;
	}
	if (simple_write_to_buffer((void *)arg, arg_size, off, buf, len) < 0) {
		return -EFAULT;
	}
	return 0;
}

int __kfuzztest_parse_input(void *input, size_t input_size,
			    struct reloc_region_array **ret_regions,
			    struct reloc_table **ret_reloc_table,
			    void **ret_payload_start, void **ret_payload_end)
{
	pr_info("[ENTER] %s", __FUNCTION__);
	int err;
	void *payload_end, *payload_start;
	size_t reloc_table_size, regions_size;
	struct reloc_table *rt;
	struct reloc_region_array *regions;

	if (input_size <
	    sizeof(struct reloc_region_array) + sizeof(struct reloc_table))
		return -EINVAL;

	payload_end = (char *)input + input_size;

	regions = input;
	regions_size = sizeof(*regions) +
		       regions->num_regions * sizeof(struct reloc_region);

	pr_info("kfuzztest: num regions = %u", regions->num_regions);

	rt = (struct reloc_table *)((char *)regions + regions_size);
	if ((char *)rt > (char *)payload_end) {
		err = -EINVAL;
		goto fail;
	}

	reloc_table_size = sizeof(*rt) +
			   rt->num_entries * sizeof(struct reloc_entry) +
			   rt->payload_offset;
	if ((char *)rt + reloc_table_size > (char *)payload_end) {
		err = -EINVAL;
		goto fail;
	}

	pr_info("kfuzztest: num relocations = %u, size = %zu", rt->num_entries,
		reloc_table_size);

	payload_start = (char *)(rt->entries + rt->num_entries);
	if ((char *)payload_start > (char *)payload_end) {
		err = -EINVAL;
		goto fail;
	}

	pr_info("kfuzztest: payload: [ %px, %px )", payload_start, payload_end);

	*ret_regions = regions;
	*ret_reloc_table = rt;
	*ret_payload_start = payload_start;
	*ret_payload_end = payload_end;
	return 0;
fail:
	kfree(input);
	return err;
}
