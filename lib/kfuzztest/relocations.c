// SPDX-License-Identifier: GPL-2.0
/* Copyright 2025 Google LLC */
#include <linux/kfuzztest.h>
#include <linux/kasan.h>

#define POISON_REGION_END 0xFC

/**
 * Poison the half open interval [start, end], where end should be 8-byte 
 * aligned if it is not, then we cannot guarantee that the whole range will
 * be poisoned.
 *
 * If start is not 8-byte-aligned, the remaining bytes in its 8-byte granule
 * can only be poisoned if CONFIG_KASAN_GENERIC is enabled.
 */
static void kfuzztest_poison_range(void *start, void *end)
{
	uintptr_t end_addr = ALIGN_DOWN((uintptr_t)end, 0x8);
	uintptr_t start_addr = (uintptr_t)start;
	uintptr_t poison_body_start;
	uintptr_t poison_body_end;
	uintptr_t head_granule_start;
	size_t head_prefix_size;

	if (start_addr >= end_addr)
		return;

	head_granule_start = ALIGN_DOWN(start_addr, 0x8);
	head_prefix_size = start_addr - head_granule_start;

	if (IS_ENABLED(CONFIG_KASAN_GENERIC) && head_prefix_size > 0) {
		kasan_poison_last_granule((void *)head_granule_start,
					  head_prefix_size);
		pr_info("kfuzztest: poisoned [%px, %px)",
			(void *)head_granule_start + head_prefix_size,
			(void *)head_granule_start + 8);
	}

	poison_body_start = ALIGN(start_addr, 0x8);
	poison_body_end = ALIGN_DOWN(end_addr, 0x8);

	pr_info("kfuzztest: want to additionally poison [%px, %px)",
		(void *)poison_body_start, (void *)poison_body_end);
	if (poison_body_start < poison_body_end) {
		kasan_poison((void *)poison_body_start,
			     poison_body_end - poison_body_start,
			     POISON_REGION_END, false);

		pr_info("kfuzztest: poisoned [%px, %px)",
			(void *)poison_body_start, (void *)poison_body_end);
	}
}

int __kfuzztest_relocate(struct reloc_region_array *regions,
			 struct reloc_table *rt, void *payload_start,
			 void *payload_end)
{
	size_t i;
	struct reloc_region reg, src, dst;
	uintptr_t *ptr_location;
	struct reloc_entry re;
	void *poison_start, *poison_end;

	/* Patch pointers. */
	for (i = 0; i < rt->num_entries; i++) {
		re = rt->entries[i];

		if (re.region_id >= regions->num_regions)
			return -EINVAL;
		src = regions->regions[re.region_id];

		ptr_location = (uintptr_t *)((char *)payload_start + src.start +
					     re.region_offset);
		if ((char *)ptr_location >= (char *)payload_end)
			return -EINVAL;
		if (src.start >= src.size)
			return -EINVAL;

		if (re.value == KFUZZTEST_REGIONID_NULL) {
			*ptr_location = (uintptr_t)NULL;
		} else if (re.value < regions->num_regions) {
			dst = regions->regions[re.value];
			*ptr_location =
				(uintptr_t)((char *)payload_start + dst.start);
		} else {
			return -EINVAL;
		}
	}

	/* Poison the padding between regions. */
	for (i = 0; i < regions->num_regions; i++) {
		reg = regions->regions[i];

		/* Points to the beginning of the inter-region padding */
		poison_start = payload_start + reg.start + reg.size;
		if (i < regions->num_regions - 1) {
			poison_end =
				payload_start + regions->regions[i + 1].start;
		} else {
			poison_end = poison_start + 8;
		}

		if ((char *)poison_end > (char *)payload_end)
			return -EINVAL;

		kfuzztest_poison_range(poison_start, poison_end);
	}
	return 0;
}
