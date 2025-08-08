// SPDX-License-Identifier: GPL-2.0
/*
 * KFuzzTest input relocation and memory poisoning.
 *
 * Copyright 2025 Google LLC
 */
#include <linux/kasan.h>
#include <linux/kfuzztest.h>

#ifdef CONFIG_KASAN

/**
 * kfuzztest_poison_range - poison the memory range [start, end)
 *
 * The exact behavior is subject to alignment with KASAN's 8-byte granule size:
 *
 * - If @start is unaligned, the initial partial granule at the beginning
 *	of the range is only poisoned if CONFIG_KASAN_GENERIC is enabled.
 * - The poisoning of the range only extends up to the last full granule
 *	before @end. Any remaining bytes in a final partial granule are ignored.
 */
static void kfuzztest_poison_range(void *start, void *end)
{
	uintptr_t end_addr = ALIGN_DOWN((uintptr_t)end, __KASAN_GRANULE_SIZE);
	uintptr_t start_addr = (uintptr_t)start;
	uintptr_t head_granule_start;
	uintptr_t poison_body_start;
	uintptr_t poison_body_end;
	size_t head_prefix_size;

	if (start_addr >= end_addr)
		return;

	head_granule_start = ALIGN_DOWN(start_addr, __KASAN_GRANULE_SIZE);
	head_prefix_size = start_addr - head_granule_start;

	if (IS_ENABLED(CONFIG_KASAN_GENERIC) && head_prefix_size > 0)
		kasan_poison_last_granule((void *)head_granule_start,
					  head_prefix_size);

	poison_body_start = ALIGN(start_addr, __KASAN_GRANULE_SIZE);
	poison_body_end = ALIGN_DOWN(end_addr, __KASAN_GRANULE_SIZE);

	if (poison_body_start < poison_body_end)
		kasan_poison((void *)poison_body_start,
			     poison_body_end - poison_body_start,
			     __KASAN_SLAB_REDZONE, false);
}

#else /* CONFIG_KASAN */

static inline void kfuzztest_poison_range(void *, void *) {}

#endif /* CONFIG_KASAN */

int __kfuzztest_relocate(struct reloc_region_array *regions,
			 struct reloc_table *rt, void *payload_start,
			 void *payload_end)
{
	struct reloc_region reg, src, dst;
	void *poison_start, *poison_end;
	uintptr_t *ptr_location;
	struct reloc_entry re;
	size_t i;

	/* Patch pointers. */
	for (i = 0; i < rt->num_entries; i++) {
		re = rt->entries[i];
		src = regions->regions[re.region_id];
		ptr_location = (uintptr_t *)((char *)payload_start +
					     src.offset + re.region_offset);
		if (re.value == KFUZZTEST_REGIONID_NULL)
			*ptr_location = (uintptr_t)NULL;
		else if (re.value < regions->num_regions) {
			dst = regions->regions[re.value];
			*ptr_location =
				(uintptr_t)((char *)payload_start + dst.offset);
		} else
			return -EINVAL;
	}

	/* Poison the padding between regions. */
	for (i = 0; i < regions->num_regions; i++) {
		reg = regions->regions[i];

		/* Points to the beginning of the inter-region padding */
		poison_start = payload_start + reg.offset + reg.size;
		if (i < regions->num_regions - 1)
			poison_end =
				payload_start + regions->regions[i + 1].offset;
		else
			poison_end = payload_end;

		if ((char *)poison_end > (char *)payload_end)
			return -EINVAL;

		kfuzztest_poison_range(poison_start, poison_end);
	}

	/* Poison the padded area preceding the payload. */
	kfuzztest_poison_range((char *)payload_start - rt->padding_size,
			       payload_start);
	return 0;
}
