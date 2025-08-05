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
static void __kfuzztest_poison_range(void *start, void *end)
{
	uintptr_t start_addr = (uintptr_t)start;
	uintptr_t end_addr = ALIGN_DOWN((uintptr_t)end, 0x8);

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

reloc_handle_t __kfuzztest_relocate(struct reloc_region_array *regions,
				    struct reloc_table *rt, void *payload_start,
				    void *payload_end, void **data_ret)
{
	pr_info("[ENTER] %s", __FUNCTION__);
	size_t i;
	struct reloc_region reg, src, dst;
	uintptr_t *ptr_location;
	struct reloc_entry re;
	void *poison_start, *poison_end;

	pr_info("kfuzztest: %d regions, %d relocations", regions->num_regions,
		rt->num_entries);

	pr_info("kfuzztest: regions = %px, rt = %px, payload_start = %px, payload_end = %px",
		regions, rt, payload_start, payload_end);

	/* Patch pointers. */
	for (i = 0; i < rt->num_entries; i++) {
		re = rt->entries[i];

		if (re.region_id >= regions->num_regions)
			goto fail;
		src = regions->regions[re.region_id];

		ptr_location = (uintptr_t *)((char *)payload_start + src.start +
					     re.region_offset);
		if ((char *)ptr_location >= (char *)payload_end)
			goto fail;
		if (src.start >= src.size)
			goto fail;

		if (re.value == KFUZZTEST_REGIONID_NULL) {
			pr_info("%px = NULL", ptr_location);
			*ptr_location = (uintptr_t)NULL;
		} else {
			if (re.value >= regions->num_regions)
				goto fail;
			dst = regions->regions[re.value];
			*ptr_location =
				(uintptr_t)((char *)payload_start + dst.start);
			pr_info("%px -> %px", ptr_location,
				(void *)*ptr_location);
		}
	}

	/* Poison the padding between regions. */
	for (i = 0; i < regions->num_regions; i++) {
		reg = regions->regions[i];

		pr_info("kfuzztest: region %zu [%px, %px) (size = %u)", i,
			payload_start + reg.start,
			payload_start + reg.start + reg.size, reg.size);
		/* Points to the beginning of the inter-region padding */
		poison_start = payload_start + reg.start + reg.size;
		if (i < regions->num_regions - 1) {
			poison_end =
				payload_start + regions->regions[i + 1].start;
		} else {
			poison_end = poison_start + 8;
		}

		if ((char *)poison_end > (char *)payload_end) {
			pr_info("kfuzztest: poison region out of bounds");
			goto fail;
		}

		__kfuzztest_poison_range(poison_start, poison_end);
	}

	*data_ret = payload_start;
	/* Returned as `reloc_handle_t`. */
	return regions;
fail:
	return NULL;
}
