#include <linux/kfuzztest.h>
#include <linux/kasan.h>

#define POISON_REGION_END 0xFC

static void __kfuzztest_poison_range(void *start, void *end)
{
	uintptr_t start_addr = (uintptr_t)start;
	uintptr_t end_addr = (uintptr_t)end;
	uintptr_t poison_start;
	uintptr_t poison_end;

	/*
	 * Calculate the largest region within [start, end) that is aligned
	 * to KASAN_GRANULE_SIZE. This is the only part we can safely poison.
	 */
	poison_start = ALIGN(start_addr, 0x8);
	poison_end = ALIGN_DOWN(end_addr, 0x8);

	/* If there's no fully-aligned granule in the range, we can't do anything. */
	if (poison_start >= poison_end)
		return;

	/*
	 * Poison the aligned region. KASAN_SLAB_REDZONE is a suitable
	 * poison value for padding that should never be accessed.
	 */
	kasan_poison((void *)poison_start, poison_end - poison_start,
		     POISON_REGION_END, false);
	pr_info("kfuzztest: poisoned [%px, %px)", (void *)poison_start,
		(void *)poison_end);
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
