#include <linux/kfuzztest.h>
#include <linux/kasan.h>

static void __kfuzztest_release_relocated_poisoned(reloc_handle_t handle)
{
	kfree(handle);
}

static void
__kfuzztest_release_relocated_distinct(struct reloc_region_array *regions,
				       reloc_handle_t handle)
{
	size_t i;
	void **allocations = (void **)handle;
	for (i = 0; i < regions->num_regions; i++)
		if (allocations[i])
			kfree(allocations[i]);
	kfree((void *)handle);
}

void __kfuzztest_release_relocated(struct reloc_region_array *regions,
				   reloc_handle_t handle)
{
	switch (regions->mode) {
	case DISTINCT:
		__kfuzztest_release_relocated_distinct(regions, handle);
		break;
	case POISONED:
		__kfuzztest_release_relocated_poisoned(handle);
		break;
	default:
		pr_warn("KFuzzTest: invalid release operation");
	}
}

static reloc_handle_t
__kfuzztest_relocate_poisoned(struct reloc_region_array *regions,
			      struct reloc_table *rt, void *payload,
			      void **data_ret)
{
	size_t i;
	struct reloc_region reg, src, dst;
	uintptr_t *ptr_location;
	struct reloc_entry re;
	void *ptr;

	/* Poison the padding between regions */
	for (i = 0; i < regions->num_regions; i++) {
		reg = regions->regions[i];
		ptr = payload + reg.start + reg.size;
		// TODO: poison this range. Figure out import for kasan.h.
	}

	// TODO: failure when the region points out of bounds.

	/* Patch pointers */
	for (i = 0; i < rt->num_entries; i++) {
		re = rt->entries[i];
		src = regions->regions[re.region_id];
		ptr_location = (uintptr_t *)(char *)payload + src.start +
			       re.region_offset;

		if (re.value == nullPtr) {
			*ptr_location = (uintptr_t)NULL;
		} else {
			if (re.value >= regions->num_regions)
				goto fail;
			dst = regions->regions[re.value];
			*ptr_location = (uintptr_t)(char *)payload + dst.start;
		}
	}

	return regions;
fail:
	__kfuzztest_release_relocated_poisoned(regions);
	return NULL;
}

static reloc_handle_t
__kfuzztest_relocate_distinct(struct reloc_region_array *regions,
			      struct reloc_table *rt, void *payload,
			      void **data_ret)
{
	void **allocated_regions;
	size_t i;
	struct reloc_region reg;
	struct reloc_entry re;
	uintptr_t *ptr_location;

	allocated_regions =
		kzalloc(regions->num_regions * sizeof(void *), GFP_KERNEL);
	if (!allocated_regions)
		return NULL;

	for (i = 0; i < regions->num_regions; i++) {
		reg = regions->regions[i];

		/* kzalloc guarantees 8-byte alignment, which is enough. */
		allocated_regions[i] = kzalloc(reg.size, GFP_KERNEL);
		if (!allocated_regions[i])
			goto fail;

		pr_info("copying from %px to %px with size 0x%x",
			(char *)payload + reg.start, allocated_regions[i],
			reg.size);

		memcpy(allocated_regions[i], (char *)payload + reg.start,
		       reg.size);

		pr_info("KFuzzTest: allocated region_%zu of size %u\n", i,
			reg.size);
	}

	for (i = 0; i < rt->num_entries; i++) {
		re = rt->entries[i];
		ptr_location =
			(uintptr_t *)((char *)allocated_regions[re.region_id] +
				      re.region_offset);
		if (re.value == nullPtr) {
			*ptr_location = (uintptr_t)NULL;
		} else {
			*ptr_location = (uintptr_t)allocated_regions[re.value];
			pr_info("KFuzzTest: pointer at offset %u in region %u pointer to region %u (0x%px)",
				re.region_offset, re.region_id, re.value,
				(void *)*ptr_location);
		}
	}

	if (data_ret)
		*data_ret = allocated_regions[0];
	return allocated_regions;

fail:
	if (!allocated_regions)
		return NULL;
	for (i = 0; i < regions->num_regions; i++) {
		if (allocated_regions[i])
			kfree(allocated_regions[i]);
	}
	return NULL;
}

reloc_handle_t __kfuzztest_relocate(struct reloc_region_array *regions,
				    struct reloc_table *rt, void *payload,
				    void **data_ret)
{
	switch (regions->mode) {
	case DISTINCT:
		return __kfuzztest_relocate_distinct(regions, rt, payload,
						     data_ret);
	case POISONED:
		return __kfuzztest_relocate_poisoned(regions, rt, payload,
						     data_ret);
	default:
		return ERR_PTR(-EINVAL);
	}
}
