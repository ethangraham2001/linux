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
	/* Regions points to the beginning of the user buffer. */
	kfree((void *)regions);
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

#define POISON_REGION_END 0xFC

static reloc_handle_t
__kfuzztest_relocate_poisoned(struct reloc_region_array *regions,
			      struct reloc_table *rt, void *payload_start,
			      void *payload_end, void **data_ret)
{
	size_t i;
	struct reloc_region reg, src, dst;
	uintptr_t *ptr_location;
	struct reloc_entry re;
	void *ptr;

	/* Patch pointers. */
	for (i = 0; i < rt->num_entries; i++) {
		re = rt->entries[i];
		if (re.region_id > regions->num_regions)
			goto fail;

		src = regions->regions[re.region_id];
		ptr_location = (uintptr_t *)(char *)payload_start + src.start +
			       re.region_offset;
		if ((char *)ptr_location >= (char *)payload_end)
			goto fail;

		if (re.value == KFUZZTEST_REGIONID_NULL) {
			*ptr_location = (uintptr_t)NULL;
		} else {
			if (re.value >= regions->num_regions)
				goto fail;
			dst = regions->regions[re.value];
			*ptr_location =
				(uintptr_t)(char *)payload_start + dst.start;
		}
	}

	/* Poison the padding between regions. */
	for (i = 0; i < regions->num_regions; i++) {
		reg = regions->regions[i];
		/* Points to the 8 bytes of padding following every region. */
		ptr = payload_start + reg.start + reg.size;
		if ((char *)ptr + 8 >= (char *)payload_end)
			goto fail;
		kasan_poison(ptr, 8, POISON_REGION_END, false);
	}

	/* Returned as `reloc_handle_t`. */
	return regions;
fail:
	__kfuzztest_release_relocated_poisoned(regions);
	return NULL;
}

static reloc_handle_t
__kfuzztest_relocate_distinct(struct reloc_region_array *regions,
			      struct reloc_table *rt, void *payload_start,
			      void *payload_end, void **data_ret)
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
		if (reg.size > KMALLOC_MAX_SIZE)
			goto fail;

		/* kzalloc guarantees 8-byte alignment, which is enough. */
		allocated_regions[i] = kzalloc(reg.size, GFP_KERNEL);
		if (!allocated_regions[i])
			goto fail;

		memcpy(allocated_regions[i], (char *)payload_start + reg.start,
		       reg.size);
	}

	for (i = 0; i < rt->num_entries; i++) {
		re = rt->entries[i];
		if (re.value >= regions->num_regions)
			goto fail;

		ptr_location =
			(uintptr_t *)((char *)allocated_regions[re.region_id] +
				      re.region_offset);

		if ((char *)ptr_location >= (char *)payload_end)
			goto fail;

		if (re.value == KFUZZTEST_REGIONID_NULL)
			*ptr_location = (uintptr_t)NULL;
		else
			*ptr_location = (uintptr_t)allocated_regions[re.value];
	}

	if (data_ret)
		*data_ret = allocated_regions[0];
	return allocated_regions;

fail:
	__kfuzztest_release_relocated_distinct(regions, allocated_regions);
	return NULL;
}

reloc_handle_t __kfuzztest_relocate(struct reloc_region_array *regions,
				    struct reloc_table *rt, void *payload_start,
				    void *payload_end, void **data_ret)
{
	switch (regions->mode) {
	case DISTINCT:
		return __kfuzztest_relocate_distinct(regions, rt, payload_start,
						     payload_end, data_ret);
	case POISONED:
		return __kfuzztest_relocate_poisoned(regions, rt, payload_start,
						     payload_end, data_ret);
	default:
		return ERR_PTR(-EINVAL);
	}
}
