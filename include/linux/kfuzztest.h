#ifndef KFUZZTEST_H
#define KFUZZTEST_H

#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ethan Graham <ethangraham@google.com>");
MODULE_DESCRIPTION("Kernel Fuzz Testing Framework (KFuzzTest)");

static void *kfuzztest_parse_input(void *input, size_t input_size,
				   size_t *num_regions);

struct kfuzztest_target {
	const char *name;
	const char *arg_type_name;
	ssize_t (*write_input_cb)(struct file *filp, const char __user *buf,
				  size_t len, loff_t *off);
} __attribute__((aligned(32)));
static_assert(sizeof(struct kfuzztest_target) == 32,
	      "struct kfuzztest_target should have size 32");

__attribute__((unused)) static int
write_input_cb_common(struct file *filp, const char __user *buf, size_t len,
		      loff_t *off, void *arg, size_t arg_size)
{
	if (len != arg_size) {
		return -EINVAL;
	}
	if (simple_write_to_buffer((void *)arg, arg_size, off, buf, len) < 0) {
		return -EFAULT;
	}
	return 0;
}

/**
 * FUZZ_TEST - defines a KFuzzTest target.
 *
 * @test_name: Name of the fuzz target, which is used to create the associated
 *	debufs entries.
 * @test_arg_type: the input type of fuzz target. This should always be a 
 *	struct type even when fuzzing with a single input parameter in order
 *	to take advantage of the domain constraint and annotation systems. See 
 *	usage example below.
 *
 *
 * This macro generates all of the necessary boilerplate for a KFuzzTest 
 * driver, which is placed in a dedicated ".kfuzztest_target" that is used by 
 * the KFuzzTest module and can be read by a fuzzing engine.
 *
 * For each test, this macro generates
 *	- A buffer to receive input through the debugfs entry
 *	- A mutex to protect the input buffer
 *	- A `struct kfuzztest_target` instance
 *
 * Example usage:
 *
 * // Assume that we are fuzzing some function func(T1 param1, ... TN paramN).
 * // Define input type of the fuzz target. This should be always be a struct.
 * struct test_arg_type {
 *	T1 arg1;
 *	...
 *	TN argn;
 * };
 *
 * // Define the test case.
 * FUZZ_TEST(test_func, struct test_arg_type) 
 * {
 *      int ret;
 *	// arg is provided by the macro, and is of type struct test_arg_type.
 *	ret = func(arg.arg1, ..., arg.argn);
 *	// Validate the return value if testing for correctness.
 *	if (ret != expected_value) {
 *		KFUZZTEST_REPORT_BUG("Unexpected return value");
 *	}
 * }
 */
#define FUZZ_TEST(test_name, test_arg_type)                                    \
	static ssize_t _write_callback_##test_name(struct file *filp,          \
						   const char __user *buf,     \
						   size_t len, loff_t *off);   \
	static void _fuzz_test_logic_##test_name(test_arg_type *arg);          \
	const struct kfuzztest_target __fuzz_test__##test_name __attribute__(( \
		__section__(".kfuzztest_target"), __used__)) = {               \
		.name = #test_name,                                            \
		.arg_type_name = #test_arg_type,                               \
		.write_input_cb = _write_callback_##test_name,                 \
	};                                                                     \
	/* Invoked when data is written into the target's input file. */       \
	static ssize_t _write_callback_##test_name(struct file *filp,          \
						   const char __user *buf,     \
						   size_t len, loff_t *off)    \
	{                                                                      \
		int err;                                                       \
		size_t i;                                                      \
		void *region, *regions;                                        \
		void *buffer = kmalloc(len, GFP_KERNEL);                       \
		if (!buffer || IS_ERR(buffer))                                 \
			return PTR_ERR(buffer);                                \
		err = write_input_cb_common(filp, buf, len, off, buffer, len); \
		if (err != 0) {                                                \
			kfree(buffer);                                         \
			return err;                                            \
		}                                                              \
		size_t num_regions;                                            \
		regions = kfuzztest_parse_input(buffer, len, &num_regions);    \
		if (!regions) {                                                \
			kfree(buffer);                                         \
			return -1;                                             \
		} else if (IS_ERR(regions)) {                                  \
			kfree(buffer);                                         \
			return PTR_ERR(regions);                               \
		}                                                              \
		pr_info("KFuzzTest: regions = 0x%px\n", regions);              \
		/* The input argument is the first region. */                  \
		test_arg_type *arg = ((void **)regions)[0];                    \
		/* Call the user's logic on the provided written input. */     \
		_fuzz_test_logic_##test_name(arg);                             \
		kfree(buffer);                                                 \
		for (i = 0; i < num_regions; i++) {                            \
			region = ((void **)regions)[i];                        \
			if (region)                                            \
				kfree(region);                                 \
		}                                                              \
		kfree(regions);                                                \
		return len;                                                    \
	}                                                                      \
	static void _fuzz_test_logic_##test_name(test_arg_type *arg)

/**
 * Reports a bug with a predictable prefix so that it can be parsed by a
 * fuzzing driver.
 */
#define KFUZZTEST_REPORT_BUG(msg, fmt) pr_warn("bug: " #msg, fmt)

enum kfuzztest_constraint_type : uint8_t {
	EXPECT_EQ = 0,
	EXPECT_NE,
	EXPECT_LE,
	EXPECT_GT,
	EXPECT_IN_RANGE,
};

/**
 * Domain constraints are used to restrict the values that the fuzz driver
 * accepts, enforcing early exit when not satisfied. Domain constraints are
 * encoded in vmlinux under the `__kfuzztest_constraint` section. A good 
 * fuzzing engine should be aware of these domain constraints during input 
 * generation and mutation.
 *
 * struct kfuzztest_constraint defines a domain constraint for a structure
 * field.
 *
 * @input_type: the name of the input (a struct name)
 * @field_name: the name of the field that this domain constraint applies to
 * @value1: used in all comparisons
 * @value2: only used in comparisons that require multiple values, e.g. range
 *	constraints
 * @type: the type of the constraint, enumerated above
 *
 * Example usage:
 *
 * struct foo {
 *	struct bar *a;
 *	int b
 * };
 *
 * FUZZ_TEST(test_name, struct foo)
 * {
 *	// Early exit if foo.a == NULL.
 *	KFUZZTEST_EXPECT_NOT_NULL(foo, a);
 *	// Early exit if foo < 23 || foo > 42
 *	KFUZZTEST_EXPECT_IN_RANGE(foo, b, 23, 42);
 *	// User-defined fuzz logic.
 * }
 */
struct kfuzztest_constraint {
	const char *input_type;
	const char *field_name;
	uintptr_t value1;
	uintptr_t value2;
	enum kfuzztest_constraint_type type;
} __attribute__((aligned(64)));

static_assert(sizeof(struct kfuzztest_constraint) == 64,
	      "struct kfuzztest_constraint should have size 64");

#define __KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val1, val2, tpe)      \
	static struct kfuzztest_constraint __constraint_##arg_type##_##field \
		__attribute__((__section__(".kfuzztest_constraint"),         \
			       __used__)) = {                                \
			.input_type = "struct " #arg_type,                   \
			.field_name = #field,                                \
			.value1 = (uintptr_t)val1,                           \
			.value2 = (uintptr_t)val2,                           \
			.type = tpe,                                         \
		};

#define KFUZZTEST_EXPECT_EQ(arg_type, field, val) \
	if (arg->field != val)                    \
		return;                           \
	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_EQ)

#define KFUZZTEST_EXPECT_NE(arg_type, field, val) \
	if (arg->field == val)                    \
		return;                           \
	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_NE)

#define KFUZZTEST_EXPECT_LE(arg_type, field, val) \
	if (arg->field > val)                     \
		return;                           \
	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_LE)

#define KFUZZTEST_EXPECT_GT(arg_type, field, val) \
	if (arg->field <= val)                    \
		return;                           \
	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_GT)

#define KFUZZTEST_EXPECT_NOT_NULL(arg_type, field) \
	KFUZZTEST_EXPECT_NE(arg_type, field, 0x0)

#define KFUZZTEST_EXPECT_IN_RANGE(arg_type, field, lower_bound, upper_bound) \
	if (arg->field < lower_bound || arg->field > upper_bound)            \
		return;                                                      \
	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, lower_bound,          \
				      upper_bound, EXPECT_IN_RANGE)

#define KFUZZTEST_EXPECT_LEN(expected_len, actual_len) \
	if ((expected_len) != (actual_len))            \
		return;

/**
 * Annotations express attributes about structure fields that can't be easily
 * verified at runtime, and are intended as a hint to the fuzzing engine.
 *
 * For example, a char* could either be a raw byte buffer or a string, where
 * the latter is null terminated. If a function accepts a null-terminated 
 * string without a length and is passed an arbitrary byte buffer, we
 * may get false positive KASAN reports, for example. However, verifying that 
 * the char buffer is null-termined could itself trigger a memory overflow.
 */
enum kfuzztest_annotation_attribute : uint8_t {
	ATTRIBUTE_LEN = 0,
	ATTRIBUTE_STRING,
	ATTRIBUTE_ARRAY,
};

struct kfuzztest_annotation {
	const char *input_type;
	const char *field_name;
	const char *linked_field_name;
	enum kfuzztest_annotation_attribute attrib;
} __attribute__((aligned(32)));

#define __KFUZZTEST_ANNOTATE(arg_type, field, linked_field, attribute)       \
	static struct kfuzztest_annotation __annotation_##arg_type##_##field \
		__attribute__((__section__(".kfuzztest_annotation"),         \
			       __used__)) = {                                \
			.input_type = "struct " #arg_type,                   \
			.field_name = #field,                                \
			.linked_field_name = #linked_field,                  \
			.attrib = attribute,                                 \
		};

/**
 * Annotates a char* field as a string, which is the subset of char arrays that 
 * are null-terminated.
 */
#define KFUZZTEST_ANNOTATE_STRING(arg_type, field) \
	__KFUZZTEST_ANNOTATE(arg_type, field, , ATTRIBUTE_STRING)

/**
 * Annotates a pointer field as an array, which is a contiguous memory region
 * containing zero or more elements of the same type.
 */
#define KFUZZTEST_ANNOTATE_ARRAY(arg_type, field) \
	__KFUZZTEST_ANNOTATE(arg_type, field, , ATTRIBUTE_ARRAY)

/**
 * Annotates arg_type.field as the length of arg_type.linked_field
 */
#define KFUZZTEST_ANNOTATE_LEN(arg_type, field, linked_field) \
	__KFUZZTEST_ANNOTATE(arg_type, field, linked_field, ATTRIBUTE_LEN)

struct reloc_entry {
	uint32_t region_id; /* Region that pointer belongs to. */
	uint32_t region_offset; /* Offset from the beginning of the region. */
	uint32_t value; /* Pointee tegion identifier, or (void*)-1 if NULL */
	uint32_t padding;
};

/*
 * How many integers of padding in the relocation table between the header
 * information and the relocation entries
 */
#define RELOC_TABLE_PADDING 3

struct reloc_table {
	uint32_t num_entries;
	uint32_t padding[RELOC_TABLE_PADDING];
	struct reloc_entry entries[];
};
static_assert(offsetof(struct reloc_table, entries) %
		      sizeof(struct reloc_entry) ==
	      0);

struct reloc_region {
	uint32_t id;
	uint32_t start; /* Offset from the start of the payload */
	uint32_t size;
	uint32_t alignment;
};

enum reloc_mode : uint32_t { DISTINCT = 0, POISONED };

/**
 * How many `uint64_t`s of padding are required.
 */
#define RELOC_REGION_PADDING 2

struct reloc_region_array {
	uint32_t num_regions;
	enum reloc_mode mode;
	uint32_t padding[RELOC_REGION_PADDING];
	struct reloc_region regions[];
};

static_assert(offsetof(struct reloc_region_array, regions) %
		      sizeof(struct reloc_region) ==
	      0);

/**
 * The relocation table format encodes pointer values as a relative offset from 
 * the location of the pointer. A relative offset of zero could indicate that 
 * the pointer points to its own address, which is valid. We encode a null 
 * pointer as 0xFF...FF as adding this value to any address would result in an 
 * overflow anyways, and is therefore invalid in any other circumstance.
 */
static const uintptr_t nullPtr = (uintptr_t)-1;

__attribute__((unused)) static void *
kfuzztest_parse_input(void *input, size_t input_size, size_t *num_regions)
{
	size_t i;
	void *payload_start;
	uintptr_t *ptr_location;
	size_t payload_len, reloc_entries_size, reloc_table_size,
		reloc_regions_size, region_array_size;
	struct reloc_table *rt;
	struct reloc_entry re;
	struct reloc_region_array *region_array;
	struct reloc_region reg;
	void **allocated_regions = NULL;

	pr_info("KFuzzTest: input [ 0x%px, 0x%px ]", input,
		(char *)input + input_size);
	if (input_size <
	    sizeof(struct reloc_table) + sizeof(struct reloc_region_array)) {
		pr_warn("KFuzzTest: input was not well-formed");
		return NULL;
	}
	rt = input;

	if (check_mul_overflow(rt->num_entries, sizeof(struct reloc_entry),
			       &reloc_entries_size))
		return NULL;
	reloc_table_size =
		offsetof(struct reloc_table, entries) + reloc_entries_size;
	pr_info("reloc_table_size: 0x%lx\n", reloc_table_size);
	if (reloc_table_size > input_size)
		return NULL;
	pr_info("num reloc entries: %d\n", rt->num_entries);

	region_array =
		(struct reloc_region_array *)((char *)input + reloc_table_size);
	if (check_mul_overflow(region_array->num_regions,
			       sizeof(struct reloc_region),
			       &reloc_regions_size))
		return NULL;

	region_array_size = offsetof(struct reloc_region_array, regions) +
			    reloc_regions_size;
	pr_info("region_array_size: 0x%lx", region_array_size);
	pr_info("num regions = %llu", region_array->num_regions);
	if (reloc_table_size + region_array_size > input_size)
		return NULL;

	allocated_regions =
		kzalloc(region_array->num_regions * sizeof(void *), GFP_KERNEL);
	if (!allocated_regions)
		return NULL;

	payload_start = (char *)region_array + region_array_size;
	if (payload_start >= input + input_size)
		return NULL;

	payload_len = input_size - (payload_start - input);

	pr_info("KFuzzTest: allocating regions");
	/* Allocate regions, and copy data in. */
	for (i = 0; i < region_array->num_regions; i++) {
		reg = region_array->regions[i];

		/* kzalloc guarantees 8-byte alignment, which is enough. */
		allocated_regions[i] = kzalloc(reg.size, GFP_KERNEL);
		if (!allocated_regions[i])
			goto fail;

		pr_info("copying from %px to %px with size 0x%llx",
			(char *)payload_start + reg.start, allocated_regions[i],
			reg.size);

		memcpy(allocated_regions[i], (char *)payload_start + reg.start,
		       reg.size);

		pr_info("KFuzzTest: allocated region_%llu of size %llu\n",
			reg.id, reg.size);
	}

	/* Patch pointers. */
	for (i = 0; i < rt->num_entries; i++) {
		re = rt->entries[i];
		ptr_location =
			(uintptr_t *)((char *)allocated_regions[re.region_id] +
				      re.region_offset);
		if (re.value == nullPtr) {
			*ptr_location = (uintptr_t)NULL;
		} else {
			*ptr_location = (uintptr_t)allocated_regions[re.value];
			pr_info("KFuzzTest: pointer at offset %llu in region %llu pointer to region %llu (0x%px)",
				re.region_offset, re.region_id, re.value,
				(void *)*ptr_location);
		}
	}

	if (num_regions)
		*num_regions = region_array->num_regions;
	return allocated_regions;

fail:
	if (!allocated_regions)
		return NULL;
	for (i = 0; i < region_array->num_regions; i++) {
		if (allocated_regions[i])
			kfree(allocated_regions[i]);
	}
	return NULL;
}

#endif /* KFUZZTEST_H */
