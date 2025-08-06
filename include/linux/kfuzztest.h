#ifndef KFUZZTEST_H
#define KFUZZTEST_H

#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ethan Graham <ethangraham@google.com>");
MODULE_DESCRIPTION("Kernel Fuzz Testing Framework (KFuzzTest)");

struct reloc_region {
	uint32_t start; /* Offset from the start of the payload. */
	uint32_t size;
};

struct reloc_region_array {
	uint32_t num_regions;
	struct reloc_region regions[];
};

struct reloc_entry {
	uint32_t region_id; /* Region that pointer belongs to. */
	uint32_t region_offset; /* Offset from the beginning of the region. */
	uint32_t value; /* Pointee tegion identifier, or (void*)-1 if NULL */
};

struct reloc_table {
	uint32_t num_entries;
	uint32_t payloadOffset; /* Offset from start of relocation table */
	struct reloc_entry entries[];
};

int __kfuzztest_write_cb_common(struct file *filp, const char __user *buf,
				size_t len, loff_t *off, void *arg,
				size_t arg_size);

/**
 * Parses a binary input of size input_size. Input should be a pointer to a 
 * heap-allocated buffer, and it's ownership is transferred to this function
 * on call.
 * @input: a heap-allocated buffer (ownership transferred).
 * @input_size: the byte-length of input
 * @ret_regions: return pointer to the relocation region array
 * @ret_reloc_table: return pointer to the relocation table
 * @ret_payload_start: return pointer to the start of payload the data
 * @ret_payload_end: return pointer to the end of the payload data, i.e., the 
 *	first address that is out of the bounds of the payload.
 *
 * @return 0 on success, or an error code.
 */
int __kfuzztest_parse_input(void *input, size_t input_size,
			    struct reloc_region_array **ret_regions,
			    struct reloc_table **ret_reloc_table,
			    void **ret_payload_start, void **ret_payload_end);

/**
 * Relocates a parsed input into kernel memory.
 */
int __kfuzztest_relocate(struct reloc_region_array *regions,
			 struct reloc_table *rt, void *payload_start,
			 void *payload_end);

struct kfuzztest_target {
	const char *name;
	const char *arg_type_name;
	ssize_t (*write_input_cb)(struct file *filp, const char __user *buf,
				  size_t len, loff_t *off);
} __attribute__((aligned(32)));
static_assert(sizeof(struct kfuzztest_target) == 32,
	      "struct kfuzztest_target should have size 32");

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
	static ssize_t kfuzztest_write_cb_##test_name(struct file *filp,       \
						      const char __user *buf,  \
						      size_t len,              \
						      loff_t *off);            \
	static void kfuzztest_logic_##test_name(                               \
		test_arg_type *arg, struct reloc_region_array *regions);       \
	const struct kfuzztest_target __fuzz_test__##test_name __attribute__(( \
		__section__(".kfuzztest_target"), __used__)) = {               \
		.name = #test_name,                                            \
		.arg_type_name = #test_arg_type,                               \
		.write_input_cb = kfuzztest_write_cb_##test_name,              \
	};                                                                     \
	static ssize_t kfuzztest_write_cb_##test_name(struct file *filp,       \
						      const char __user *buf,  \
						      size_t len, loff_t *off) \
	{                                                                      \
		int ret;                                                       \
		struct reloc_region_array *regions;                            \
		struct reloc_table *rt;                                        \
		void *payload_start, *payload_end, *buffer;                    \
		test_arg_type *arg;                                            \
                                                                               \
		buffer = kmalloc(len, GFP_KERNEL);                             \
		if (!buffer)                                                   \
			return -ENOMEM;                                        \
		else if (IS_ERR(buffer))                                       \
			return PTR_ERR(buffer);                                \
		ret = __kfuzztest_write_cb_common(filp, buf, len, off, buffer, \
						  len);                        \
		if (ret)                                                       \
			goto out;                                              \
		ret = __kfuzztest_parse_input(buffer, len, &regions, &rt,      \
					      &payload_start, &payload_end);   \
		if (ret)                                                       \
			goto out;                                              \
		ret = __kfuzztest_relocate(regions, rt, payload_start,         \
					   payload_end);                       \
		if (ret)                                                       \
			goto out;                                              \
		/* Call the fuzz logic on the provided written input. */       \
		arg = (test_arg_type *)payload_start;                          \
		kfuzztest_logic_##test_name(arg, regions);                     \
		ret = len;                                                     \
out:                                                                           \
		kfree(buffer);                                                 \
		return ret;                                                    \
	}                                                                      \
	static void kfuzztest_logic_##test_name(                               \
		test_arg_type *arg, struct reloc_region_array *regions)

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

/**
 * The input format is such that the value field is a region index. We reserve
 * this value to encode a NULL pointer in the input.
 */
#define KFUZZTEST_REGIONID_NULL U32_MAX

/* The size of a region if it exists, or 0 if it does not. */
#define KFUZZTEST_REGION_SIZE(n) \
	((n) < (regions->num_regions) ? (regions->regions[n].size) : 0)

#endif /* KFUZZTEST_H */
