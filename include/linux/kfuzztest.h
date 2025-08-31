// SPDX-License-Identifier: GPL-2.0
/*
 * The Kernel Fuzz Testing Framework (KFuzzTest) API for defining fuzz targets
 * for internal kernel functions.
 *
 * For more information please see Documentation/dev-tools/kfuzztest.rst.
 *
 * Copyright 2025 Google LLC
 */
#ifndef KFUZZTEST_H
#define KFUZZTEST_H

#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/types.h>

/**
 * @brief The KFuzzTest Input Serialization Format
 *
 * KFuzzTest receives its input from userspace as a single binary blob. This
 * format allows for the serialization of complex, pointer-rich C structures
 * into a flat buffer that can be safely passed into the kernel. This format
 * requires only a single copy from userspace into a kenrel buffer, and no
 * further kernel allocations. Pointers are patched internally using a "region"
 * system where each region corresponds to some pointed-to data.
 *
 * Regions should be padded to respect alignment constraints of their underlying
 * types, and should be followed by at least 8 bytes of padding. These padded
 * regions are poisoned by KFuzzTest to ensure that KASAN catches OOB accesses.
 *
 * The format consists of three main components:
 * 1. A reloc_region_array: Defines the memory layout of the target structure
 *	by partitioning the payload into logical regions. Each logical region
 *	should contain the byte representation of the type that it represents,
 *	including any necessary padding. The region descriptors should be
 *	ordered by offset ascending.
 * 2. A reloc_table: Provides "linking" instructions that tell the kernel how
 *	to patch pointer fields to point to the correct regions. By design,
 *	the first region (index 0) is passed as input into a FUZZ_TEST.
 * 3. A Payload: The raw binary data for the structure and its associated
 *	buffers. This should be aligned to the maximum alignment of all
 *	regions to satisfy alignment requirements of the input types, but this
 *	isn't checked by the parser.
 *
 * For a detailed specification of the binary layout see the full documentation
 * at: Documentation/dev-tools/kfuzztest.rst
 */

/**
 * struct reloc_region - single contiguous memory region in the payload
 *
 * @offset: The byte offset of this region from the start of the payload, which
 *	should be aligned to the alignment requirements of the region's
 *	underlying type.
 * @size: The size of this region in bytes.
 */
struct reloc_region {
	uint32_t offset;
	uint32_t size;
};

/**
 * struct reloc_region_array - array of regions in an input
 * @num_regions: The total number of regions defined.
 * @regions: A flexible array of `num_regions` region descriptors.
 */
struct reloc_region_array {
	uint32_t num_regions;
	struct reloc_region regions[];
};

/**
 * struct reloc_entry - a single pointer to be patched in an input
 *
 * @region_id: The index of the region in the `reloc_region_array` that
 *	contains the pointer.
 * @region_offset: The start offset of the pointer inside of the region.
 * @value: contains the index of the pointee region, or KFUZZTEST_REGIONID_NULL
 *	if the pointer is NULL.
 */
struct reloc_entry {
	uint32_t region_id;
	uint32_t region_offset;
	uint32_t value;
};

/**
 * struct reloc_entry - array of relocations required by an input
 *
 * @num_entries: the number of pointer relocations.
 * @padding_size: the number of padded bytes between the last relocation in
 *	entries, and the start of the payload data. This should be at least
 *	8 bytes, as it is used for poisoning.
 * @entries: array of relocations.
 */
struct reloc_table {
	uint32_t num_entries;
	uint32_t padding_size;
	struct reloc_entry entries[];
};

/**
 * __kfuzztest_parse_input - parse and validate a KFuzzTest input
 *
 * @input: A buffer containing the serialized test case.
 * @input_size: The size in bytes of the @input buffer.
 * @ret_regions: On success, updated to point to the relocation region array
 *	within the @input buffer.
 * @ret_reloc_table: On success, updated to point to the relocation table
 *	within the @input buffer.
 * @ret_payload_start: On success, updated to point to the start of the data
 *	payload within the @input buffer.
 * @ret_payload_end: On success, updated to point to the first byte after the
 *	end of the data payload.
 *
 * Returns: 0 on success, or a negative error code if the input is corrupted.
 */
int __kfuzztest_parse_input(void *input, size_t input_size,
			    struct reloc_region_array **ret_regions,
			    struct reloc_table **ret_reloc_table,
			    void **ret_payload_start, void **ret_payload_end);

/**
 * __kfuzztest_relocate - resolve relocations in a serialized payload
 *
 * @regions: The relocation region array parsed from the input.
 * @rt: The relocation table parsed from the input.
 * @payload_start: A pointer to the start of the data payload.
 * @payload_end: A pointer to the first byte after the end of the payload.
 *
 * This function iterates through the region array and relocation table to
 * patch the pointers inside of the payload, reconstructing pointer-pointee
 * relationships between the logical regions of the fuzz driver input. For
 * each entry in @rt, it calculates the address of a pointer field within the
 * payload and sets it to the start address of its target region, or a NULL
 * pointer if marked with KFUZZTEST_REGIONID_NULL.
 *
 * The padded areas between each region are poisoned with a KASAN slab redzone
 * to enable the detection of byte-accurate OOB accesses in the fuzz logic.
 *
 * Returns: 0 on success, or a negative error code if the relocation data is
 * found to be corrupt (e.g., invalid pointers).
 *
 * NOTE: this function only performs basic input validation. Full input
 * validation is handled during parsing by __kfuzztest_parse_input.
 */
int __kfuzztest_relocate(struct reloc_region_array *regions,
			 struct reloc_table *rt, void *payload_start,
			 void *payload_end);

/*
 * Dump some information on the parsed headers and payload. Can be useful for
 * debugging inputs when writing an encoder for the KFuzzTest input format.
 */
__attribute__((unused)) static inline void
__kfuzztest_debug_header(struct reloc_region_array *regions,
			 struct reloc_table *rt, void *payload_start,
			 void *payload_end)
{
	uint32_t i;
	pr_info("regions: { num_regions = %u } @ %px", regions->num_regions,
		regions);
	for (i = 0; i < regions->num_regions; i++) {
		pr_info("  region_%u: { start: 0x%x, size: 0x%x }", i,
			regions->regions[i].offset, regions->regions[i].size);
	}

	pr_info("reloc_table: { num_entries = %u, padding = %u } @ offset 0x%lx",
		rt->num_entries, rt->padding_size,
		(char *)rt - (char *)regions);
	for (i = 0; i < rt->num_entries; i++) {
		pr_info("  reloc_%u: { src: %u, offset: 0x%x, dst: %u }", i,
			rt->entries[i].region_id, rt->entries[i].region_offset,
			rt->entries[i].value);
	}

	pr_info("payload: [0x%lx, 0x%lx)",
		(char *)payload_start - (char *)regions,
		(char *)payload_end - (char *)regions);
}

struct kfuzztest_target {
	const char *name;
	const char *arg_type_name;
	ssize_t (*write_input_cb)(struct file *filp, const char __user *buf,
				  size_t len, loff_t *off);
} __attribute__((aligned(32)));

/*
 * Enforce a fixed struct size to ensure a consistent stride when iterating
 * over the array of these structs in the dedicated ELF section.
 */
static_assert(sizeof(struct kfuzztest_target) == 32,
	      "struct kfuzztest_target should have size 32");

/**
 * FUZZ_TEST - defines a KFuzzTest target
 *
 * @test_name: The unique identifier for the fuzz test, which is used to name
 *	the debugfs entry, e.g., /sys/kernel/debug/kftf/@test_name.
 * @test_arg_type: The struct type that defines the inputs for the test. This
 *	must be the full struct type (e.g., "struct my_inputs"), not a typedef.
 *
 * Context:
 * This macro is the primary entry point for the KFuzzTest framework. It
 * generates all the necessary boilerplate for a fuzz test, including:
 *   - A static `struct kfuzztest_target` instance that is placed in a
 *	dedicated ELF section for discovery by userspace tools.
 *   - A `debugfs` write callback that handles receiving serialized data from
 *	a fuzzer, parsing it, and "hydrating" it into a valid C struct.
 *   - A function stub where the developer places the test logic.
 *
 * User-Provided Logic:
 * The developer must provide the body of the fuzz test logic within the curly
 * braces following the macro invocation. Within this scope, the framework
 * provides the following variables:
 *
 * - `arg`: A pointer of type `@test_arg_type *` to the fully hydrated input
 * structure. All pointer fields within this struct have been relocated
 * and are valid kernel pointers. This is the primary variable to use
 * for accessing fuzzing inputs.
 *
 * - `regions`: A pointer of type `struct reloc_region_array *`. This is an
 * advanced feature that allows access to the raw region metadata, which
 * can be useful for checking the actual allocated size of a buffer via
 * `KFUZZTEST_REGION_SIZE(n)`.
 *
 * Example Usage:
 *
 * // 1. The kernel function we want to fuzz.
 * int process_data(const char *data, size_t len);
 *
 * // 2. Define a struct to hold all inputs for the function.
 * struct process_data_inputs {
 *	const char *data;
 *	size_t len;
 * };
 *
 * // 3. Define the fuzz test using the FUZZ_TEST macro.
 * FUZZ_TEST(process_data_fuzzer, struct process_data_inputs)
 * {
 *	int ret;
 *	// Use KFUZZTEST_EXPECT_* to enforce preconditions.
 *	// The test will exit early if data is NULL.
 *	KFUZZTEST_EXPECT_NOT_NULL(process_data_inputs, data);
 *
 *	// Use KFUZZTEST_ANNOTATE_* to provide hints to the fuzzer.
 *	// This links the 'len' field to the 'data' buffer.
 *	KFUZZTEST_ANNOTATE_LEN(process_data_inputs, len, data);
 *
 *	// Call the function under test using the 'arg' variable. OOB memory
 *	// accesses will be caught by KASAN, but the user can also choose to
 *	// validate the return value and log any failures.
 *	ret = process_data(arg->data, arg->len);
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
		void *payload_start, *payload_end, *buffer;                    \
		struct reloc_region_array *regions;                            \
		struct reloc_table *rt;                                        \
		test_arg_type *arg;                                            \
		int ret;                                                       \
                                                                               \
		buffer = kmalloc(len, GFP_KERNEL);                             \
		if (!buffer)                                                   \
			return -ENOMEM;                                        \
		ret = simple_write_to_buffer(buffer, len, off, buf, len);      \
		if (ret < 0)                                                   \
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

enum kfuzztest_constraint_type {
	EXPECT_EQ = 0,
	EXPECT_NE,
	EXPECT_LT,
	EXPECT_LE,
	EXPECT_GT,
	EXPECT_GE,
	EXPECT_IN_RANGE,
};

/**
 * struct kfuzztest_constraint - a metadata record for a domain constraint
 *
 * Domain constraints are rules about the input data that must be satisfied for
 * a fuzz test to proceed. While they are enforced in the kernel with a runtime
 * check, they are primarily intended as a discoverable contract for userspace
 * fuzzers.
 *
 * Instances of this struct are generated by the KFUZZTEST_EXPECT_* macros
 * and placed into the read-only ".kfuzztest_constraint" ELF section of the
 * vmlinux binary. A fuzzer can parse this section to learn about the
 * constraints and generate valid inputs more intelligently.
 *
 * For an example of how these constraints are used within a fuzz test, see the
 * documentation for the FUZZ_TEST() macro.
 *
 * @input_type: The name of the input struct type, without the leading
 *	"struct ".
 * @field_name: The name of the field within the struct that this constraint
 *	applies to.
 * @value1: The primary value used in the comparison (e.g., the upper
 *	bound for EXPECT_LE).
 * @value2: The secondary value, used only for multi-value comparisons
 *	(e.g., the upper bound for EXPECT_IN_RANGE).
 * @type: The type of the constraint.
 */
struct kfuzztest_constraint {
	const char *input_type;
	const char *field_name;
	uintptr_t value1;
	uintptr_t value2;
	enum kfuzztest_constraint_type type;
} __attribute__((aligned(64)));

/*
 * Enforce a fixed struct size to ensure a consistent stride when iterating
 * over the array of these structs in the dedicated ELF section.
 */
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

#define KFUZZTEST_EXPECT_LT(arg_type, field, val) \
	if (arg->field >= val)                    \
		return;                           \
	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_LT)

#define KFUZZTEST_EXPECT_LE(arg_type, field, val) \
	if (arg->field > val)                     \
		return;                           \
	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_LE)

#define KFUZZTEST_EXPECT_GT(arg_type, field, val) \
	if (arg->field <= val)                    \
		return;                           \
	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_GT)

#define KFUZZTEST_EXPECT_GE(arg_type, field, val) \
	if (arg->field < val)                     \
		return;                           \
	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_GE)

#define KFUZZTEST_EXPECT_NOT_NULL(arg_type, field) \
	KFUZZTEST_EXPECT_NE(arg_type, field, 0x0)

#define KFUZZTEST_EXPECT_IN_RANGE(arg_type, field, lower_bound, upper_bound) \
	if (arg->field < lower_bound || arg->field > upper_bound)            \
		return;                                                      \
	__KFUZZTEST_DEFINE_CONSTRAINT(arg_type, field, lower_bound,          \
				      upper_bound, EXPECT_IN_RANGE)

/**
 * Annotations express attributes about structure fields that can't be easily
 * or safely verified at runtime. They are intended as hints to the fuzzing
 * engine to help it generate more semantically correct and effective inputs.
 * Unlike constraints, annotations do not add any runtime checks and do not
 * cause a test to exit early.
 *
 * For example, a `char *` field could be a raw byte buffer or a C-style
 * null-terminated string. A fuzzer that is aware of this distinction can avoid
 * creating inputs that would cause trivial, uninteresting crashes from reading
 * past the end of a non-null-terminated buffer.
 */
enum kfuzztest_annotation_attribute : uint8_t {
	ATTRIBUTE_LEN = 0,
	ATTRIBUTE_STRING,
	ATTRIBUTE_ARRAY,
};

/**
 * struct kfuzztest_annotation - a metadata record for a fuzzer hint
 *
 * This struct captures a single hint about a field in the input structure.
 * Instances are generated by the KFUZZTEST_ANNOTATE_* macros and are placed
 * into the read-only ".kfuzztest_annotation" ELF section of the vmlinux binary.
 *
 * A userspace fuzzer can parse this section to understand the semantic
 * relationships between fields (e.g., which field is a length for which
 * buffer) and the expected format of the data (e.g., a null-terminated
 * string). This allows the fuzzer to be much more intelligent during input
 * generation and mutation.
 *
 * For an example of how annotations are used within a fuzz test, see the
 * documentation for the FUZZ_TEST() macro.
 *
 * @input_type: The name of the input struct type.
 * @field_name: The name of the field being annotated (e.g., the data
 *	buffer field).
 * @linked_field_name: For annotations that link two fields (like
 *	ATTRIBUTE_LEN), this is the name of the related field (e.g., the
 *	length field). For others, this may be unused.
 * @attrib: The type of the annotation hint.
 */
struct kfuzztest_annotation {
	const char *input_type;
	const char *field_name;
	const char *linked_field_name;
	enum kfuzztest_annotation_attribute attrib;
} __attribute__((aligned(32)));

/*
 * Enforce a fixed struct size to ensure a consistent stride when iterating
 * over the array of these structs in the dedicated ELF section.
 */
static_assert(sizeof(struct kfuzztest_annotation) == 32,
	      "struct kfuzztest_annotation should have size 32");

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

#define KFUZZTEST_REGIONID_NULL U32_MAX

/** Get the size of a payload region from within a FUZZ_TEST body */
#define KFUZZTEST_REGION_SIZE(n) \
	((n) < (regions->num_regions) ? (regions->regions[n].size) : 0)

/*
 * FIXME: These are both defined in `mm/kasan/kasan.h`, but the build breaks
 * if we define them in `include/linux/kasan.h` Since these values are unlikely
 * to change, we redefine them here.
 */
#define __KASAN_SLAB_REDZONE 0xFC
#define __KASAN_GRANULE_SIZE 0x8

/**
 * The end of the input should be padded by at least this number of bytes as
 * it is poisoned to detect out of bounds accesses at the end of the last 
 * region.
 */
#define KFUZZTEST_POISON_SIZE __KASAN_GRANULE_SIZE

#endif /* KFUZZTEST_H */
