#ifndef KFTF_H
#define KFTF_H

#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ethan Graham <ethangraham@google.com>");
MODULE_DESCRIPTION("Kernel Fuzz Testing Framework (KFTF)");

/* forward decl */
static void *kftf_parse_input(void *input, size_t input_size);

/**
 * struct kftf_test case defines a single fuzz test case. These should not
 * be created manually. Instead the user should use the FUZZ_TEST macro defined
 * below.
 * @name: The name of the test case, generally the function being fuzzed.
 * @arg_type_name: string representation of the type of argument being fuzzed,
 *	for example "struct func_arg_type"
 * @write_input_cb: Callback invoked when a write's to the test case's debugfs
 *	input file. This is the entry point for fuzzing data. It is responsible
 *	for parsing any data written to the input file and invoking the fuzzing
 *	logic. It should return the number of bytes consumed from `buf`
 * @read_metadata_cb: Callback invoked when a user reads from the test case's
 *	"metadata" debugfs file. It should simply return whatever is contained
 *	in the `arg_type_name` field.
 */
struct kftf_test_case {
	const char *name;
	const char *arg_type_name;
	ssize_t (*write_input_cb)(struct file *filp, const char __user *buf,
				  size_t len, loff_t *off);
	ssize_t (*read_metadata_cb)(struct file *, char __user *, size_t,
				    loff_t *);
};

// XXX: why can't we use without the attribute unused anymore??
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
 * FUZZ_TEST - defines a fuzz test case for a function.
 * @func: the function to be fuzzed. This is used to name the test case and
 *	create associated debufs entries.
 * @func_arg_type: the input type of func. If func takes multiple arguments,
 *	then one should wrap that inside of a multi-fielded struct. See usage
 *	example below.
 *
 *
 * This macro generates all of the necessary boilerplate for a KFTF test case,
 * which is placed in a dedicated ".kftf" section so that the dedicated KFTF
 * module can discover all defined tests at runtime.
 *
 * For each test, this macro generates
 *	- A buffer to receive input through the debugfs entry
 *	- A mutex to protect the input buffer
 *	- A `struct kftf_test_case` instance
 *
 * Example usagea:
 *
 * Assume some function `func(T1 param1, ... TN paramN)`
 * // Define input type of the target function
 * struct func_arg_type {
 *	T1 arg1;
 *	...
 *	TN argn;
 * };
 *
 * // Define the test case
 * FUZZ_TEST(func, struct func_arg_type) 
 * {
 *	// arg is provided by the macro, and is of type `struct func_arg_type`
 *	ret = func(arg.arg1, ..., arg.argn);
 *	validate(ret);
 * }
 */
#define FUZZ_TEST(func, func_arg_type)                                         \
	/* forward decls */                                                    \
	static ssize_t _write_callback_##func(struct file *filp,               \
					      const char __user *buf,          \
					      size_t len, loff_t *off);        \
	static ssize_t _read_metadata_callback_##func(                         \
		struct file *filp, char __user *buf, size_t len, loff_t *off); \
	static void _fuzz_test_logic_##func(func_arg_type *arg);               \
	/* test case struct initialization */                                  \
	const struct kftf_test_case __fuzz_test__##func                        \
		__attribute__((__section__(".kftf_test"), __used__)) = {       \
			.name = #func,                                         \
			.arg_type_name = #func_arg_type,                       \
			.write_input_cb = _write_callback_##func,              \
			.read_metadata_cb = _read_metadata_callback_##func     \
		};                                                             \
	/* callback that simply returns the type name to the user */           \
	static ssize_t _read_metadata_callback_##func(                         \
		struct file *filp, char __user *buf, size_t len, loff_t *off)  \
	{                                                                      \
		const char *message = __fuzz_test__##func.arg_type_name;       \
		int message_len = strlen(message);                             \
		return simple_read_from_buffer(buf, len, off, message,         \
					       message_len);                   \
	}                                                                      \
	/* user-defined write callback */                                      \
	static ssize_t _write_callback_##func(struct file *filp,               \
					      const char __user *buf,          \
					      size_t len, loff_t *off)         \
	{                                                                      \
		pr_info("[ENTER] %s\n", __FUNCTION__);                         \
		int err;                                                       \
		void *buffer = kmalloc(len, GFP_KERNEL);                       \
		if (!buffer || IS_ERR(buffer))                                 \
			return PTR_ERR(buffer);                                \
		err = write_input_cb_common(filp, buf, len, off, buffer, len); \
		if (err != 0) {                                                \
			kfree(buffer);                                         \
			return err;                                            \
		}                                                              \
		void *payload = kftf_parse_input(buffer, len);                 \
		if (!payload) {                                                \
			kfree(buffer);                                         \
			return -1;                                             \
		}                                                              \
		func_arg_type *arg = payload;                                  \
		/* call the user's logic on the provided arg. */               \
		/* NOTE: define some success/failure return types? */          \
		pr_info("invoking fuzz logic for %s\n", #func);                \
		_fuzz_test_logic_##func(arg);                                  \
		kfree(buffer);                                                 \
		kfree(payload);                                                \
		return len;                                                    \
	}                                                                      \
	static void _fuzz_test_logic_##func(func_arg_type *arg)

/**
 * Reports a bug with a predictable prefix so that it can be parsed by a
 * fuzzing driver.
 */
#define KFTF_REPORT_BUG(msg, fmt) pr_warn("bug: " #msg, fmt)

/**
 * struct kftf_constraint_type defines a type of constraint. The fuzzing driver
 * should be aware of these.
 */
enum kftf_constraint_type : uint8_t {
	EXPECT_EQ = 0,
	EXPECT_NE,
	EXPECT_LE,
	EXPECT_GT,
	EXPECT_IN_RANGE,
};

/**
 * ktft_constraint defines a domain constraint for a struct variable that is
 * taken as input for a FUZZ_TEST
 *
 * @input_type: the name of the input (a struct name)
 * @field_name: the name of the field that this domain constraint applies to
 * @value1: used in all comparisons
 * @value2: only used in comparisons that require multiple values, e.g. range
 *	constraints
 * @type: the type of the constraint, enumerated above
 *
 * Note: if this struct is not a multiple of 64 bytes, everything breaks and
 * we get corrupted data and occasional kernel panics. To avoid this happening,
 * we enforce 64 Byte alignment and statically assert that this struct has size
 * 64 Bytes.
 */
struct kftf_constraint {
	const char *input_type;
	const char *field_name;
	uintptr_t value1;
	uintptr_t value2;
	enum kftf_constraint_type type;
} __attribute__((aligned(64)));

static_assert(sizeof(struct kftf_constraint) == 64,
	      "struct kftf_constraint should have size 64");

/**
 * __KFTF_DEFINE_CONSTRAINT - defines a fuzz test constraint linked to a given
 * argument type belonging to a fuzz test. See FUZZ_TEST above.
 *
 * @arg_type: the type of argument (a struct) without the leading "struct" in
 *	its name, which will be prepended.
 * @field: the field on which the constraint is defined.
 * @val: used for comparison constraints such as KFTF_EXPECT_NE
 * @tpe: the type of constaint that this defines
 *
 * This macro is intended for internal use. A user should opt for 
 * KFTF_EXPECT_* instead when defining fuzz test constraints.
 */
#define __KFTF_DEFINE_CONSTRAINT(arg_type, field, val1, val2, tpe)             \
	static struct kftf_constraint __constraint_##arg_type##_##field        \
		__attribute__((__section__(".kftf_constraint"), __used__)) = { \
			.input_type = "struct " #arg_type,                     \
			.field_name = #field,                                  \
			.value1 = (uintptr_t)val1,                             \
			.value2 = (uintptr_t)val2,                             \
			.type = tpe,                                           \
		};

#define KFTF_EXPECT_EQ(arg_type, field, val) \
	if (arg->field != val)               \
		return;                      \
	__KFTF_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_EQ)

#define KFTF_EXPECT_NE(arg_type, field, val) \
	if (arg->field == val)               \
		return;                      \
	__KFTF_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_NE)

#define KFTF_EXPECT_LE(arg_type, field, val) \
	if (arg->field > val)                \
		return;                      \
	__KFTF_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_LE)

#define KFTF_EXPECT_GT(arg_type, field, val) \
	if (arg->field <= val)               \
		return;                      \
	__KFTF_DEFINE_CONSTRAINT(arg_type, field, val, 0x0, EXPECT_GT)

#define KFTF_EXPECT_NOT_NULL(arg_type, field) \
	KFTF_EXPECT_NE(arg_type, field, 0x0)

#define KFTF_EXPECT_IN_RANGE(arg_type, field, lower_bound, upper_bound)     \
	if (arg->field < lower_bound || arg->field > upper_bound)           \
		return;                                                     \
	__KFTF_DEFINE_CONSTRAINT(arg_type, field, lower_bound, upper_bound, \
				 EXPECT_IN_RANGE)

enum kftf_annotation_attribute : uint8_t {
	ATTRIBUTE_LEN = 0,
	ATTRIBUTE_STRING,
};

struct kftf_annotation {
	const char *input_type;
	const char *field_name;
	const char *linked_field_name;
	enum kftf_annotation_attribute attrib;
} __attribute__((aligned(32)));

#define __KFTF_ANNOTATE(arg_type, field, linked_field, attribute)              \
	static struct kftf_annotation __annotation_##arg_type##_##field        \
		__attribute__((__section__(".kftf_annotation"), __used__)) = { \
			.input_type = "struct " #arg_type,                     \
			.field_name = #field,                                  \
			.linked_field_name = #linked_field,                    \
			.attrib = attribute,                                   \
		};

/**
 * Annotates arg_type.field as a string
 */
#define KFTF_ANNOTATE_STRING(arg_type, field) \
	__KFTF_ANNOTATE(arg_type, field, , ATTRIBUTE_STRING)

/**
 * Annotates arg_type.field as the length of arg_type.linked_field
 */
#define KFTF_ANNOTATE_LEN(arg_type, field, linked_field) \
	__KFTF_ANNOTATE(arg_type, field, linked_field, ATTRIBUTE_LEN)

struct reloc_entry {
	uintptr_t pointer; /* offset from the beginning of the payload */
	uintptr_t value; /* difference between the pointed to address and the address itself */
};

/*
 * How many integers of padding in the relocation table between the header
 * information and the relocation entries
 */
#define RELOC_TABLE_PADDING 2

struct reloc_table {
	int num_entries;
	uint32_t max_alignment;
	int padding[RELOC_TABLE_PADDING];
	struct reloc_entry entries[];
};
static_assert(offsetof(struct reloc_table, entries) %
		      sizeof(struct reloc_entry) ==
	      0);

static const uintptr_t nullPtr = (uintptr_t)-1;

static void *kftf_parse_input(void *input, size_t input_size)
{
	size_t i;
	void *payload_start, *out;
	uintptr_t *ptr_location;
	size_t payload_len, alloc_size;
	struct reloc_table *rt;
	struct reloc_entry re;
	pr_info("%s: input_size = %zu\n", __FUNCTION__, input_size);

	if (input_size < sizeof(struct reloc_table)) {
		pr_warn("got misformed input in %s\n", __FUNCTION__);
		return NULL;
	}
	rt = input;

	payload_start = (char *)input + offsetof(struct reloc_table, entries) +
			rt->num_entries * sizeof(struct reloc_entry);
	if (payload_start >= input + input_size)
		return NULL;

	/*
	 * To guarantee correct alignment of structures within the payload, we
	 * allocate a new property that is aligned to the next power of two
	 * greater than either the size of the payload or the maximum alignment
	 * of the nested structures.
	 */
	payload_len = input_size - (payload_start - input);
	alloc_size = MAX(roundup_pow_of_two(payload_len),
			 roundup_pow_of_two(rt->max_alignment));
	out = kmalloc(alloc_size, GFP_KERNEL);
	if (!out) {
		return NULL;
	}
	memcpy(out, payload_start, payload_len);

	/*
	 * Iterate through entries in the relocation table and patch the
	 * pointers.
	 */
	for (i = 0; i < rt->num_entries; i++) {
		re = rt->entries[i];
		ptr_location = (uintptr_t *)(out + re.pointer);
		if ((void *)ptr_location + sizeof(uintptr_t) >=
		    input + input_size)
			return NULL;

		if (re.value == nullPtr) {
			*ptr_location = (uintptr_t)NULL;
		} else {
			*ptr_location = (uintptr_t)ptr_location + re.value;
		}
	}

	return out;
}

#endif /* KFTF_H */
