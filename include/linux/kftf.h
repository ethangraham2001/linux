#ifndef KFTF_H
#define KFTF_H

#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ethan Graham <ethangraham@google.com>");
MODULE_DESCRIPTION("Kernel Fuzz Testing Framework (KFTF)");

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

static int write_input_cb_common(struct file *filp, const char __user *buf,
				 size_t len, loff_t *off, void *arg,
				 size_t arg_size)
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
	static void _fuzz_test_logic_##func(func_arg_type arg);                \
	/* test case struct initialization */                                  \
	const struct kftf_test_case __fuzz_test__##func                        \
		__attribute__((__section__(".kftf"), __used__)) = {            \
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
		int err;                                                       \
		func_arg_type arg;                                             \
		err = write_input_cb_common(filp, buf, len, off, &arg,         \
					    sizeof(arg));                      \
		if (err != 0) {                                                \
			return err;                                            \
		}                                                              \
		/* call the user's logic on the provided arg. */               \
		/* NOTE: define some success/failure return types? */          \
		pr_info("invoking fuzz logic for %s\n", #func);                \
		_fuzz_test_logic_##func(arg);                                  \
		return len;                                                    \
	}                                                                      \
	static void _fuzz_test_logic_##func(func_arg_type arg)

#endif /* KFTF_H */
