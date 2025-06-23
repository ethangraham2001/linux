#ifndef KFTF_H
#define KFTF_H

#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ethan Graham <ethangraham@google.com>");
MODULE_DESCRIPTION("Kernel Fuzz Testing Framework (KFTF)");

struct kftf_test_case {
	const char *name;
	const char *arg_type_name;
	ssize_t (*write_input_cb)(struct file *filp, const char __user *buf,
				  size_t len, loff_t *off);
	ssize_t (*read_metadata_cb)(struct file *, char __user *, size_t,
				    loff_t *);
};

/**
 * Shared buffer used for copying data out of userspace
 */
static char kftf_input_buf[128];

/**
 * Expected usage: 
 *
 * ```
 * FUZZ_TEST(func, func_arg_type)
 * ret = func(arg.arg1, arg.arg2, ..., arg.argn);
 * validate(ret);
 * }
 * ```
 *
 * The created structure will be registered by the kftf module, which creates
 * a debugfs entry for it. The write callback is such that it accepts valid
 * struct instances as input.
 */
#define FUZZ_TEST(func, func_arg_type)                                         \
	/* forward decls */                                                    \
	static ssize_t _write_callback_##func(struct file *filp,               \
					      const char __user *buf,          \
					      size_t len, loff_t *off);        \
	static ssize_t _read_metadata_callback_##func(                         \
		struct file *filp, char __user *buf, size_t len, loff_t *off); \
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
		int bytes_to_copy;                                             \
		int message_len = strlen(__fuzz_test__##func.arg_type_name);   \
		if (*off >= message_len) {                                     \
			return -EINVAL;                                        \
		}                                                              \
		bytes_to_copy = message_len - *off;                            \
		if (bytes_to_copy > len) {                                     \
			bytes_to_copy = len;                                   \
		}                                                              \
		if (copy_to_user(buf,                                          \
				 __fuzz_test__##func.arg_type_name + *off,     \
				 bytes_to_copy) != 0) {                        \
			return -EFAULT;                                        \
		}                                                              \
		*off += bytes_to_copy;                                         \
		return bytes_to_copy;                                          \
	}                                                                      \
	/* user-defined write callback */                                      \
	static ssize_t _write_callback_##func(struct file *filp,               \
					      const char __user *buf,          \
					      size_t len, loff_t *off)         \
	{                                                                      \
		pr_info("invoke %s", __FUNCTION__);                            \
		if (len >= sizeof(kftf_input_buf))                             \
			return -EINVAL;                                        \
		if (simple_write_to_buffer((void *)kftf_input_buf,             \
					   sizeof(kftf_input_buf) - 1, off,    \
					   buf, len) < 0)                      \
			return -EFAULT;                                        \
		if (len != sizeof(func_arg_type)) {                            \
			pr_warn("incorrect data size\n");                      \
			return -EINVAL;                                        \
		}                                                              \
		func_arg_type *arg = (void *)kftf_input_buf;

#endif /* KFTF_H */
