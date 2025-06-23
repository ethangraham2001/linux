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
 * Expected usage: 
 *
 * ```
 * FUZZ_TEST(func, func_arg_type) {
 *	ret = func(arg.arg1, arg.arg2, ..., arg.argn);
 *	validate(ret);
 * }
 * ```
 *
 * The created structure will be registered by the kftf module, which creates
 * a debugfs entry for it. The write callback is such that it accepts valid
 * struct instances as input.
 */
#define FUZZ_TEST(func, func_arg_type)                                         \
	/* input buffer. Size 1 for now, but we may support batching  */       \
	static func_arg_type input_buf_##func[2];                              \
	/* guard the buffer as concurrent processes could race */              \
	DEFINE_MUTEX(input_mutex_##func);                                      \
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
		pr_info("invoke %s\n", __FUNCTION__);                          \
		if (len >= sizeof(input_buf_##func)) {                         \
			mutex_unlock(&input_mutex_##func);                     \
			return -EINVAL;                                        \
		}                                                              \
		if (simple_write_to_buffer((void *)input_buf_##func,           \
					   sizeof(input_buf_##func) - 1, off,  \
					   buf, len) < 0) {                    \
			pr_info("unable to read from buffer!\n");              \
			mutex_unlock(&input_mutex_##func);                     \
			return -EFAULT;                                        \
		}                                                              \
		if (len != sizeof(func_arg_type)) {                            \
			pr_info("incorrect data size\n");                      \
			mutex_unlock(&input_mutex_##func);                     \
			return -EINVAL;                                        \
		}                                                              \
		/* XXX: no batching support, so just take the only elem */     \
		func_arg_type arg = input_buf_##func[0];                       \
		/* call the user's logic on the provided arg. */               \
		/* NOTE: define some success/failure return types? */          \
		pr_info("invoking fuzz logic\n");                              \
		_fuzz_test_logic_##func(arg);                                  \
		mutex_unlock(&input_mutex_##func);                             \
		return len;                                                    \
	}                                                                      \
	static void _fuzz_test_logic_##func(func_arg_type arg)

#endif /* KFTF_H */
