#ifndef KFTF_SIMPLE_FUZZER_H
#define KFTF_SIMPLE_FUZZER_H

#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/kftf.h>

struct kftf_simple_fuzzer_state {
	struct file_operations fops;
	struct dentry *kftf_dir;
	struct dentry *input_file;
	char buffer[128]; //< buffer for user input
};

static struct kftf_simple_fuzzer_state st;

/**
 * write callback for the simple fuzzer
 */
static ssize_t kftf_fuzz_write(struct file *filp, const char __user *buf,
			       size_t len, loff_t *off)
{
	if (len >= sizeof(st.buffer))
		return -EINVAL;

	if (simple_write_to_buffer(st.buffer, sizeof(st.buffer) - 1, off, buf,
				   len) < 0)
		return -EFAULT;

	if (len != sizeof(struct kftf_simple_arg)) {
		pr_warn("incorrect data size\n");
		return -EINVAL;
	}

	// intrepret the binary contents of the buffer
	struct kftf_simple_arg *fuzz_arg = (void *)st.buffer;
	kftf_fuzzable(fuzz_arg);
	return len;
}

static int kftf_simple_fuzzer_init(void)
{
	st.kftf_dir = debugfs_create_dir("kftf", NULL);
	if (!st.kftf_dir)
		return 1; // TODO: proper errors

	st.fops = (struct file_operations){
		.owner = THIS_MODULE,
		.write = kftf_fuzz_write,
	};

	st.input_file =
		debugfs_create_file("input", 0222, st.kftf_dir, NULL, &st.fops);

	if (!st.input_file)
		return 1; // TODO: proper errors

	return 0;
}

static void kftf_simple_fuzzer_cleanup(void)
{
	debugfs_remove(st.kftf_dir);
}

#endif /* KFTF_SIMPLE_FUZZER_H */
