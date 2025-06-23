#include "kftf_tests.h"
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/printk.h>
#include <linux/kftf.h>

extern const struct kftf_test_case __kftf_start[];
extern const struct kftf_test_case __kftf_end[];

#define KFTF_MAX_TEST_CASES 1024

/// defines a dentry with file-operations
struct kftf_dentry {
	struct dentry *dentry;
	struct file_operations fops;
};

/**
 * Wraps teh state of the created
 */
struct kftf_debugfs_state {
	struct dentry *test_dir;
	struct kftf_dentry input_dentry;
	struct kftf_dentry metadata_dentry;
};

struct kftf_simple_fuzzer_state {
	struct file_operations fops;
	struct dentry *kftf_dir;
	struct kftf_debugfs_state
		debugfs_state[KFTF_MAX_TEST_CASES]; // FIXME: fine for WIP
};

static struct kftf_simple_fuzzer_state st;

// XXX: be careful of flags here
const umode_t kftf_flags_w = 0666;
const umode_t kftf_flags_r = 0444;

static int __init kftf_init(void)
{
	int ret = 0;

	// To avoid kmalloc entirely, we enforce a maximum number of fuzz tests
	// that can be defined inside the kernel.
	size_t num_test_cases = __kftf_end - __kftf_start;
	if (num_test_cases > KFTF_MAX_TEST_CASES)
		return -EINVAL;

	st.kftf_dir = debugfs_create_dir("kftf", NULL);
	if (!st.kftf_dir) {
		pr_warn("kftf: could not create debugfs");
		return -ENODEV;
	}

	if (IS_ERR(st.kftf_dir)) {
		st.kftf_dir = NULL;
		return PTR_ERR(st.kftf_dir);
	}

	const struct kftf_test_case *test;
	int i = 0; // XXX: find better way of doing this
	for (test = __kftf_start; test < __kftf_end; test++) {
		st.debugfs_state[i].test_dir =
			debugfs_create_dir(test->name, st.kftf_dir);

		if (!st.debugfs_state[i].test_dir) {
			ret = -ENOMEM;
			goto cleanup_failure;
		} else if (IS_ERR(st.debugfs_state[i].test_dir)) {
			ret = PTR_ERR(st.debugfs_state[i].test_dir);
			goto cleanup_failure;
		}

		st.debugfs_state[i].input_dentry.fops =
			(struct file_operations){
				.owner = THIS_MODULE,
				.write = test->write_input_cb,
			};

		st.debugfs_state[i].input_dentry.dentry = debugfs_create_file(
			"input", kftf_flags_w, st.debugfs_state[i].test_dir,
			NULL, &st.debugfs_state[i].input_dentry.fops);
		if (!st.debugfs_state[i].input_dentry.dentry) {
			ret = -ENOMEM;
			goto cleanup_failure;
		} else if (IS_ERR(st.debugfs_state[i].input_dentry.dentry)) {
			ret = PTR_ERR(st.debugfs_state[i].input_dentry.dentry);
			goto cleanup_failure;
		}

		st.debugfs_state[i].metadata_dentry.fops =
			(struct file_operations){
				.owner = THIS_MODULE,
				.read = test->read_metadata_cb,
			};

		st.debugfs_state[i].metadata_dentry.dentry =
			debugfs_create_file(
				"metadata", kftf_flags_r,
				st.debugfs_state[i].test_dir, NULL,
				&st.debugfs_state[i].metadata_dentry.fops);
		if (!st.debugfs_state[i].metadata_dentry.dentry) {
			ret = -ENOMEM;
			goto cleanup_failure;
		} else if (IS_ERR(st.debugfs_state[i].metadata_dentry.dentry)) {
			ret = PTR_ERR(
				st.debugfs_state[i].metadata_dentry.dentry);
			goto cleanup_failure;
		}

		i++;
		pr_info("kftf: registered %s\n", test->name);
	}

	return 0;

cleanup_failure:
	debugfs_remove_recursive(st.kftf_dir);
	return ret;
}

static void __exit kftf_exit(void)
{
	if (!st.kftf_dir)
		return;

	debugfs_remove_recursive(st.kftf_dir);
	st.kftf_dir = NULL;
}

module_init(kftf_init);
module_exit(kftf_exit);
