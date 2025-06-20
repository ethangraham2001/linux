#include "kftf_tests.h"
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/printk.h>
#include <linux/kftf.h>

extern const struct kftf_test_case __kftf_start[];
extern const struct kftf_test_case __kftf_end[];

struct kftf_debugfs_state {
	struct file_operations fops;
	struct dentry *test_dir;
	struct dentry *input_file;
};

struct kftf_simple_fuzzer_state {
	struct file_operations fops;
	struct dentry *kftf_dir;
	struct kftf_debugfs_state debugfs_state[1024]; // FIXME: fine for WIP
};

static struct kftf_simple_fuzzer_state st;

// XXX: allows everyone to write - correct flags?
const umode_t kftf_debug_fs_flags = 0222;

static int __init kftf_init(void)
{
	int ret = 0;

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

		st.debugfs_state[i].fops = (struct file_operations){
			.owner = THIS_MODULE,
			.write = test->write_callback,
		};

		st.debugfs_state[i].input_file =
			debugfs_create_file("input", kftf_debug_fs_flags,
					    st.debugfs_state[i].test_dir, NULL,
					    &st.debugfs_state[i].fops);

		if (!st.debugfs_state[i].input_file) {
			ret = -ENOMEM;
			goto cleanup_failure;
		} else if (IS_ERR(st.debugfs_state[i].input_file)) {
			ret = PTR_ERR(st.debugfs_state[i].input_file);
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
