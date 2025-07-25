/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel Fuzz Testing Framework (KFuzzTest) - Core Module
 *
 * This module is responsible for discovering and initializing all fuzz test
 * cases defined using the FUZZ_TEST() macro. It creates a debugfs interface
 * under /sys/kernel/debug/kfuzztest/ for userspace to interact with each test.
 */
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/kfuzztest.h>
#include <linux/printk.h>

extern const struct kfuzztest_target __kfuzztest_targets_start[];
extern const struct kfuzztest_target __kfuzztest_targets_end[];

/**
 * struct kfuzztest_dentry - A container for a debugfs dentry and its fops.
 * @dentry: Pointer to the created debugfs dentry.
 * @fops: The file_operations struct associated with this dentry.
 *
 * This simplifies state management by keeping a file's dentry and its
 * operations bundled together.
 */
struct kfuzztest_dentry {
	struct dentry *dentry;
	struct file_operations fops;
};

/**
 * struct kfuzztest_debugfs_state - Per-test-case debugfs state.
 * @test_dir: The top-level debugfs directory for a single test case, e.g.,
 * /sys/kernel/debug/kfuzztest/<test-name>/.
 * @input_dentry: The state for the "input" file, which is write-only.
 *
 * Wraps all debugfs components created for a single test case.
 */
struct kfuzztest_debugfs_state {
	struct dentry *target_dir;
	struct kfuzztest_dentry input_dentry;
};

/**
 * struct kfuzztest_simple_fuzzer_state - Global state for the KFTF module.
 * @kfuzztest_dir: The root debugfs directory, /sys/kernel/debug/kfuzztest/.
 * @debugfs_state: A statically sized array holding the state for each
 *	registered test case.
 */
struct kfuzztest_state {
	struct file_operations fops;
	struct dentry *kfuzztest_dir;
	struct kfuzztest_debugfs_state *debugfs_state;
};

/* Global static variable to hold all state for the module. */
static struct kfuzztest_state st;

/**
 * Default file permissions for the debugfs entries.
 * 0222: World-writable for the 'input' file.
 *
 * XXX: should formally define what the permissions should be on these files.
 */
const umode_t kfuzztest_flags_w = 0222;

/**
 * kfuzztest_init - Initializes the debug filesystem for KFuzzTest.
 *
 * Each registered test in the ".kfuzztest" section gets its own subdirectory
 * under "/sys/kernel/debug/kfuzztest/<test-name>" with one files:
 *	- input: write-only file to send input to the fuzz driver
 *
 * Returns:
 *	0 on success.
 *	-ENODEV or other error codes if debugfs creation fails.
 */
static int __init kfuzztest_init(void)
{
	const struct kfuzztest_target *targ;
	int ret = 0;
	int i = 0;
	size_t num_test_cases;

	num_test_cases = __kfuzztest_targets_end - __kfuzztest_targets_start;

	st.debugfs_state =
		kmalloc(num_test_cases * sizeof(struct kfuzztest_debugfs_state),
			GFP_KERNEL);
	if (!st.debugfs_state)
		return -ENOMEM;
	else if (IS_ERR(st.debugfs_state))
		return PTR_ERR(st.debugfs_state);

	/* Create the main "kfuzztest" directory in /sys/kernel/debug. */
	st.kfuzztest_dir = debugfs_create_dir("kfuzztest", NULL);
	if (!st.kfuzztest_dir) {
		pr_warn("KFuzzTest: could not create debugfs");
		return -ENODEV;
	}

	if (IS_ERR(st.kfuzztest_dir)) {
		st.kfuzztest_dir = NULL;
		return PTR_ERR(st.kfuzztest_dir);
	}

	for (targ = __kfuzztest_targets_start; targ < __kfuzztest_targets_end;
	     targ++, i++) {
		/* Create debugfs directory for the target. */
		st.debugfs_state[i].target_dir =
			debugfs_create_dir(targ->name, st.kfuzztest_dir);

		if (!st.debugfs_state[i].target_dir) {
			ret = -ENOMEM;
			goto cleanup_failure;
		} else if (IS_ERR(st.debugfs_state[i].target_dir)) {
			ret = PTR_ERR(st.debugfs_state[i].target_dir);
			goto cleanup_failure;
		}

		/* Create an input file under the target's directory. */
		st.debugfs_state[i].input_dentry.fops =
			(struct file_operations){
				.owner = THIS_MODULE,
				.write = targ->write_input_cb,
			};
		st.debugfs_state[i].input_dentry.dentry = debugfs_create_file(
			"input", kfuzztest_flags_w,
			st.debugfs_state[i].target_dir, NULL,
			&st.debugfs_state[i].input_dentry.fops);
		if (!st.debugfs_state[i].input_dentry.dentry) {
			ret = -ENOMEM;
			goto cleanup_failure;
		} else if (IS_ERR(st.debugfs_state[i].input_dentry.dentry)) {
			ret = PTR_ERR(st.debugfs_state[i].input_dentry.dentry);
			goto cleanup_failure;
		}

		pr_info("KFuzzTest: registered target %s\n", targ->name);
	}

	return 0;

cleanup_failure:
	debugfs_remove_recursive(st.kfuzztest_dir);
	return ret;
}

static void __exit kfuzztest_exit(void)
{
	pr_info("KFuzzTest: exiting\n");
	if (!st.kfuzztest_dir)
		return;

	debugfs_remove_recursive(st.kfuzztest_dir);
	st.kfuzztest_dir = NULL;

	if (st.debugfs_state) {
		kfree(st.debugfs_state);
		st.debugfs_state = NULL;
	}
}

module_init(kfuzztest_init);
module_exit(kfuzztest_exit);
