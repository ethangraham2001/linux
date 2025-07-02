/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel Fuzz Testing Framework (KFTF) - Core Module
 *
 * This module is responsible for discovering and initializing all fuzz test
 * cases defined using the FUZZ_TEST() macro. It creates a debugfs interface
* under /sys/kernel/debug/kftf/ for userspace to interact with each test.
*/
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/kftf.h>
#include <linux/printk.h>
#include "kftf_tests.h"

#include "kftf_tests.h"

extern const struct kftf_test_case __kftf_test_case_start[];
extern const struct kftf_test_case __kftf_test_case_end[];
extern const struct kftf_constraint __kftf_constraint_start[];
extern const struct kftf_constraint __kftf_constraint_end[];

/**
 * struct kftf_dentry - A container for a debugfs dentry and its fops.
 * @dentry: Pointer to the created debugfs dentry.
 * @fops: The file_operations struct associated with this dentry.
 *
 * This simplifies state management by keeping a file's dentry and its
 * operations bundled together.
 */
struct kftf_dentry {
	struct dentry *dentry;
	struct file_operations fops;
};

/**
 * struct kftf_debugfs_state - Per-test-case debugfs state.
 * @test_dir: The top-level debugfs directory for a single test case, e.g.,
 * /sys/kernel/debug/kftf/<test-name>/.
 * @input_dentry: The state for the "input" file, which is write-only.
 * @metadata_dentry: The state for the "metadata" file, which is read-only.
 *
 * Wraps all debugfs components created for a single test case.
 */
struct kftf_debugfs_state {
	struct dentry *test_dir;
	struct kftf_dentry input_dentry;
	struct kftf_dentry metadata_dentry;
};

/**
 * struct kftf_simple_fuzzer_state - Global state for the KFTF module.
 * @kftf_dir: The root debugfs directory, /sys/kernel/debug/kftf/.
 * @debugfs_state: A statically sized array holding the state for each
 *	registered test case.
 */
struct kftf_simple_fuzzer_state {
	struct file_operations fops;
	struct dentry *kftf_dir;
	struct kftf_debugfs_state *debugfs_state;
};

/* Global static variable to hold all state for the module. */
static struct kftf_simple_fuzzer_state st;

/*
 * Default file permissions for the debugfs entries.
 * 0222: World-writable for the 'input' file.
 * 0444: World-readable for the 'metadata' file.
 *
 * XXX: should formally define what the permissions should be on these files
 */
const umode_t kftf_flags_w = 0222;
const umode_t kftf_flags_r = 0444;

/**
 * kftf_init - Initializes the debug filesystem for KFTF.
 *
 * This function is the entry point for the KFTF module, populating the debugfs
 * that is used for IO interaction between the individual fuzzing drivers and
 * a userspace fuzzing tool like syzkaller.
 *
 * Each registered test in the ".kftf" section gets its own subdirectory
 * under "/sys/kernel/debug/kftf/<test-name>" with two files:
 *	- input: write-only file to send input to the fuzz driver
 *	- metadata: used to read the type name that the fuzz driver expects
 *
 * Returns:
 * 0 on success.
 * -EINVAL if the number of tests exceeds KFTF_MAX_TEST_CASES
 * -ENODEV or other error codes if debugfs creation fails.
 */
static int __init kftf_init(void)
{
	const struct kftf_test_case *test;
	const struct kftf_constraint *constraint;
	int ret = 0;
	int i = 0;
	size_t num_test_cases;

	num_test_cases = __kftf_test_case_end - __kftf_test_case_start;

	st.debugfs_state = kmalloc(
		num_test_cases * sizeof(struct kftf_debugfs_state), GFP_KERNEL);
	if (!st.debugfs_state)
		return -ENOMEM;

	/* create the main "kftf" directory in `/sys/kernel/debug` */
	st.kftf_dir = debugfs_create_dir("kftf", NULL);
	if (!st.kftf_dir) {
		pr_warn("kftf: could not create debugfs");
		return -ENODEV;
	}

	if (IS_ERR(st.kftf_dir)) {
		st.kftf_dir = NULL;
		return PTR_ERR(st.kftf_dir);
	}

	/* iterate over all discovered test cases and set up debugfs entries */
	for (test = __kftf_test_case_start; test < __kftf_test_case_end;
	     test++, i++) {
		/* create a directory for the discovered test case */
		st.debugfs_state[i].test_dir =
			debugfs_create_dir(test->name, st.kftf_dir);

		if (!st.debugfs_state[i].test_dir) {
			ret = -ENOMEM;
			goto cleanup_failure;
		} else if (IS_ERR(st.debugfs_state[i].test_dir)) {
			ret = PTR_ERR(st.debugfs_state[i].test_dir);
			goto cleanup_failure;
		}

		/* create "input" file for fuzz test */
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

		/* create "metadata" file for fuzz test */
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

		pr_info("kftf: registered %s\n", test->name);
	}

	// TODO: make debugfs entries for these constraints
	size_t num_constraints = 0;
	for (constraint = __kftf_constraint_start;
	     constraint < __kftf_constraint_end; constraint++) {
		pr_info("kftf: addr = 0x%lX\n", (size_t)constraint);
		pr_info("input type: %s\n", constraint->input_type);
		pr_info("field name: %s\n", constraint->field_name);
		pr_info("value1:     %lx\n", constraint->value1);
		pr_info("value2:     %lx\n", constraint->value2);
		pr_info("type:       %d\n", constraint->type);
		num_constraints++;
	}

	return 0;

cleanup_failure:
	debugfs_remove_recursive(st.kftf_dir);
	return ret;
}

/**
 * kftf_exit - Cleans up the module.
 */
static void __exit kftf_exit(void)
{
	pr_info("kftf: shutting down\n");
	if (!st.kftf_dir)
		return;

	debugfs_remove_recursive(st.kftf_dir);
	st.kftf_dir = NULL;
}

module_init(kftf_init);
module_exit(kftf_exit);
