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

#define KFUZZTEST_MAX_INPUT_SIZE (PAGE_SIZE * 16)

/**
 * kfuzztest_handle - opaque handle that persists throughout the lifetime of a
 *		      test sequence
 */
typedef void *kfuzztest_handle;

struct kfuzztest_input {
	size_t op_code;
	size_t arg_size;
	char *arg_data;
};

struct kfuzztest_input_seq {
	size_t init_arg_size;
	char *init_arg;
	size_t num_args;
	struct kfuzztest_input *args;
};

/* Define a maximum number of supported operations so that we can iterate over
 * the linker section without a headache. */
#define KFUZZ_MAX_HARNESS_OPS 32

struct __attribute__((aligned(128))) kfuzztest_harness {
	const char *name;
	kfuzztest_handle (*initialize_fn)(size_t, char *);
	void (*teardown_fn)(kfuzztest_handle);
	// Interpreted as bool: 0 = failure, anything 1 = success.
	int (*check_correctness_fn)(kfuzztest_handle);
	int (*operations[KFUZZ_MAX_HARNESS_OPS])(kfuzztest_handle, char *, size_t);
	ssize_t (*on_write)(struct file *filp, const char __user *buf, size_t len, loff_t *off);
};

int kfuzztest_harness_on_write(const struct kfuzztest_harness *harness, struct file *filp, const char __user *buf,
			       size_t len, loff_t *off);

#define KFUZZ_REGISTER_HARNESS(harness_name, init, teardown, check_correctness, ...)                            \
	static ssize_t kfuzztest_on_write_##harness_name(struct file *filp, const char __user *buf, size_t len, \
							 loff_t *off);                                          \
	static const struct kfuzztest_harness __kfuzz_harness_##harness_name __section(".kfuzztest_harness")    \
		__used = { .name = #harness_name,                                                               \
			   .initialize_fn = init,                                                               \
			   .teardown_fn = teardown,                                                             \
			   .check_correctness_fn = check_correctness,                                           \
			   .operations = { __VA_ARGS__ },                                                       \
			   .on_write = kfuzztest_on_write_##harness_name };                                     \
	static ssize_t kfuzztest_on_write_##harness_name(struct file *filp, const char __user *buf, size_t len, \
							 loff_t *off)                                           \
	{                                                                                                       \
		return kfuzztest_harness_on_write(&__kfuzz_harness_##harness_name, filp, buf, len, off);        \
	};

/**
 * Defines an operation with a typed and fixed-sized input.
 *
 * TODO: store in ELF within a dedicated section so that we can export this
 *       information to guide a fuzzer.
 */
#define KFUZZ_OP(op_name, st_type, arg_type)                                  \
	static bool validate_##op_name(size_t datalen)                        \
	{                                                                     \
		return datalen >= sizeof(arg_type);                           \
	}                                                                     \
	static int body_##op_name(st_type *st, arg_type *arg);                \
	static int op_name(kfuzztest_handle comp, char *data, size_t datalen) \
	{                                                                     \
		if (!comp || validate_##op_name(datalen))                     \
			return -EINVAL;                                       \
		return body_##op_name((st_type *)comp, (arg_type *)data);     \
	}                                                                     \
	static int body_##op_name(st_type *st, arg_type *arg)

#endif /* KFUZZTEST_H */
