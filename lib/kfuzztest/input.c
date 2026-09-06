/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KFuzzTest input handling.
 *
 * Copyright 2025 Google LLC
 */
#include <linux/kfuzztest.h>

static int parse_kfuzztest_input(const char *buf, size_t len, struct kfuzztest_input_seq **ret)
{
	size_t successfully_init_args = 0;
	struct kfuzztest_input_seq *out;
	char *dedicated_buffer;
	size_t i;
	int err;

	pr_info("parsing input");
	pr_info("pointer = %px", buf);

	out = kzalloc(sizeof(struct kfuzztest_input_seq), GFP_KERNEL);
	if (!out)
		return -ENOMEM;
	else if (IS_ERR(out))
		return PTR_ERR(out);

	/* Parse the initialization argument. */
	char *cursor = (char *)buf;
	out->init_arg_size = *(size_t *)(cursor);
	cursor += sizeof(size_t);
	out->init_arg = kmalloc(out->init_arg_size, GFP_KERNEL);
	memcpy(out->init_arg, cursor, out->init_arg_size);
	cursor += out->init_arg_size;

	out->num_args = *(size_t *)(cursor);
	cursor += sizeof(size_t);
	out->args = kmalloc(out->num_args * sizeof(struct kfuzztest_input), GFP_KERNEL);

	for (i = 0; i < out->num_args; i++, successfully_init_args++) {
		out->args[i].op_code = *(size_t *)(cursor);
		out->args[i].arg_size = *(size_t *)(cursor + sizeof(size_t));
		cursor += 2 * sizeof(size_t);

		dedicated_buffer = kmalloc(out->args[i].arg_size, GFP_KERNEL);
		if (!dedicated_buffer) {
			err = -ENOMEM;
			goto fail;
		} else if (IS_ERR(dedicated_buffer)) {
			err = PTR_ERR(dedicated_buffer);
			goto fail;
		}
		out->args[i].arg_data = dedicated_buffer;
		memcpy(out->args[i].arg_data, cursor, out->args[i].arg_size);
		cursor += out->args[i].arg_size;
	}

	*ret = out;
	return 0;

fail:
	for (i = 0; i < successfully_init_args; i++)
		kfree(out->args[i].arg_data);
	return err;
};

static int kfuzztest_invoke(const struct kfuzztest_harness *harness, struct kfuzztest_input_seq *in)
{
	struct kfuzztest_input arg;
	void *component;
	size_t i;
	int ret;

	pr_info("invoking with %zu calls", in->num_args);

	component = harness->initialize_fn(in->init_arg_size, in->init_arg);
	for (i = 0; i < in->num_args; i++) {
		pr_info("operation start: %zu", i);
		arg = in->args[i];
		ret = harness->operations[arg.op_code](component, arg.arg_size, arg.arg_data);
		if (ret != 0)
			return ret;
		ret = harness->check_correctness_fn(component);
		if (!ret)
			pr_warn("input %zu failed correctness check", i);
		pr_info("operation end: %zu", i);
	}
	harness->teardown_fn(component);

	pr_info("input passed correctness checks");
	return 0;
}

static int kfuzztest_invoke_harness(const struct kfuzztest_harness *harness, char *data, size_t datalen)
{
	struct kfuzztest_input_seq *in;
	int ret;

	ret = parse_kfuzztest_input(data, datalen, &in);
	if (ret)
		return ret;
	return kfuzztest_invoke(harness, in);
}

static int kfuzztest_write_cb_common(struct file *filp, const char __user *buf, size_t len, loff_t *off,
				     void **test_buffer)
{
	void *buffer;
	ssize_t ret;

	/*
	 * Enforce a zero-offset to ensure that all data is passed down in a
	 * single contiguous blob and not fragmented across multiple write
	 * system calls.
	 */
	if (*off)
		return -EINVAL;

	/*
	 * Taint the kernel on the first fuzzing invocation. The debugfs
	 * interface provides a high-risk entry point for userspace to
	 * call kernel functions with untrusted input.
	 */
	if (!test_taint(TAINT_TEST))
		add_taint(TAINT_TEST, LOCKDEP_STILL_OK);

	if (len > KFUZZTEST_MAX_INPUT_SIZE) {
		pr_warn("kfuzztest: user input of size %zu is too large", len);
		return -EINVAL;
	}

	buffer = kzalloc(len, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	ret = simple_write_to_buffer(buffer, len, off, buf, len);
	if (ret != len) {
		kfree(buffer);
		return -EFAULT;
	}

	*test_buffer = buffer;
	return 0;
}

int kfuzztest_harness_on_write(const struct kfuzztest_harness *harness, struct file *filp, const char __user *buf,
			       size_t len, loff_t *off)
{
	char *data;
	int ret;

	pr_info("invoke %s", harness->name);

	ret = kfuzztest_write_cb_common(filp, buf, len, off, (void **)&data);
	if (ret)
		return ret;

	pr_info("received input of length %zu", len);

	ret = kfuzztest_invoke_harness(harness, data, len);
	kfree(data);
	return ret ? ret : len;
}
