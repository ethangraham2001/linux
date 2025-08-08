// SPDX-License-Identifier: GPL-2.0
/*
 * This file contains some KFuzzTest target examples.
 *
 * Copyright 2025 Google LLC
 */
#include <linux/kfuzztest.h>

struct nested_buffers {
	const char *a;
	size_t a_len;
	const char *b;
	size_t b_len;
};

/**
 * The KFuzzTest input format specifies that struct nested buffers should
 * be expanded as:
 *
 * | a | b | pad[8] | *a | pad[8] | *b |
 *
 * where the padded regions are poisoned. We expect to trigger a KASAN report by
 * overflowing one byte into the `a` buffer.
 */
FUZZ_TEST(test_overflow_on_nested_buffer, struct nested_buffers)
{
	size_t i;

	KFUZZTEST_EXPECT_NOT_NULL(nested_buffers, a);
	KFUZZTEST_EXPECT_NOT_NULL(nested_buffers, b);
	KFUZZTEST_ANNOTATE_LEN(nested_buffers, a_len, a);
	KFUZZTEST_ANNOTATE_LEN(nested_buffers, b_len, b);

	pr_info("a = [%px, %px)", arg->a, arg->a + KFUZZTEST_REGION_SIZE(1));
	pr_info("b = [%px, %px)", arg->b, arg->b + KFUZZTEST_REGION_SIZE(2));

	/* Ensure that all bytes in arg->b are accessible. */
	for (i = 0; i < arg->b_len; i++)
		READ_ONCE(arg->b[i]);
	/*
	 * Check that all bytes in arg->a are accessible, and provoke an OOB on
	 * the first byte to the right of the buffer which will trigger a KASAN
	 * report.
	 */
	for (i = 0; i <= arg->a_len; i++)
		READ_ONCE(arg->a[i]);
}

struct some_buffer {
	char *buf;
	size_t buflen;
};

/**
 * Tests that the region between struct some_buffer and the expanded *buf field
 * is correctly poisoned by accessing the first byte before *buf.
 */
FUZZ_TEST(test_underflow_on_buffer, struct some_buffer)
{
	size_t i;

	KFUZZTEST_EXPECT_NOT_NULL(some_buffer, buf);
	KFUZZTEST_ANNOTATE_LEN(some_buffer, buflen, buf);

	pr_info("buf = [%px, %px)", arg->buf, arg->buf + arg->buflen);

	/* First ensure that all bytes in arg->b are accessible. */
	for (i = 0; i < arg->buflen; i++)
		READ_ONCE(arg->buf[i]);
	/*
	 * Provoke a buffer overflow on the first byte preceding b, triggering
	 * a KASAN report.
	 */
	READ_ONCE(*((char *)arg->buf - 1));
}
