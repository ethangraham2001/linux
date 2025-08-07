// SPDX-License-Identifier: GPL-2.0
/* Copyright 2025 Google LLC */
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
 * We expect to see a KASAN warning by overflowing one byte into the A buffer.
 *
 */
FUZZ_TEST(test_overflow_on_nested_buffer, struct nested_buffers)
{
	KFUZZTEST_EXPECT_NOT_NULL(nested_buffers, a);
	KFUZZTEST_EXPECT_NOT_NULL(nested_buffers, b);
	KFUZZTEST_ANNOTATE_LEN(nested_buffers, a_len, a);
	KFUZZTEST_ANNOTATE_LEN(nested_buffers, b_len, b);

	/* Buffer overflow out of a bounds. This should be caught by KASAN. */
	for (size_t i = 0; i <= arg->a_len; i++)
		READ_ONCE(arg->a[i]);
}
