/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KFUZZTEST_EXAMPLES_H
#define KFUZZTEST_EXAMPLES_H

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
 * In DISTINCT mode, this will result in 3 distinct kmalloc'd regions, and
 * in POISONED mode, the buffer is untouched but the padding will be poisoned.
 *
 * In this test case, we look to see that a KASAN warning is triggered in both
 * cases when overflowing on *a by one.
 */
FUZZ_TEST(test_overflow_on_nested_buffer, struct nested_buffers)
{
	u32 a_size;
	u32 b_size;

	KFUZZTEST_EXPECT_NOT_NULL(nested_buffers, a);
	KFUZZTEST_EXPECT_NOT_NULL(nested_buffers, b);
	KFUZZTEST_ANNOTATE_LEN(nested_buffers, a_len, a);
	KFUZZTEST_ANNOTATE_LEN(nested_buffers, b_len, b);

	volatile char c;
	pr_info("a = [%px, %px)", arg->a, arg->a + arg->a_len);
	pr_info("b = [%px, %px)", arg->b, arg->b + arg->b_len);
	pr_info("a_len = %zu", arg->a_len);
	pr_info("b_len = %zu", arg->b_len);

	a_size = KFUZZTEST_REGION_SIZE(1);
	b_size = KFUZZTEST_REGION_SIZE(2);
	pr_info("actual sizes = %u, %u", a_size, b_size);

	/* Buffer overflow out of a bounds. This should be caught by KASAN. */
	for (size_t i = 0; i <= a_size; i++)
		c = arg->a[i];
}

#endif /* KFUZZTEST_EXAMPLES_H */
