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
	KFUZZTEST_EXPECT_NOT_NULL(some_input, a);
	KFUZZTEST_EXPECT_NOT_NULL(some_input, b);
	KFUZZTEST_ANNOTATE_LEN(some_input, a_len, a);
	KFUZZTEST_ANNOTATE_LEN(some_input, b_len, b);

	volatile char c;
	pr_info("a = [%px, %px)", arg->a, arg->a + arg->a_len);
	/* Buffer overflow out of a bounds. This should be caught by KASAN. */
	for (size_t i = 0; i <= arg->a_len; i++)
		c = arg->a[i];
}

#endif /* KFUZZTEST_EXAMPLES_H */
