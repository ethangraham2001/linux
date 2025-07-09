#ifndef KFTF_TESTS_H
#define KFTF_TESTS_H

#include <linux/kftf.h>
#include <linux/math.h>

struct kftf_simple_arg {
	char first;
	char second;
	char third;
};

// contains a bug!
static void kftf_fuzzable(char first, char second, char third)
{
	// can buffer overflow or underflow, or cause a null pointer dereference
	// crashing the kernel
	if (first == 'a') {
		pr_info("first was a");
		if (second == 'b') {
			pr_info("second was b");
			if (third == 'c') {
				pr_info("third was c");
				volatile char *ptr = (void *)0xBEEF;
				pr_info("reading %p: 0x%x", ptr, *(uint *)ptr);
			}
		}
	}
}

FUZZ_TEST(kftf_fuzzable, struct kftf_simple_arg)
{
	KFTF_EXPECT_NOT_NULL(kftf_simple_arg, first);
	KFTF_EXPECT_IN_RANGE(kftf_simple_arg, second, 'a', 'z');
	KFTF_EXPECT_IN_RANGE(kftf_simple_arg, third, 'a', 'z');
	kftf_fuzzable(arg->first, arg->second, arg->third);
}

#endif /* KFTF_TESTS_H */
