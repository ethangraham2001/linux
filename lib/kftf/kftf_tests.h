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
				/* do some weird access */
				char value = *(char *)&first + (first * 10 + 1);
				pr_info("dumping ptr %c\b", value);
			}
		}
	}
}

FUZZ_TEST(kftf_fuzzable, struct kftf_simple_arg)
{
	kftf_fuzzable(arg.first, arg.second, arg.third);
}

#endif /* KFTF_TESTS_H */
