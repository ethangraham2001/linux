#ifndef KFTF_TESTS_H
#define KFTF_TESTS_H

#include <linux/kftf.h>
#include <linux/math.h>

struct nested {
	char value;
};
struct top_level {
	struct nested nested;
};

struct kftf_simple_arg {
	struct top_level first;
	struct nested second;
	struct top_level third;
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
	// XXX: we need to figure out how to handle nested struct fields,
	// whoops!
	kftf_fuzzable(arg->first.nested.value, arg->second.value,
		      arg->third.nested.value);
}

struct my_fun_func_arg {
	const char *string;
	char *buffer;
	size_t buffer_size;
};

volatile char __w;
static void my_fun_func(const char *string, char *buffer, size_t buffer_size)
{
	size_t i;
	/* string should be NULL terminated! */
	pr_info("string length = %zu",
		strlen(string) + 1 /* null terminated str */);
	pr_info("buffer_size = %zu\n", buffer_size);

	for (i = 0; i < buffer_size; i++) {
		buffer[i]++;
		__w = buffer[i]; // avoid inlining
	}
}

FUZZ_TEST(my_memncpy, struct my_fun_func_arg)
{
	pr_info("[ENTER] %s\n", __FUNCTION__);

	KFTF_ANNOTATE_STRING(my_fun_func_arg, string);
	KFTF_ANNOTATE_LEN(my_fun_func_arg, buffer_size, buffer);
	KFTF_EXPECT_NOT_NULL(my_fun_func_arg, string);
	KFTF_EXPECT_NOT_NULL(my_fun_func_arg, buffer);
	my_fun_func(arg->string, arg->buffer, arg->buffer_size);
}

#endif /* KFTF_TESTS_H */
