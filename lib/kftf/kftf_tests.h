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
	kftf_fuzzable(arg.first, arg.second, arg.third);
}

struct my_fun_func_arg {
	const char *string;
	char *buffer;
	size_t buffer_size;
};

static void my_fun_func(const char *string, char *buffer, size_t buffer_size)
{
	size_t i;
	/* string should be NULL terminated! */
	pr_info("this is my string: %s", string);

	for (i = 0; i < buffer_size; i++) {
		buffer[i]++;
		pr_info("buffer[%zu] = %c\n", i, buffer[i]);
	}
}

FUZZ_TEST(my_memncpy, struct my_fun_func_arg)
{
	const char *kernel_string;
	char *kernel_buffer;

	KFTF_ANNOTATE_STRING(my_fun_func_arg, string);
	KFTF_ANNOTATE_LEN(my_fun_func_arg, buffer_size, buffer);
	KFTF_EXPECT_NOT_NULL(my_fun_func_arg, string);
	KFTF_EXPECT_NOT_NULL(my_fun_func_arg, buffer);

	kernel_string = strndup_user(arg.string, PAGE_SIZE);
	if (!kernel_string || IS_ERR(kernel_string))
		return;

	kernel_buffer = memdup_user(arg.buffer, arg.buffer_size);
	if (!kernel_buffer || IS_ERR(kernel_buffer)) {
		kfree(kernel_string);
		return;
	}

	my_fun_func(kernel_string, kernel_buffer, arg.buffer_size);
	kfree(kernel_string);
	kfree(kernel_buffer);
}

#endif /* KFTF_TESTS_H */
