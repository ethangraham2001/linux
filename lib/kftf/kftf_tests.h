#ifndef KFTF_TESTS_H
#define KFTF_TESTS_H

#include <linux/kftf.h>
#include <linux/math.h>

struct kftf_simple_arg {
	int data;
	int access;
};

// contains a bug!
static void kftf_fuzzable(int access, int data, void *ptr)
{
	// can buffer overflow or underflow, or cause a null pointer dereference
	// crashing the kernel
	char access_data = *(((char *)ptr) + access);
	pr_info("%s: data = %0x\n", __FUNCTION__, data);
	pr_info("%s: data at ptr[%d] = %x\n", __FUNCTION__, access,
		access_data);
}

FUZZ_TEST(kftf_fuzzable, struct kftf_simple_arg)
kftf_fuzzable(arg->access, arg->data, &arg);
return len;
}

#endif /* KFTF_TESTS_H */
