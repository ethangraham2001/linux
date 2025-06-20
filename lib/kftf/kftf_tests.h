#ifndef KFTF_TESTS_H
#define KFTF_TESTS_H

#include <linux/kftf.h>
#include <linux/math.h>

struct kftf_simple_arg {
	int data;
	int access;
};

// contains a bug!
static void kftf_fuzzable(struct kftf_simple_arg *foo)
{
	// can buffer overflow or underflow, or cause a null pointer dereference
	// crashing the kernel
	char *data = ((char *)foo) + foo->access;
	pr_info("%s: foo->data = %d\n", __FUNCTION__, foo->data);
	pr_info("%s: data at foo[%d] = %x\n", __FUNCTION__, foo->access, *data);
}

FUZZ_TEST(kftf_fuzzable, struct kftf_simple_arg)
kftf_fuzzable(arg);
return len;
}

struct int_sqrt_arg {
	unsigned long x;
};

FUZZ_TEST(int_sqrt, struct int_sqrt_arg)
unsigned long res = int_sqrt(arg->x);
pr_info("fuzz_arg.x = %lu, res = %lu", arg->x, res);
return len;
}

#endif /* KFTF_TESTS_H */
