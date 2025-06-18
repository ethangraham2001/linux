#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/printk.h>
#include <linux/kftf.h>

#include "kftf_simple_fuzzer.h"

// contains a bug!
void kftf_fuzzable(struct kftf_simple_arg *foo)
{
	// can buffer overflow or underflow, or cause a null pointer dereference
	// crashing the kernel
	char *data = ((char *)foo) + foo->access;
	pr_info("%s: foo->data = %d\n", __FUNCTION__, foo->data);
	pr_info("%s: data at foo[%d] = %x\n", __FUNCTION__, foo->access, *data);
}

static int __init kftf_init(void)
{
	return kftf_simple_fuzzer_init();
}

static void __exit kftf_exit(void)
{
	kftf_simple_fuzzer_cleanup();
}

module_init(kftf_init);
module_exit(kftf_exit);
