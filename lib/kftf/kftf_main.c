#include <linux/printk.h>
#include <linux/kftf.h>

// contains a bug!
void kftf_fuzzable(struct foo *foo)
{
	// can buffer overflow or underflow, or cause a null pointer dereference
	// crashing the kernel
	char *data = ((char *)foo) + foo->access;
	pr_info("%s: data at foo[%d] = %x\n", __FUNCTION__, foo->access, *data);
}

static int __init kftf_init(void)
{
	struct foo foo = {
		.access = -1,
		.size = 0,
	};

	pr_info("%s: enter\n", __FUNCTION__);
	kftf_fuzzable(&foo);
	return 0;
}

static void __exit kftf_exit(void)
{
	pr_info("%s: exiting\n", __FUNCTION__);
}

module_init(kftf_init);
module_exit(kftf_exit);
