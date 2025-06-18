#include <linux/printk.h>
#include <linux/kftf.h>

// contains a bug!
void kftf_fuzzable(struct foo *foo)
{
	// can buffer overflow or underflow, or cause a null pointer dereference
	// crashing the kernel
	char *data = ((char *)foo) + foo->access;
	printk("%s: data at foo[%d] = %x\n", __FUNCTION__, foo->access, *data);
}
