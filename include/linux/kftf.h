#ifndef KFTF_H
#define KFTF_H

#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ethan Graham <ethangraham@google.com>");
MODULE_DESCRIPTION("Kernel Fuzz Testing Framework");

struct kftf_simple_arg {
	int data;
	int access;
};

void kftf_fuzzable(struct kftf_simple_arg *foo);

#endif /* KFTF_H */
