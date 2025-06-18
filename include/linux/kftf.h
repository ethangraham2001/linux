#ifndef KFTF_H
#define KFTF_H

#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ethan Graham <ethangraham@google.com>");
MODULE_DESCRIPTION("Kernel Fuzz Testing Framework");

struct foo {
	int size; //< size of struct foo
	int access;
};

void kftf_fuzzable(struct foo *foo);

#endif /* KFTF_H */
