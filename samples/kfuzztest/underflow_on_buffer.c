// SPDX-License-Identifier: GPL-2.0
/*
 * This file contains a KFuzzTest example target that ensures that a buffer
 * underflow on a region triggers a KASAN OOB access report.
 *
 * Copyright 2025 Google LLC
 */

/**
 * test_underflow_on_buffer - a sample fuzz target
 *
 * This sample fuzz target serves to illustrate the usage of the
 * FUZZ_TEST_SIMPLE macro, as well as provide a sort of self-test that KFuzzTest
 * functions correctly for trivial fuzz targets. In KASAN builds, fuzzing this
 * harness should trigger a report for every input (provided that its length is
 * greater than 0 and less than KFUZZTEST_MAX_INPUT_SIZE).
 *
 * This harness can be invoked (naively) like so:
 * head -c 128 /dev/urandom > \
 *	/sys/kernel/debug/kfuzztest/test_underflow_on_buffer/input_simple
 */
#include <linux/kfuzztest.h>

static void underflow_on_buffer(char *buf, size_t buflen)
{
	size_t i;

	/*
	 * Print the address range of `buf` to allow correlation with the
	 * subsequent KASAN report.
	 */
	pr_info("buf = [%px, %px)", buf, buf + buflen);

	/* First ensure that all bytes in `buf` are accessible. */
	for (i = 0; i < buflen; i++)
		READ_ONCE(buf[i]);
	/*
	 * Provoke a buffer underflow on the first byte preceding `buf`,
	 * triggering a KASAN report.
	 */
	READ_ONCE(*((char *)buf - 1));
}

/**
 * Define the fuzz target. This wrapper ensures that the `underflow_on_buffer`
 * function is invoked with the data provided from userspace.
 */
FUZZ_TEST_SIMPLE(test_underflow_on_buffer)
{
	underflow_on_buffer(data, datalen);
	return 0;
}

struct llnode {
	struct llnode *next;
	int value;
};

struct ll {
	struct llnode *head;
};

static void push(struct ll *ll, int value)
{
	struct llnode *new = kmalloc(sizeof(struct llnode), GFP_KERNEL);
	new->value = value;
	new->next = NULL;

	struct llnode *curr = ll->head;
	if (!curr) {
		ll->head = new;
		return;
	}

	while (curr && curr->next)
		curr = curr->next;
	curr->next = new;
}

static void pop_front(struct ll *ll)
{
	if (!ll->head)
		return;
	struct llnode *head = ll->head;
	ll->head = ll->head->next;
	kfree(head);
}

static void *initialize(size_t datalen, char *data)
{
	return kzalloc(sizeof(struct ll), GFP_KERNEL);
}

static void teardown(void *ll)
{
	struct ll *linked_list = ll;
	struct llnode *curr = linked_list->head;
	while (curr) {
		struct llnode *next = curr->next;
		kfree(curr);
		curr = next;
	}
	kfree(ll);
}

static int op_push(void *comp, size_t datalen, char *data)
{
	struct ll *ll = comp;

	if (datalen < sizeof(int))
		return -1;
	int val = *(int *)data;
	push(ll, val);
	return 0;
}

static int op_pop_front(void *comp, size_t datalen, char *data)
{
	struct ll *ll = comp;
	pop_front(ll);
	return 0;
}

static int check_correctness(void *comp)
{
	/* true. */
	return 1;
}

KFUZZ_REGISTER_HARNESS(ll_fuzz_harness, initialize, teardown, check_correctness, op_push, op_pop_front)
