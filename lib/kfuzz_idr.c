// SPDX-License-Identifier: GPL-2.0
/*
 * KFuzzTest stateful harness for the IDR.
 *
 * Companion to lib/kfuzz_ida.c, covering the other half of lib/idr.c. The IDR
 * is a better stateful target than the IDA for two reasons:
 *
 *  1. idr_alloc_cyclic() carries state the caller never sees. idr->idr_next
 *     persists across calls, so the result of an allocation depends on every
 *     allocation that came before it, and the wrap-around retry path
 *     ("if ((err == -ENOSPC) && (id > start))") is only reachable once that
 *     hidden cursor has been pushed past the requested range. No single call
 *     can exercise it.
 *
 *  2. A non-zero idr_base shifts every ID, and the arithmetic is done by hand
 *     in several places ("id - idr->idr_base", "max - base"). That is exactly
 *     where c6e8e595a079 ("idr: fix idr_alloc() returning an ID out of range")
 *     lived: with a non-zero base and a range entirely below it, "max - base"
 *     underflowed to something enormous and idr_get_free() returned an ID
 *     outside the requested range. The fuzzer chooses the base here, so that
 *     arithmetic is under test rather than assumed.
 *
 * The oracle is a shadow map from ID to the pointer that was stored, which is
 * the whole model. Beyond content it asserts the two allocator properties that
 * a content comparison cannot see:
 *
 *   - a returned ID lies inside the requested range, and was not already
 *     allocated;
 *   - -ENOSPC is only correct when every ID in the range is taken. The maple
 *     tree archaeology identified this "assert the negative" case as the largest
 *     single class of allocator bug and the one nothing in the existing
 *     harnesses checked.
 *
 * Copyright 2025 Google LLC
 */
#include <linux/bitmap.h>
#include <linux/err.h>
#include <linux/idr.h>
#include <linux/kfuzztest.h>
#include <linux/slab.h>
#include <linux/types.h>

#define KFUZZ_IDR_MAX_IDS 2048
#define KFUZZ_IDR_MIN_IDS 32

/*
 * Bases are small but include 0 and 1: idr_base == 1 is the case
 * 6ce711f27500 ("idr: Make 1-based IDRs more efficient") special-cased, and
 * which c6e8e595a079 then had to fix.
 */
#define KFUZZ_IDR_MAX_BASE 64

/* See lib/kfuzz_xarray.c: real, aligned pointers that are never dereferenced. */
#define KFUZZ_IDR_TOKEN_POOL_SZ 4096

struct kfuzz_idr_state {
	struct idr idr;

	/* Shadow, indexed by (id - base). NULL == not allocated. */
	void **val;

	char *tokpool;
	unsigned long gen;

	unsigned int nr_ids;
	unsigned int base;

	unsigned long op_index;
	bool failed;
};

/* Init blob. */
struct kfuzz_idr_init_arg {
	__u16 nr_ids;
	__u8 base;
	__u8 __pad;
} __packed;

/* Operation arguments. */
struct kfuzz_idr_range_arg {
	__u32 start;
	__u32 end;
} __packed;

struct kfuzz_idr_nth_arg {
	__u32 nth;
} __packed;

struct kfuzz_idr_id_arg {
	__u32 id;
} __packed;

/* FRAMEWORK GAP: KFUZZ_OP() cannot express a no-argument operation. */
struct kfuzz_idr_void_arg {
	__u8 unused;
} __packed;

/*
 * FRAMEWORK GAP: the framework only pr_warn()s check_correctness_fn()'s
 * verdict, so the harness raises the WARN itself and latches on first failure.
 */
#define kfuzz_idr_fail(st, fmt, ...)                                          \
	do {                                                                  \
		if (!(st)->failed) {                                          \
			(st)->failed = true;                                  \
			WARN(1, "kfuzz_idr: op %lu: " fmt "\n",                \
			     (st)->op_index, ##__VA_ARGS__);                   \
		}                                                             \
	} while (0)

/* ------------------------------------------------------------- helpers --- */

static void *kfuzz_idr_new_token(struct kfuzz_idr_state *st)
{
	st->gen = (st->gen + 1) % (KFUZZ_IDR_TOKEN_POOL_SZ / 4);

	return st->tokpool + 4 * st->gen;
}

/* Absolute IDs the harness can model: [base, base + nr_ids). */
static bool kfuzz_idr_in_space(struct kfuzz_idr_state *st, unsigned int id)
{
	return id >= st->base && id < st->base + st->nr_ids;
}

static unsigned int kfuzz_idr_slot(struct kfuzz_idr_state *st, unsigned int id)
{
	return id - st->base;
}

/* Count what the shadow believes is allocated. */
static unsigned long kfuzz_idr_shadow_count(struct kfuzz_idr_state *st)
{
	unsigned long i, n = 0;

	for (i = 0; i < st->nr_ids; i++)
		if (st->val[i])
			n++;

	return n;
}

/*
 * Shared result checking for idr_alloc() and idr_alloc_cyclic().
 *
 * @start is inclusive and @end exclusive, matching the IDR API. A range with
 * start >= end is empty and must never produce an allocation; it is generated
 * deliberately, because "the requested range lies entirely below the base" is
 * the shape of c6e8e595a079.
 */
static void kfuzz_idr_check_alloc(struct kfuzz_idr_state *st, const char *what,
				  unsigned int start, unsigned int end, int ret,
				  void *token)
{
	unsigned int id;

	if (ret >= 0) {
		if (start >= end) {
			kfuzz_idr_fail(st, "%s(%u, %u) returned %d from an empty range",
				       what, start, end, ret);
			return;
		}
		if (ret < start || (unsigned int)ret >= end) {
			kfuzz_idr_fail(st, "%s(%u, %u) returned %d, outside the range",
				       what, start, end, ret);
			return;
		}
		if (!kfuzz_idr_in_space(st, ret)) {
			kfuzz_idr_fail(st, "%s(%u, %u) returned %d, outside the [%u, %u) ID space",
				       what, start, end, ret, st->base,
				       st->base + st->nr_ids);
			return;
		}
		if (st->val[kfuzz_idr_slot(st, ret)]) {
			kfuzz_idr_fail(st, "%s(%u, %u) returned %d, which is already allocated",
				       what, start, end, ret);
			return;
		}
		st->val[kfuzz_idr_slot(st, ret)] = token;
		return;
	}

	/* Memory pressure tells us nothing about correctness. */
	if (ret == -ENOMEM)
		return;

	if (ret != -ENOSPC) {
		kfuzz_idr_fail(st, "%s(%u, %u) returned unexpected %d", what, start, end, ret);
		return;
	}

	if (start >= end)
		return;

	/* ASSERT THE NEGATIVE: -ENOSPC must mean the range really is full. */
	for (id = start; id < end; id++) {
		/*
		 * IDs below idr_base are not allocatable at all, so -ENOSPC is
		 * justified with respect to them. Skipping them also keeps the
		 * shadow index from underflowing for a range that straddles the
		 * base.
		 */
		if (!kfuzz_idr_in_space(st, id))
			continue;
		if (st->val[kfuzz_idr_slot(st, id)])
			continue;
		kfuzz_idr_fail(st, "%s(%u, %u) returned -ENOSPC but ID %u is free",
			       what, start, end, id);
		return;
	}
}

/*
 * Map a fuzzer word onto the modelled ID space. @end is exclusive and may land
 * at or below @start, which is the empty-range case.
 */
static void kfuzz_idr_pick_range(struct kfuzz_idr_state *st,
				 const struct kfuzz_idr_range_arg *arg,
				 unsigned int *startp, unsigned int *endp)
{
	/*
	 * The top bit of @end asks for a range placed at or below idr_base.
	 *
	 * This matters because c6e8e595a079 ("idr: fix idr_alloc() returning an
	 * ID out of range") was exactly that case: with a non-zero base and a
	 * range entirely below it, "max - base" underflowed to something
	 * enormous and idr_get_free() returned an ID outside the request. A
	 * generator that only ever asks for ranges at or above the base cannot
	 * reach the arithmetic that broke, so the shape is generated on purpose.
	 *
	 * No ID below idr_base is allocatable, so the only correct outcome for a
	 * range entirely below it is -ENOSPC.
	 */
	if ((arg->end & 0x80000000u) && st->base > 0) {
		*startp = arg->start % (st->base + 1);
		*endp = *startp + 1 + (arg->end % (st->base + 1));
		return;
	}

	*startp = st->base + (arg->start % st->nr_ids);
	*endp = st->base + (arg->end % st->nr_ids) + 1;
}

/* ------------------------------------------------------------------ ops --- */

/* op 0: plain allocation from a fuzzer-chosen range. */
KFUZZ_OP(kfuzz_idr_op_alloc, struct kfuzz_idr_state, struct kfuzz_idr_range_arg)
{
	unsigned int start, end;
	void *token;
	int ret;

	if (st->failed)
		return 0;

	kfuzz_idr_pick_range(st, arg, &start, &end);
	token = kfuzz_idr_new_token(st);

	ret = idr_alloc(&st->idr, token, start, end, GFP_KERNEL);
	kfuzz_idr_check_alloc(st, "idr_alloc", start, end, ret, token);

	return 0;
}

/*
 * op 1: cyclic allocation.
 *
 * This is the stateful one. idr->idr_next survives the call, so the ID this
 * returns depends on the whole preceding sequence, and the wrap-around retry is
 * only reachable once that hidden cursor has been pushed past @start.
 */
KFUZZ_OP(kfuzz_idr_op_alloc_cyclic, struct kfuzz_idr_state, struct kfuzz_idr_range_arg)
{
	unsigned int start, end;
	void *token;
	int ret;

	if (st->failed)
		return 0;

	kfuzz_idr_pick_range(st, arg, &start, &end);
	token = kfuzz_idr_new_token(st);

	ret = idr_alloc_cyclic(&st->idr, token, start, end, GFP_KERNEL);
	kfuzz_idr_check_alloc(st, "idr_alloc_cyclic", start, end, ret, token);

	return 0;
}

/*
 * op 2: remove the nth allocated ID.
 *
 * FRAMEWORK GAP: the same hand-rolled substitute for a resource concept as in
 * lib/kfuzz_ida.c - nothing connects this argument to IDs earlier ops produced,
 * so a raw fuzzer word would essentially never name a live ID.
 */
KFUZZ_OP(kfuzz_idr_op_remove, struct kfuzz_idr_state, struct kfuzz_idr_nth_arg)
{
	unsigned long weight, nth, i, seen = 0;
	unsigned int id = 0;
	void *expect, *got;
	bool found = false;

	if (st->failed)
		return 0;

	weight = kfuzz_idr_shadow_count(st);
	if (!weight)
		return 0;

	nth = arg->nth % weight;
	for (i = 0; i < st->nr_ids; i++) {
		if (!st->val[i])
			continue;
		if (seen++ == nth) {
			id = st->base + i;
			found = true;
			break;
		}
	}
	if (!found)
		return 0;

	expect = st->val[kfuzz_idr_slot(st, id)];
	got = idr_remove(&st->idr, id);
	if (got != expect) {
		kfuzz_idr_fail(st, "idr_remove(%u) returned %px, shadow expected %px",
			       id, got, expect);
		return 0;
	}
	st->val[kfuzz_idr_slot(st, id)] = NULL;

	return 0;
}

/* op 3: idr_find() must agree with the shadow, present or absent. */
KFUZZ_OP(kfuzz_idr_op_find, struct kfuzz_idr_state, struct kfuzz_idr_id_arg)
{
	unsigned int id;
	void *expect, *got;

	if (st->failed)
		return 0;

	id = st->base + (arg->id % st->nr_ids);
	expect = st->val[kfuzz_idr_slot(st, id)];

	got = idr_find(&st->idr, id);
	if (got != expect)
		kfuzz_idr_fail(st, "idr_find(%u) returned %px, shadow expected %px",
			       id, got, expect);

	return 0;
}

/*
 * op 4: replace the pointer at the nth allocated ID.
 *
 * Also checks the negative: replacing an *unallocated* ID must fail with
 * -ENOENT rather than quietly succeeding.
 */
KFUZZ_OP(kfuzz_idr_op_replace, struct kfuzz_idr_state, struct kfuzz_idr_nth_arg)
{
	unsigned long weight, nth, i, seen = 0;
	unsigned int id = 0;
	void *expect, *got, *token;
	bool found = false;

	if (st->failed)
		return 0;

	weight = kfuzz_idr_shadow_count(st);
	token = kfuzz_idr_new_token(st);

	if (!weight) {
		/* Nothing allocated: any ID must be rejected. */
		id = st->base + (arg->nth % st->nr_ids);
		got = idr_replace(&st->idr, token, id);
		if (!IS_ERR(got))
			kfuzz_idr_fail(st, "idr_replace(%u) returned %px on an empty IDR",
				       id, got);
		else if (PTR_ERR(got) != -ENOENT)
			kfuzz_idr_fail(st, "idr_replace(%u) returned %ld, expected -ENOENT",
				       id, PTR_ERR(got));
		return 0;
	}

	nth = arg->nth % weight;
	for (i = 0; i < st->nr_ids; i++) {
		if (!st->val[i])
			continue;
		if (seen++ == nth) {
			id = st->base + i;
			found = true;
			break;
		}
	}
	if (!found)
		return 0;

	expect = st->val[kfuzz_idr_slot(st, id)];
	got = idr_replace(&st->idr, token, id);
	if (IS_ERR(got)) {
		kfuzz_idr_fail(st, "idr_replace(%u) returned %ld for an allocated ID",
			       id, PTR_ERR(got));
		return 0;
	}
	if (got != expect) {
		kfuzz_idr_fail(st, "idr_replace(%u) returned %px, shadow expected %px",
			       id, got, expect);
		return 0;
	}
	st->val[kfuzz_idr_slot(st, id)] = token;

	return 0;
}

/*
 * op 5: enumerate the IDR with idr_get_next() and compare the set to the
 * shadow, in both directions.
 *
 * The walk is bounded: a corrupted container can make an iterator fail to
 * advance, and an unbounded loop here would hang rather than report. See the
 * XArray harness for a case where that actually happened.
 */
KFUZZ_OP(kfuzz_idr_op_check, struct kfuzz_idr_state, struct kfuzz_idr_void_arg)
{
	unsigned long found = 0, expected, cap;
	int id = 0, prev = -1;
	bool empty;
	void *entry;

	if (st->failed)
		return 0;

	expected = kfuzz_idr_shadow_count(st);
	cap = 2UL * st->nr_ids + 64;

	empty = idr_is_empty(&st->idr);
	if (empty != (expected == 0)) {
		kfuzz_idr_fail(st, "idr_is_empty() returned %d but the shadow holds %lu IDs",
			       empty, expected);
		return 0;
	}

	while ((entry = idr_get_next(&st->idr, &id)) != NULL) {
		if (++found > cap) {
			kfuzz_idr_fail(st, "idr_get_next() did not terminate after %lu iterations (last id %d)",
				       cap, id);
			return 0;
		}
		if (id <= prev) {
			kfuzz_idr_fail(st, "idr_get_next() went backwards: %d after %d", id, prev);
			return 0;
		}
		prev = id;
		if (!kfuzz_idr_in_space(st, id)) {
			kfuzz_idr_fail(st, "idr_get_next() produced id %d outside the [%u, %u) space",
				       id, st->base, st->base + st->nr_ids);
			return 0;
		}
		if (entry != st->val[kfuzz_idr_slot(st, id)]) {
			kfuzz_idr_fail(st, "idr_get_next() gave %px at id %d, shadow has %px",
				       entry, id, st->val[kfuzz_idr_slot(st, id)]);
			return 0;
		}
		if (id == INT_MAX)
			break;
		id++;
	}

	if (found != expected)
		kfuzz_idr_fail(st, "idr_get_next() enumerated %lu IDs, the shadow holds %lu",
			       found, expected);

	return 0;
}

/* op 6: tear the IDR down mid-sequence and keep going. */
KFUZZ_OP(kfuzz_idr_op_destroy, struct kfuzz_idr_state, struct kfuzz_idr_void_arg)
{
	if (st->failed)
		return 0;

	idr_destroy(&st->idr);
	memset(st->val, 0, st->nr_ids * sizeof(*st->val));

	if (!idr_is_empty(&st->idr))
		kfuzz_idr_fail(st, "IDR is not empty after idr_destroy()");

	return 0;
}

/* ------------------------------------------------------------- lifecycle --- */

/* FRAMEWORK GAP: no way to schedule the O(n) check every k ops; it is op 5. */
static int kfuzz_idr_check_correctness(kfuzztest_handle comp)
{
	struct kfuzz_idr_state *st = comp;

	if (!st)
		return 1;

	st->op_index++;
	return st->failed ? 0 : 1;
}

static kfuzztest_handle kfuzz_idr_initialize(size_t len, char *data)
{
	struct kfuzz_idr_init_arg arg;
	struct kfuzz_idr_state *st;

	st = kzalloc(sizeof(*st), GFP_KERNEL);
	if (!st)
		return NULL;

	memset(&arg, 0, sizeof(arg));
	if (data && len >= sizeof(arg))
		memcpy(&arg, data, sizeof(arg));

	st->nr_ids = KFUZZ_IDR_MIN_IDS +
		     (arg.nr_ids % (KFUZZ_IDR_MAX_IDS - KFUZZ_IDR_MIN_IDS + 1));
	st->base = arg.base % (KFUZZ_IDR_MAX_BASE + 1);

	st->val = kvcalloc(st->nr_ids, sizeof(*st->val), GFP_KERNEL);
	st->tokpool = kzalloc(KFUZZ_IDR_TOKEN_POOL_SZ, GFP_KERNEL);
	if (!st->val || !st->tokpool) {
		kvfree(st->val);
		kfree(st->tokpool);
		kfree(st);
		return NULL;
	}

	idr_init_base(&st->idr, st->base);

	return st;
}

static void kfuzz_idr_teardown(kfuzztest_handle comp)
{
	struct kfuzz_idr_state *st = comp;

	if (!st)
		return;

	idr_destroy(&st->idr);
	kvfree(st->val);
	kfree(st->tokpool);
	kfree(st);
}

/*
 * FRAMEWORK GAP: every op returns 0 unconditionally, because a non-zero return
 * aborts the sequence without running teardown_fn() - leaking the whole radix
 * tree - and fails the write(), which makes a fuzzing manager discard the
 * execution's coverage.
 */
KFUZZ_REGISTER_HARNESS(idr, kfuzz_idr_initialize, kfuzz_idr_teardown,
		       kfuzz_idr_check_correctness,
		       kfuzz_idr_op_alloc,		/* 0 */
		       kfuzz_idr_op_alloc_cyclic,	/* 1 */
		       kfuzz_idr_op_remove,		/* 2 */
		       kfuzz_idr_op_find,		/* 3 */
		       kfuzz_idr_op_replace,		/* 4 */
		       kfuzz_idr_op_check,		/* 5 */
		       kfuzz_idr_op_destroy)		/* 6 */
