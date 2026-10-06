// SPDX-License-Identifier: GPL-2.0
/*
 * KFuzzTest stateful harness for the IDA (ID allocator).
 *
 * The IDA is the cheapest place in the tree to build a *complete* allocator
 * oracle, which is why it is worth a harness of its own.
 *
 * The shadow model is a bitmap - allocated or not, per ID - and that is the
 * entire model. Unlike a container's shadow it cannot encode a wrong
 * assumption about semantics, because there are no semantics beyond "this ID
 * is handed out or it is not".
 *
 * That lets this harness assert something the maple tree harness could not:
 * the *negative*. An allocator that returns -ENOSPC while free space provably
 * exists is the single largest class in the maple tree's own bug history, and
 * nothing in a content-comparison oracle can see it. Here it is three lines:
 * if ida_alloc_range() fails, the shadow must have no free ID in the range.
 *
 * Why the IDA is genuinely stateful: it has two internal representations per
 * 1024-ID chunk. Up to BITS_PER_XA_VALUE (63) IDs are held compactly inside
 * the XArray slot itself as a value entry; reaching a higher bit promotes the
 * slot to a full struct ida_bitmap, carrying the existing bits across. Nothing
 * about that transition is observable through the API, and no single call can
 * exercise it - you need a live low ID *and* a subsequent allocation above the
 * boundary.
 *
 * Copyright 2025 Google LLC
 */
#include <linux/bitmap.h>
#include <linux/idr.h>
#include <linux/kfuzztest.h>
#include <linux/slab.h>
#include <linux/types.h>

/*
 * Two IDA_BITMAP_BITS chunks, so the fuzzer can reach both the within-chunk
 * compact/bitmap promotion boundary at ID 63 and the chunk boundary at 1024.
 */
#define KFUZZ_IDA_MAX_IDS 2048
#define KFUZZ_IDA_MIN_IDS 64

struct kfuzz_ida_state {
	struct ida ida;
	unsigned long *alloc;		/* shadow: one bit per ID */
	unsigned int nr_ids;
	unsigned long op_index;
	bool failed;
};

/* Init blob. */
struct kfuzz_ida_init_arg {
	__u16 nr_ids;
	__u8 __pad[2];
} __packed;

/* Operation arguments. */
struct kfuzz_ida_range_arg {
	__u32 min;
	__u32 max;
} __packed;

struct kfuzz_ida_nth_arg {
	__u32 nth;
} __packed;

/*
 * FRAMEWORK GAP: KFUZZ_OP() requires an argument type and rejects a blob
 * shorter than sizeof(arg_type), so a no-argument operation cannot be
 * expressed. This placeholder exists only to satisfy that.
 */
struct kfuzz_ida_void_arg {
	__u8 unused;
} __packed;

/*
 * FRAMEWORK GAP: check_correctness_fn()'s verdict is only pr_warn()ed, and a
 * plain printk is not recognised as a bug by a fuzzing manager, so the harness
 * raises the WARN itself and latches so the first report survives the dmesg
 * ring.
 */
#define kfuzz_ida_fail(st, fmt, ...)                                          \
	do {                                                                  \
		if (!(st)->failed) {                                          \
			(st)->failed = true;                                  \
			WARN(1, "kfuzz_ida: op %lu: " fmt "\n",                \
			     (st)->op_index, ##__VA_ARGS__);                   \
		}                                                             \
	} while (0)

/* ------------------------------------------------------------------ ops --- */

/*
 * op 0: allocate from a fuzzer-chosen range.
 *
 * Four oracles, none of which needs a model of the IDA beyond the bitmap:
 *
 *  - a returned ID must lie inside [min, max]. This is the shape of
 *    c6e8e595a079 ("idr: fix idr_alloc() returning an ID out of range").
 *  - a returned ID must not already be allocated. This is what catches state
 *    silently lost inside the allocator.
 *  - an empty range (min > max) must never succeed.
 *  - ASSERT THE NEGATIVE: -ENOSPC is only correct if every ID in the range is
 *    already taken.
 *
 * The range is deliberately *not* normalised. min > max is the exact shape of
 * the IDR bug above, so it is worth generating.
 */
KFUZZ_OP(kfuzz_ida_op_alloc_range, struct kfuzz_ida_state, struct kfuzz_ida_range_arg)
{
	unsigned int min, max, free_id;
	int ret;

	if (st->failed)
		return 0;

	min = arg->min % st->nr_ids;
	max = arg->max % st->nr_ids;

	ret = ida_alloc_range(&st->ida, min, max, GFP_KERNEL);

	if (ret >= 0) {
		if (min > max) {
			kfuzz_ida_fail(st, "ida_alloc_range(%u, %u) returned %d from an empty range",
				       min, max, ret);
			return 0;
		}
		if (ret < min || ret > max) {
			kfuzz_ida_fail(st, "ida_alloc_range(%u, %u) returned %d, outside the range",
				       min, max, ret);
			return 0;
		}
		if (ret >= st->nr_ids) {
			kfuzz_ida_fail(st, "ida_alloc_range(%u, %u) returned %d, beyond the %u-ID space",
				       min, max, ret, st->nr_ids);
			return 0;
		}
		if (test_bit(ret, st->alloc)) {
			kfuzz_ida_fail(st,
				       "ida_alloc_range(%u, %u) returned %d, which is already allocated",
				       min, max, ret);
			return 0;
		}
		__set_bit(ret, st->alloc);
		return 0;
	}

	/* Allocation failure under memory pressure tells us nothing. */
	if (ret == -ENOMEM)
		return 0;

	if (ret != -ENOSPC) {
		kfuzz_ida_fail(st, "ida_alloc_range(%u, %u) returned unexpected %d", min, max, ret);
		return 0;
	}

	if (min > max)
		return 0;

	free_id = find_next_zero_bit(st->alloc, max + 1, min);
	if (free_id <= max)
		kfuzz_ida_fail(st, "ida_alloc_range(%u, %u) returned -ENOSPC but ID %u is free",
			       min, max, free_id);

	return 0;
}

/*
 * op 1: allocate with only a lower bound.
 *
 * Separate from op 0 because this is how a sequence reaches the compact ->
 * bitmap promotion inside a chunk without first having to allocate 63 IDs: a
 * high @min forces the allocator past BITS_PER_XA_VALUE directly.
 */
KFUZZ_OP(kfuzz_ida_op_alloc_min, struct kfuzz_ida_state, struct kfuzz_ida_range_arg)
{
	unsigned int min, max, free_id;
	int ret;

	if (st->failed)
		return 0;

	min = arg->min % st->nr_ids;
	max = st->nr_ids - 1;

	ret = ida_alloc_range(&st->ida, min, max, GFP_KERNEL);

	if (ret >= 0) {
		if (ret < min || ret > max) {
			kfuzz_ida_fail(st, "ida_alloc_range(%u, %u) returned %d, outside the range",
				       min, max, ret);
			return 0;
		}
		if (test_bit(ret, st->alloc)) {
			kfuzz_ida_fail(st,
				       "ida_alloc_range(%u, %u) returned %d, which is already allocated",
				       min, max, ret);
			return 0;
		}
		__set_bit(ret, st->alloc);
		return 0;
	}

	if (ret == -ENOMEM)
		return 0;
	if (ret != -ENOSPC) {
		kfuzz_ida_fail(st, "ida_alloc_range(%u, %u) returned unexpected %d", min, max, ret);
		return 0;
	}

	free_id = find_next_zero_bit(st->alloc, max + 1, min);
	if (free_id <= max)
		kfuzz_ida_fail(st, "ida_alloc_range(%u, %u) returned -ENOSPC but ID %u is free",
			       min, max, free_id);

	return 0;
}

/*
 * op 2: free an ID the shadow believes is allocated.
 *
 * FRAMEWORK GAP: this is a hand-rolled substitute for the resource concept
 * described in kfuzztest-framework-improvements.md 3.4. Nothing connects op N's
 * arguments to the values earlier ops produced, so a raw fuzzer word would
 * almost never name a live ID and this op would be a no-op for an entire
 * sequence. Interpreting the argument as "the nth currently-allocated ID"
 * recovers the correlation inside the harness, which is work every stateful
 * harness author will otherwise redo.
 *
 * Only valid frees are issued, deliberately - see the harness notes on why
 * fuzzing the IDA's own double-free detection is not possible today.
 */
KFUZZ_OP(kfuzz_ida_op_free, struct kfuzz_ida_state, struct kfuzz_ida_nth_arg)
{
	unsigned long weight, nth, id;

	if (st->failed)
		return 0;

	weight = bitmap_weight(st->alloc, st->nr_ids);
	if (!weight)
		return 0;

	nth = arg->nth % weight;
	id = find_nth_bit(st->alloc, st->nr_ids, nth);
	if (id >= st->nr_ids) {
		kfuzz_ida_fail(st, "shadow inconsistency: no %lu'th set bit among %lu", nth, weight);
		return 0;
	}

	ida_free(&st->ida, id);
	__clear_bit(id, st->alloc);

	return 0;
}

/* op 3: the lowest allocated ID in a range must be what the shadow says. */
KFUZZ_OP(kfuzz_ida_op_find_first, struct kfuzz_ida_state, struct kfuzz_ida_range_arg)
{
	unsigned int min, max, want;
	int got, expect;

	if (st->failed)
		return 0;

	min = arg->min % st->nr_ids;
	max = arg->max % st->nr_ids;
	if (min > max)
		swap(min, max);

	want = find_next_bit(st->alloc, max + 1, min);
	expect = (want <= max) ? (int)want : -ENOENT;

	got = ida_find_first_range(&st->ida, min, max);
	if (got != expect)
		kfuzz_ida_fail(st, "ida_find_first_range(%u, %u) returned %d, shadow expected %d",
			       min, max, got, expect);

	return 0;
}

/*
 * op 4: enumerate everything the IDA believes is allocated and compare the set
 * to the shadow, in both directions.
 *
 * There is no "is this ID allocated" API, so the walk chains
 * ida_find_first_range() forward. That both checks every reported ID against
 * the shadow and - via the final count - catches IDs the shadow holds but the
 * IDA has forgotten, which is the symptom of state lost inside the allocator.
 */
KFUZZ_OP(kfuzz_ida_op_check, struct kfuzz_ida_state, struct kfuzz_ida_void_arg)
{
	unsigned long found = 0, expected;
	unsigned int cur = 0;
	bool empty;
	int got;

	if (st->failed)
		return 0;

	expected = bitmap_weight(st->alloc, st->nr_ids);

	empty = ida_is_empty(&st->ida);
	if (empty != (expected == 0)) {
		kfuzz_ida_fail(st, "ida_is_empty() returned %d but the shadow holds %lu IDs",
			       empty, expected);
		return 0;
	}

	for (;;) {
		got = ida_find_first_range(&st->ida, cur, st->nr_ids - 1);
		if (got == -ENOENT)
			break;
		if (got < 0) {
			kfuzz_ida_fail(st, "ida_find_first_range(%u, %u) returned unexpected %d",
				       cur, st->nr_ids - 1, got);
			return 0;
		}
		if (got < cur || got >= st->nr_ids) {
			kfuzz_ida_fail(st, "ida_find_first_range(%u, %u) returned %d, out of range",
				       cur, st->nr_ids - 1, got);
			return 0;
		}
		if (!test_bit(got, st->alloc)) {
			kfuzz_ida_fail(st, "IDA reports ID %d allocated, the shadow does not", got);
			return 0;
		}
		found++;
		if ((unsigned int)got == st->nr_ids - 1)
			break;
		cur = got + 1;
	}

	if (found != expected)
		kfuzz_ida_fail(st, "IDA enumerated %lu allocated IDs, the shadow holds %lu",
			       found, expected);

	return 0;
}

/* op 5: tear the whole allocator down mid-sequence and keep going. */
KFUZZ_OP(kfuzz_ida_op_destroy, struct kfuzz_ida_state, struct kfuzz_ida_void_arg)
{
	if (st->failed)
		return 0;

	ida_destroy(&st->ida);
	bitmap_zero(st->alloc, st->nr_ids);

	if (!ida_is_empty(&st->ida))
		kfuzz_ida_fail(st, "IDA is not empty after ida_destroy()");

	return 0;
}

/* ------------------------------------------------------------- lifecycle --- */

/*
 * FRAMEWORK GAP: this hook runs after every operation with no way to say "run
 * the expensive check every k ops, plus once at the end", so the O(n) sweep is
 * exposed as op 4 for the fuzzer to schedule rather than run unconditionally
 * here.
 */
static int kfuzz_ida_check_correctness(kfuzztest_handle comp)
{
	struct kfuzz_ida_state *st = comp;

	if (!st)
		return 1;

	st->op_index++;
	return st->failed ? 0 : 1;
}

static kfuzztest_handle kfuzz_ida_initialize(size_t len, char *data)
{
	struct kfuzz_ida_init_arg arg;
	struct kfuzz_ida_state *st;

	st = kzalloc(sizeof(*st), GFP_KERNEL);
	if (!st)
		return NULL;

	memset(&arg, 0, sizeof(arg));
	if (data && len >= sizeof(arg))
		memcpy(&arg, data, sizeof(arg));

	st->nr_ids = KFUZZ_IDA_MIN_IDS +
		     (arg.nr_ids % (KFUZZ_IDA_MAX_IDS - KFUZZ_IDA_MIN_IDS + 1));

	st->alloc = kzalloc(BITS_TO_LONGS(st->nr_ids) * sizeof(unsigned long), GFP_KERNEL);
	if (!st->alloc) {
		kfree(st);
		return NULL;
	}

	ida_init(&st->ida);

	return st;
}

static void kfuzz_ida_teardown(kfuzztest_handle comp)
{
	struct kfuzz_ida_state *st = comp;

	if (!st)
		return;

	ida_destroy(&st->ida);
	kfree(st->alloc);
	kfree(st);
}

/*
 * FRAMEWORK GAP: every op returns 0 unconditionally. A non-zero return aborts
 * the sequence in kfuzztest_invoke() *without* running teardown_fn(), leaking
 * every ida_bitmap the sequence allocated, and it fails the write(), which
 * makes a fuzzing manager discard the execution's coverage. KFUZZ_OP() itself
 * returns -EINVAL on a short argument blob - the most common thing a mutating
 * fuzzer produces.
 */
KFUZZ_REGISTER_HARNESS(ida, kfuzz_ida_initialize, kfuzz_ida_teardown,
		       kfuzz_ida_check_correctness,
		       kfuzz_ida_op_alloc_range,	/* 0 */
		       kfuzz_ida_op_alloc_min,		/* 1 */
		       kfuzz_ida_op_free,		/* 2 */
		       kfuzz_ida_op_find_first,		/* 3 */
		       kfuzz_ida_op_check,		/* 4 */
		       kfuzz_ida_op_destroy)		/* 5 */
