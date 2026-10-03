// SPDX-License-Identifier: GPL-2.0
/*
 * KFuzzTest stateful harness for the XArray.
 *
 * The XArray is a good fit for stateful fuzzing for three reasons:
 *
 *  1. Its bug history is dominated by *sequence-dependent semantic* failures -
 *     multi-index entries interacting with search marks and with iteration -
 *     rather than by single-call memory safety violations. Nothing is corrupt
 *     after the bug fires; a query simply returns the wrong answer.
 *
 *  2. Its shadow model is cheap and hard to get wrong. An XArray is
 *     index -> entry plus three mark bits per entry. There is no range
 *     coalescing to reason about, which is the single riskiest assumption in
 *     lib/kfuzz_maple_tree.c.
 *
 *  3. Several of its invariants need no model at all. "No API call ever hands
 *     an internal entry back to the caller" is an absolute rule, and it is
 *     exactly the rule that multi-index mark bugs break.
 *
 * The oracle here is therefore layered. The invariant checks carry zero
 * assumption risk and are what actually catch things; the shadow model adds
 * content and mark verification on top.
 *
 * Documented semantics this harness relies on (Documentation/core-api/xarray.rst):
 *
 *  - "Setting or clearing a mark on any index of a multi-index entry will
 *     affect all indices covered by that entry. Querying the mark on any index
 *     will return the same result."  => marks can be modelled per index,
 *     uniformly across an entry's extent.
 *  - "Storing NULL into any index of a multi-index entry will set the entry at
 *     every index to NULL and dissolve the tie."  => one erase kills a whole
 *     multi-index entry.
 *  - "Erasing an entry from the XArray causes all marks associated with that
 *     entry to be cleared."
 *  - "Each entry will only be returned once, no matter how many indices it
 *     occupies."  => iteration counts entries, not indices.
 *
 * Storing a non-NULL entry over *part* of a larger multi-index entry is not
 * documented and is not done here; see kfuzz_xa_op_store().
 *
 * Copyright 2025 Google LLC
 */
#include <linux/bitmap.h>
#include <linux/kfuzztest.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/xarray.h>

/*
 * The index space is bounded and dense so that randomly chosen operations
 * collide. 4096 indices is enough to hold an order-11 entry (2048 indices)
 * twice over, which matters because the interesting split behaviour only
 * appears once an entry is large enough to occupy a whole tree level.
 */
#define KFUZZ_XA_MAX_INDICES 4096
#define KFUZZ_XA_MIN_LOG2 6
#define KFUZZ_XA_MAX_LOG2 12
#define KFUZZ_XA_MAX_ORDER 11
#define KFUZZ_XA_NR_MARKS 3

/*
 * Hard ceiling on any iteration the harness drives. Every entry occupies at
 * least one index, so a correct walk of the index space cannot exceed it; a walk
 * that does has failed to make progress.
 */
#define KFUZZ_XA_ITER_CAP(st) (4UL * (st)->nr_indices + 64)

/*
 * Tokens are minted from a real allocation so that a stored entry is always a
 * valid, 4-byte-aligned kernel pointer: the XArray never dereferences a stored
 * entry, but handing it a raw fuzzer word risks tripping its internal-entry
 * checks and reporting a harness bug as an XArray bug. Uniqueness per store is
 * what lets the shadow model tell two entries apart during iteration.
 */
#define KFUZZ_XA_TOKEN_POOL_SZ 4096

static const xa_mark_t kfuzz_xa_marks[KFUZZ_XA_NR_MARKS] = {
	XA_MARK_0,
	XA_MARK_1,
	XA_MARK_2,
};

struct kfuzz_xa_state {
	struct xarray xa;

	/* Shadow model, one slot per index. */
	void **tok;				/* NULL == absent */
	u8 *ord;				/* order of the covering entry */
	unsigned long *mk[KFUZZ_XA_NR_MARKS];	/* per-index mark bitmaps */

	char *tokpool;
	unsigned long gen;

	unsigned int nr_indices;
	unsigned int max_order;

	unsigned long op_index;
	bool failed;
};

/* Init blob. */
struct kfuzz_xa_init_arg {
	__u8 log2_indices;
	__u8 max_order;
	__u8 __pad[2];
} __packed;

/* Operation arguments. */
struct kfuzz_xa_store_arg {
	__u32 index;
	__u8 order;
} __packed;

struct kfuzz_xa_index_arg {
	__u32 index;
} __packed;

struct kfuzz_xa_mark_arg {
	__u32 index;
	__u8 mark;
} __packed;

struct kfuzz_xa_split_arg {
	__u32 index;
	__u8 new_order;
} __packed;

struct kfuzz_xa_markonly_arg {
	__u8 mark;
} __packed;

/*
 * FRAMEWORK GAP: KFUZZ_OP() requires an argument type and rejects any blob
 * shorter than sizeof(arg_type), so an operation that takes no arguments
 * cannot be expressed. This placeholder exists only to satisfy that.
 */
struct kfuzz_xa_void_arg {
	__u8 unused;
} __packed;

/*
 * FRAMEWORK GAP: check_correctness_fn()'s verdict is only pr_warn()ed by the
 * framework, and a plain printk is not recognised as a bug by a fuzzing
 * manager, so the harness raises the WARN itself.
 *
 * Latching matters: once the model and the XArray disagree they will keep
 * disagreeing, and a flood of WARNs pushes the first - the only useful - one
 * out of the dmesg ring.
 */
#define kfuzz_xa_fail(st, fmt, ...)                                           \
	do {                                                                  \
		if (!(st)->failed) {                                          \
			(st)->failed = true;                                  \
			WARN(1, "kfuzz_xarray: op %lu: " fmt "\n",             \
			     (st)->op_index, ##__VA_ARGS__);                  \
		}                                                             \
	} while (0)

/* ------------------------------------------------------------- helpers --- */

static void *kfuzz_xa_new_token(struct kfuzz_xa_state *st)
{
	st->gen = (st->gen + 1) % (KFUZZ_XA_TOKEN_POOL_SZ / 4);

	/* 4-byte aligned, so never mistaken for a value or an internal entry. */
	return st->tokpool + 4 * st->gen;
}

/* Local copy of the test suite's helper; there is no exported xa_store_order. */
static void *kfuzz_xa_store_order(struct xarray *xa, unsigned long index,
				  unsigned int order, void *entry, gfp_t gfp)
{
	XA_STATE_ORDER(xas, xa, index, order);
	void *curr;

	do {
		xas_lock(&xas);
		curr = xas_store(&xas, entry);
		xas_unlock(&xas);
	} while (xas_nomem(&xas, gfp));

	return curr;
}

static unsigned long kfuzz_xa_entry_base(struct kfuzz_xa_state *st,
					 unsigned long index)
{
	unsigned long size = 1UL << st->ord[index];

	return index & ~(size - 1);
}

/* Drop [base, base + size) from the shadow, marks included. */
static void kfuzz_xa_shadow_clear(struct kfuzz_xa_state *st, unsigned long base,
				  unsigned long size)
{
	unsigned int m;

	memset(&st->tok[base], 0, size * sizeof(*st->tok));
	memset(&st->ord[base], 0, size * sizeof(*st->ord));
	for (m = 0; m < KFUZZ_XA_NR_MARKS; m++)
		bitmap_clear(st->mk[m], base, size);
}

/* ------------------------------------------------------------------ ops --- */

/*
 * op 0: store a freshly minted entry of a fuzzer-chosen order.
 *
 * The chosen index is aligned down to the order, matching what
 * XA_STATE_ORDER() does, so the shadow extent and the real extent agree.
 *
 * A store that would partially overwrite a *larger* multi-index entry is not
 * documented behaviour, so the larger entry is dissolved with an erase first.
 * Both calls are well defined, and the order matters for the mark model: the
 * erase clears the old entry's marks before the store squashes whatever marks
 * remain in the range onto the new entry.
 */
KFUZZ_OP(kfuzz_xa_op_store, struct kfuzz_xa_state, struct kfuzz_xa_store_arg)
{
	unsigned long base, size, i, ebase, esize;
	unsigned int order, m;
	bool mark[KFUZZ_XA_NR_MARKS];
	void *token, *curr;

	if (st->failed)
		return 0;

	order = arg->order % (st->max_order + 1);
	size = 1UL << order;
	base = (arg->index % st->nr_indices) & ~(size - 1);

	/* Dissolve any larger entry straddling the range. */
	for (i = base; i < base + size; i++) {
		if (!st->tok[i] || st->ord[i] <= order)
			continue;
		esize = 1UL << st->ord[i];
		ebase = kfuzz_xa_entry_base(st, i);
		curr = xa_erase(&st->xa, i);
		if (xa_is_internal(curr)) {
			kfuzz_xa_fail(st, "xa_erase(%lu) returned internal entry %px",
				      i, curr);
			return 0;
		}
		kfuzz_xa_shadow_clear(st, ebase, esize);
	}

	/*
	 * xas_squash_marks() ORs the marks of every slot the new entry covers
	 * onto its canonical slot, and for entries large enough to occupy a
	 * whole tree level the ancestor slot's mark is already that same OR.
	 */
	for (m = 0; m < KFUZZ_XA_NR_MARKS; m++)
		mark[m] = find_next_bit(st->mk[m], base + size, base) < base + size;

	token = kfuzz_xa_new_token(st);
	curr = kfuzz_xa_store_order(&st->xa, base, order, token, GFP_KERNEL);
	if (xa_is_err(curr))
		return 0;

	for (i = base; i < base + size; i++) {
		st->tok[i] = token;
		st->ord[i] = order;
	}
	for (m = 0; m < KFUZZ_XA_NR_MARKS; m++) {
		if (mark[m])
			bitmap_set(st->mk[m], base, size);
		else
			bitmap_clear(st->mk[m], base, size);
	}

	return 0;
}

/* op 1: erase whatever covers an index, dissolving a multi-index entry whole. */
KFUZZ_OP(kfuzz_xa_op_erase, struct kfuzz_xa_state, struct kfuzz_xa_index_arg)
{
	unsigned long index, base, size;
	void *curr, *expect;

	if (st->failed)
		return 0;

	index = arg->index % st->nr_indices;
	expect = st->tok[index];
	base = kfuzz_xa_entry_base(st, index);
	size = 1UL << st->ord[index];

	curr = xa_erase(&st->xa, index);
	if (xa_is_internal(curr)) {
		kfuzz_xa_fail(st, "xa_erase(%lu) returned internal entry %px", index, curr);
		return 0;
	}

	/*
	 * Only the order-0 return value is checked. Erasing at a non-canonical
	 * index of a multi-index entry has no documented return value, so
	 * asserting one would be the harness inventing semantics.
	 */
	if (st->ord[index] == 0 && curr != expect) {
		kfuzz_xa_fail(st, "xa_erase(%lu) returned %px, shadow expected %px",
			      index, curr, expect);
		return 0;
	}

	if (expect)
		kfuzz_xa_shadow_clear(st, base, size);

	return 0;
}

/* op 2: set a mark; a no-op on an absent entry, as xa_set_mark() is. */
KFUZZ_OP(kfuzz_xa_op_set_mark, struct kfuzz_xa_state, struct kfuzz_xa_mark_arg)
{
	unsigned long index, base, size;
	unsigned int m;

	if (st->failed)
		return 0;

	index = arg->index % st->nr_indices;
	m = arg->mark % KFUZZ_XA_NR_MARKS;

	xa_set_mark(&st->xa, index, kfuzz_xa_marks[m]);

	if (st->tok[index]) {
		base = kfuzz_xa_entry_base(st, index);
		size = 1UL << st->ord[index];
		bitmap_set(st->mk[m], base, size);
	}

	return 0;
}

/* op 3: clear a mark. */
KFUZZ_OP(kfuzz_xa_op_clear_mark, struct kfuzz_xa_state, struct kfuzz_xa_mark_arg)
{
	unsigned long index, base, size;
	unsigned int m;

	if (st->failed)
		return 0;

	index = arg->index % st->nr_indices;
	m = arg->mark % KFUZZ_XA_NR_MARKS;

	xa_clear_mark(&st->xa, index, kfuzz_xa_marks[m]);

	if (st->tok[index]) {
		base = kfuzz_xa_entry_base(st, index);
		size = 1UL << st->ord[index];
		bitmap_clear(st->mk[m], base, size);
	}

	return 0;
}

/*
 * op 4: split a multi-index entry into smaller ones.
 *
 * xas_split() copies the existing entry into every replacement slot, so the
 * contents shadow is unchanged and only ->ord shrinks. The marks shadow is
 * unchanged too: the parent entry's marks propagate to all of the children, and
 * the model already records marks uniformly across an entry's extent.
 *
 * That invariance is exactly what makes a mark bug here invisible to a contents
 * oracle and visible only to iteration - see kfuzz_xa_op_iter_marked().
 */
KFUZZ_OP(kfuzz_xa_op_split, struct kfuzz_xa_state, struct kfuzz_xa_split_arg)
{
	unsigned long index, base, size, i;
	unsigned int order, new_order;
	void *entry;

	if (st->failed)
		return 0;

	index = arg->index % st->nr_indices;
	if (!st->tok[index] || !st->ord[index])
		return 0;

	order = st->ord[index];
	new_order = arg->new_order % order;
	base = kfuzz_xa_entry_base(st, index);
	size = 1UL << order;
	entry = st->tok[base];

	{
		XA_STATE_ORDER(xas, &st->xa, base, new_order);

		xas_split_alloc(&xas, entry, order, GFP_KERNEL);
		if (xas_error(&xas))
			return 0;

		xas_lock(&xas);
		xas_split(&xas, entry, order);
		xas_unlock(&xas);

		if (xas_error(&xas))
			return 0;
	}

	for (i = base; i < base + size; i++)
		st->ord[i] = new_order;

	return 0;
}

/*
 * op 5: the incremental split path.
 *
 * xas_try_split() refuses splits that would cross a tree level by more than
 * one step, returning -EINVAL. That is documented behaviour, not a finding, so
 * it is treated as a skip - which also exercises the error path.
 */
KFUZZ_OP(kfuzz_xa_op_try_split, struct kfuzz_xa_state, struct kfuzz_xa_split_arg)
{
	unsigned long index, base, size, i;
	unsigned int order, new_order;
	void *entry;

	if (st->failed)
		return 0;

	index = arg->index % st->nr_indices;
	if (!st->tok[index] || !st->ord[index])
		return 0;

	order = st->ord[index];
	new_order = arg->new_order % order;
	base = kfuzz_xa_entry_base(st, index);
	size = 1UL << order;
	entry = st->tok[base];

	{
		XA_STATE_ORDER(xas, &st->xa, base, new_order);

		/* Pre-allocate one node, as lib/test_xarray.c does. */
		xas_set_err(&xas, -ENOMEM);
		if (!xas_nomem(&xas, GFP_KERNEL))
			return 0;

		xas_lock(&xas);
		xas_try_split(&xas, entry, order);
		xas_unlock(&xas);

		if (xas_error(&xas)) {
			xas_destroy(&xas);
			return 0;
		}
	}

	for (i = base; i < base + size; i++)
		st->ord[i] = new_order;

	return 0;
}

/*
 * op 6: every index must hold what the shadow says, and xa_load() must never
 * return an internal entry.
 *
 * The internal-entry check is the assumption-free half: a sibling entry
 * escaping to a caller is a bug no matter what the harness believes about
 * contents.
 */
KFUZZ_OP(kfuzz_xa_op_check_contents, struct kfuzz_xa_state, struct kfuzz_xa_void_arg)
{
	unsigned long i;
	void *entry;

	if (st->failed)
		return 0;

	for (i = 0; i < st->nr_indices; i++) {
		entry = xa_load(&st->xa, i);
		if (xa_is_internal(entry)) {
			kfuzz_xa_fail(st, "xa_load(%lu) returned internal entry %px", i, entry);
			return 0;
		}
		if (entry != st->tok[i]) {
			kfuzz_xa_fail(st, "xa_load(%lu) returned %px, shadow expected %px (order %u)",
				      i, entry, st->tok[i], st->ord[i]);
			return 0;
		}
	}

	return 0;
}

/* op 7: xa_get_mark() must agree with the shadow at every index. */
KFUZZ_OP(kfuzz_xa_op_check_marks, struct kfuzz_xa_state, struct kfuzz_xa_void_arg)
{
	unsigned long i;
	unsigned int m;
	bool got, want;

	if (st->failed)
		return 0;

	for (m = 0; m < KFUZZ_XA_NR_MARKS; m++) {
		for (i = 0; i < st->nr_indices; i++) {
			got = xa_get_mark(&st->xa, i, kfuzz_xa_marks[m]);
			want = st->tok[i] && test_bit(i, st->mk[m]);
			if (got != want) {
				kfuzz_xa_fail(st,
					      "xa_get_mark(%lu, MARK_%u) returned %d, shadow expected %d (entry %px order %u)",
					      i, m, got, want, st->tok[i], st->ord[i]);
				return 0;
			}
		}
	}

	return 0;
}

/*
 * op 8: walk the marked entries. This is the operation that catches
 * multi-index mark bugs, and it is worth being precise about why.
 *
 * After a split, the contents of every index are unchanged and xa_get_mark()
 * still answers correctly for every index, because a mark bit wrongly set on a
 * *sibling* slot reads back the same as the correct bit on the canonical slot.
 * Both of the checks above therefore pass. Only an iterator, which walks slots
 * rather than indices, can see the difference - and what it sees is an internal
 * sibling entry handed back to the caller.
 *
 * Three oracles, in order of assumption risk:
 *   - the iteration must terminate. Absolute, and not hypothetical: a tree whose
 *     marks have been corrupted can livelock xas_find_marked(), because a mark
 *     left on a *sibling* slot is found, canonicalised back to the slot it
 *     points at, and then found again - no forward progress. An unbounded
 *     xas_for_each_marked() under rcu_read_lock() turns that into an RCU stall
 *     with the harness nowhere in the report. Bounding the walk converts it into
 *     an attributable finding instead.
 *   - no internal entry may be returned. Absolute; needs no model.
 *   - the number of entries visited must equal the number of distinct marked
 *     entries in the shadow.
 */
KFUZZ_OP(kfuzz_xa_op_iter_marked, struct kfuzz_xa_state, struct kfuzz_xa_markonly_arg)
{
	unsigned long i, found = 0, expected = 0, steps = 0;
	unsigned int m;
	void *entry;

	if (st->failed)
		return 0;

	m = arg->mark % KFUZZ_XA_NR_MARKS;

	for (i = 0; i < st->nr_indices;) {
		if (!st->tok[i]) {
			i++;
			continue;
		}
		if (test_bit(i, st->mk[m]))
			expected++;
		i += 1UL << st->ord[i];
	}

	{
		XA_STATE(xas, &st->xa, 0);

		rcu_read_lock();
		xas_for_each_marked(&xas, entry, ULONG_MAX, kfuzz_xa_marks[m]) {
			if (++steps > KFUZZ_XA_ITER_CAP(st)) {
				rcu_read_unlock();
				kfuzz_xa_fail(st,
					      "xas_for_each_marked(MARK_%u) did not terminate after %lu iterations (last index %lu)",
					      m, steps - 1, xas.xa_index);
				return 0;
			}
			if (xa_is_internal(entry)) {
				rcu_read_unlock();
				kfuzz_xa_fail(st,
					      "xas_for_each_marked(MARK_%u) returned internal entry %px at index %lu",
					      m, entry, xas.xa_index);
				return 0;
			}
			if (xas.xa_index >= st->nr_indices) {
				rcu_read_unlock();
				kfuzz_xa_fail(st,
					      "xas_for_each_marked(MARK_%u) visited index %lu outside the %u-index space",
					      m, xas.xa_index, st->nr_indices);
				return 0;
			}
			if (entry != st->tok[xas.xa_index]) {
				rcu_read_unlock();
				kfuzz_xa_fail(st,
					      "xas_for_each_marked(MARK_%u) returned %px at index %lu, shadow has %px",
					      m, entry, xas.xa_index, st->tok[xas.xa_index]);
				return 0;
			}
			found++;
		}
		rcu_read_unlock();
	}

	if (found != expected)
		kfuzz_xa_fail(st, "xas_for_each_marked(MARK_%u) visited %lu entries, shadow has %lu marked",
			      m, found, expected);

	return 0;
}

/* op 9: walk every entry; same invariants, no marks involved. */
KFUZZ_OP(kfuzz_xa_op_iter_all, struct kfuzz_xa_state, struct kfuzz_xa_void_arg)
{
	unsigned long i, index, found = 0, expected = 0, steps = 0;
	void *entry;

	if (st->failed)
		return 0;

	for (i = 0; i < st->nr_indices;) {
		if (!st->tok[i]) {
			i++;
			continue;
		}
		expected++;
		i += 1UL << st->ord[i];
	}

	xa_for_each(&st->xa, index, entry) {
		if (++steps > KFUZZ_XA_ITER_CAP(st)) {
			kfuzz_xa_fail(st, "xa_for_each did not terminate after %lu iterations (last index %lu)",
				      steps - 1, index);
			return 0;
		}
		if (xa_is_internal(entry)) {
			kfuzz_xa_fail(st, "xa_for_each returned internal entry %px at index %lu",
				      entry, index);
			return 0;
		}
		if (index >= st->nr_indices) {
			kfuzz_xa_fail(st, "xa_for_each visited index %lu outside the %u-index space",
				      index, st->nr_indices);
			return 0;
		}
		if (entry != st->tok[index]) {
			kfuzz_xa_fail(st, "xa_for_each returned %px at index %lu, shadow has %px",
				      entry, index, st->tok[index]);
			return 0;
		}
		found++;
	}

	if (found != expected)
		kfuzz_xa_fail(st, "xa_for_each visited %lu entries, shadow has %lu", found, expected);

	return 0;
}

/* ------------------------------------------------------------- lifecycle --- */

/*
 * FRAMEWORK GAP: check_correctness_fn() runs after every operation, and the
 * framework offers no way to say "this check is O(n), run it every k ops and
 * once at the end". Verifying 4096 indices x 3 marks after each op would make
 * a sequence O(n^2) and dominate its runtime, so the expensive checks are
 * exposed as ops the fuzzer schedules instead, and this hook only reports the
 * latched verdict.
 */
static int kfuzz_xa_check_correctness(kfuzztest_handle comp)
{
	struct kfuzz_xa_state *st = comp;

	if (!st)
		return 1;

	st->op_index++;
	return st->failed ? 0 : 1;
}

static void kfuzz_xa_free_state(struct kfuzz_xa_state *st)
{
	unsigned int m;

	for (m = 0; m < KFUZZ_XA_NR_MARKS; m++)
		kvfree(st->mk[m]);
	kvfree(st->ord);
	kvfree(st->tok);
	kfree(st->tokpool);
	kfree(st);
}

static kfuzztest_handle kfuzz_xa_initialize(size_t len, char *data)
{
	struct kfuzz_xa_init_arg arg;
	struct kfuzz_xa_state *st;
	unsigned int m, log2;

	st = kzalloc(sizeof(*st), GFP_KERNEL);
	if (!st)
		return NULL;

	memset(&arg, 0, sizeof(arg));
	if (data && len >= sizeof(arg))
		memcpy(&arg, data, sizeof(arg));

	log2 = KFUZZ_XA_MIN_LOG2 +
	       (arg.log2_indices % (KFUZZ_XA_MAX_LOG2 - KFUZZ_XA_MIN_LOG2 + 1));
	st->nr_indices = 1U << log2;

	/*
	 * An entry may not be larger than the index space, otherwise an
	 * order-aligned base plus its extent would run off the end of the
	 * shadow arrays.
	 */
	st->max_order = min_t(unsigned int, KFUZZ_XA_MAX_ORDER, log2);
	st->max_order = min_t(unsigned int, st->max_order,
			      arg.max_order ? arg.max_order % (KFUZZ_XA_MAX_ORDER + 1)
					    : KFUZZ_XA_MAX_ORDER);

	st->tok = kvcalloc(st->nr_indices, sizeof(*st->tok), GFP_KERNEL);
	st->ord = kvcalloc(st->nr_indices, sizeof(*st->ord), GFP_KERNEL);
	st->tokpool = kzalloc(KFUZZ_XA_TOKEN_POOL_SZ, GFP_KERNEL);
	if (!st->tok || !st->ord || !st->tokpool)
		goto fail;

	for (m = 0; m < KFUZZ_XA_NR_MARKS; m++) {
		st->mk[m] = kvcalloc(BITS_TO_LONGS(st->nr_indices),
				     sizeof(unsigned long), GFP_KERNEL);
		if (!st->mk[m])
			goto fail;
	}

	xa_init(&st->xa);

	return st;

fail:
	kfuzz_xa_free_state(st);
	return NULL;
}

static void kfuzz_xa_teardown(kfuzztest_handle comp)
{
	struct kfuzz_xa_state *st = comp;

	if (!st)
		return;

	xa_destroy(&st->xa);
	kfuzz_xa_free_state(st);
}

/*
 * FRAMEWORK GAP: every op above returns 0 unconditionally. A non-zero return
 * aborts the sequence in kfuzztest_invoke() *without* running teardown_fn(),
 * which would leak the XArray's nodes and the whole shadow model, and it also
 * fails the write() - which makes a fuzzing manager discard the execution's
 * coverage. KFUZZ_OP() itself returns -EINVAL on a short argument blob, which
 * is the single most common thing a mutating fuzzer produces, so today a
 * truncated argument leaks and throws away the run.
 */
KFUZZ_REGISTER_HARNESS(xarray, kfuzz_xa_initialize, kfuzz_xa_teardown,
		       kfuzz_xa_check_correctness,
		       kfuzz_xa_op_store,		/* 0 */
		       kfuzz_xa_op_erase,		/* 1 */
		       kfuzz_xa_op_set_mark,		/* 2 */
		       kfuzz_xa_op_clear_mark,		/* 3 */
		       kfuzz_xa_op_split,		/* 4 */
		       kfuzz_xa_op_try_split,		/* 5 */
		       kfuzz_xa_op_check_contents,	/* 6 */
		       kfuzz_xa_op_check_marks,		/* 7 */
		       kfuzz_xa_op_iter_marked,		/* 8 */
		       kfuzz_xa_op_iter_all)		/* 9 */
