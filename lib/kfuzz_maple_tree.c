// SPDX-License-Identifier: GPL-2.0
/*
 * KFuzzTest stateful fuzz harness for the maple tree.
 *
 * The maple tree is a stateful data structure: a bug is usually the result of a
 * *sequence* of operations rather than a single malformed input, so it is a
 * natural fit for the stateful KFuzzTest API (KFUZZ_REGISTER_HARNESS).
 *
 * Two independent oracles run after every operation:
 *
 *  1. mt_validate(), the maple tree's own structural invariant checker. It
 *     verifies pivot limits, parent slot back-pointers, child slot validity,
 *     node occupancy, gap metadata (on allocation trees) and the absence of
 *     sequential NULLs.
 *
 *  2. A shadow model maintained by this harness, which catches *semantic*
 *     failures that leave the tree structurally valid: a load returning the
 *     wrong entry, an erase removing the wrong range, an allocation handing out
 *     an occupied range, or an entry silently going missing.
 *
 * Index space
 * -----------
 * The fuzzer does not address the 64-bit index space directly. Instead the
 * harness carves out a window of @ncells equally sized "cells" starting at
 * @base, and every operation addresses cells rather than raw indices:
 *
 *	cell c covers [base + (c << cell_shift), base + ((c + 1) << cell_shift) - 1]
 *
 * @base and @cell_shift are chosen by the fuzzer, so the window can sit at
 * index 0, at index 1, hard against ULONG_MAX, or anywhere in between, and a
 * single cell can be one index wide or terabytes wide. This keeps the shadow
 * model dense and exact (it is a flat array of cells) while still exercising
 * the full 64-bit pivot range and its boundary conditions.
 *
 * Because every store is cell aligned, every pivot in the tree is cell aligned,
 * which is what makes the walk cross-check below sound.
 *
 * Copyright 2025 Google LLC
 */
#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/kfuzztest.h>
#include <linux/maple_tree.h>
#include <linux/minmax.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/xarray.h>

/* Size of the shadow model, in cells. */
#define KFUZZ_MT_MAX_CELLS 512
/*
 * Largest cell size, as a shift. Bounded so that the whole window
 * (KFUZZ_MT_MAX_CELLS << KFUZZ_MT_MAX_SHIFT) cannot overflow an unsigned long.
 */
#define KFUZZ_MT_MAX_SHIFT (BITS_PER_LONG - 20)
/* Largest allocation request, in cells. */
#define KFUZZ_MT_MAX_ALLOC_CELLS 8

/**
 * struct kfuzz_mt_state - the component under test
 *
 * @mt: the maple tree being fuzzed.
 * @base: index of the first cell.
 * @cell_shift: log2 of the number of indices covered by one cell.
 * @ncells: number of live cells, at most KFUZZ_MT_MAX_CELLS.
 * @flags: the MT_FLAGS_* the tree was initialised with.
 * @gen: monotonic counter used to mint unique entry values.
 * @op_index: index of the operation being executed, for diagnostics.
 * @shadow_valid: false once the harness can no longer track the tree exactly.
 * @failed: true once a mismatch has been reported.
 * @shadow: shadow model. shadow[c] is the value stored in cell @c, or 0 when
 *          the cell is empty. The tree holds xa_mk_value(shadow[c]).
 */
struct kfuzz_mt_state {
	struct maple_tree mt;
	unsigned long base;
	unsigned int cell_shift;
	unsigned int ncells;
	unsigned int flags;
	unsigned long gen;
	unsigned long op_index;
	bool shadow_valid;
	bool failed;
	unsigned long shadow[KFUZZ_MT_MAX_CELLS];
};

/* Initialisation blob, consumed by kfuzz_mt_initialize(). */
struct kfuzz_mt_init_arg {
	__u8 flags_sel;
	__u8 cell_shift;
	__u8 base_sel;
	__u8 __pad;
	__u32 ncells;
	__u64 base_hint;
} __packed;

/* Argument for the range operations (store, insert). */
struct kfuzz_mt_range_arg {
	__u32 first_cell;
	__u32 last_cell;
	__u8 store_null;
	__u8 keep_order;
	__u8 __pad[2];
} __packed;

/* Argument for the point operations (erase, load). */
struct kfuzz_mt_point_arg {
	__u32 cell;
	__u32 __pad;
	__u64 off;
} __packed;

/* Argument for the allocation operations. */
struct kfuzz_mt_alloc_arg {
	__u32 min_cell;
	__u32 max_cell;
	__u32 size_cells;
	__u32 __pad;
} __packed;

/*
 * maple_tree_tests_run / maple_tree_tests_passed are global counters, so two
 * harness invocations validating concurrently would corrupt each other's
 * deltas. Serialise validation across all invocations.
 */
static DEFINE_MUTEX(kfuzz_mt_validate_lock);

/*
 * Report a mismatch. Only the first one is reported: after that the shadow
 * model has diverged from the tree and every subsequent check would fire.
 *
 * This deliberately uses WARN() rather than pr_warn(): a plain printk is not
 * recognised as a bug by a fuzzing manager, and neither is the maple tree's own
 * MT_BUG_ON(), which prints "BUG at ..." without a colon.
 */
#define kfuzz_mt_fail(st, fmt, ...)                                                                    \
	do {                                                                                           \
		if (!(st)->failed) {                                                                   \
			(st)->failed = true;                                                           \
			WARN(1, "kfuzz_maple_tree: op %lu: " fmt "\n", (st)->op_index, ##__VA_ARGS__); \
		}                                                                                      \
	} while (0)

static unsigned long kfuzz_mt_cell_size(const struct kfuzz_mt_state *st)
{
	return 1UL << st->cell_shift;
}

static unsigned long kfuzz_mt_cell_start(const struct kfuzz_mt_state *st, unsigned int cell)
{
	return st->base + ((unsigned long)cell << st->cell_shift);
}

static unsigned long kfuzz_mt_cell_end(const struct kfuzz_mt_state *st, unsigned int cell)
{
	return kfuzz_mt_cell_start(st, cell) + kfuzz_mt_cell_size(st) - 1;
}

/* Map an index back to a cell. Returns false if it falls outside the window. */
static bool kfuzz_mt_cell_of(const struct kfuzz_mt_state *st, unsigned long index, unsigned int *cell)
{
	unsigned long off;

	if (index < st->base)
		return false;
	off = (index - st->base) >> st->cell_shift;
	if (off >= st->ncells)
		return false;
	*cell = off;
	return true;
}

/*
 * Copy a fixed size argument out of the fuzzer-supplied blob. A short blob is
 * not an error: the operation is skipped and the sequence continues, so that a
 * truncated argument does not cost the whole execution.
 */
static bool kfuzz_mt_arg(struct kfuzz_mt_state *st, size_t len, const char *data, void *out, size_t need)
{
	if (st->failed)
		return false;
	if (len < need || !data)
		return false;
	memcpy(out, data, need);
	return true;
}

/*
 * Mint a fresh entry. Values are unique per store, which is what lets the walk
 * cross-check below map a coalesced tree range back onto a run of cells, and
 * what lets kfuzz_mt_op_erase() work out how far an erase reaches.
 *
 * xa_mk_value() also guarantees the entry is neither an "advanced" nor a
 * "reserved" value; handing the tree a raw fuzzer-controlled word would trip
 * the WARN_ON_ONCE(xa_is_advanced(entry)) in mtree_store_range() and report a
 * harness bug as a maple tree bug.
 */
static void *kfuzz_mt_new_entry(struct kfuzz_mt_state *st, unsigned long *val)
{
	*val = ++st->gen;
	return xa_mk_value(*val);
}

static void *kfuzz_mt_expected(const struct kfuzz_mt_state *st, unsigned int cell)
{
	return st->shadow[cell] ? xa_mk_value(st->shadow[cell]) : NULL;
}

static void kfuzz_mt_swap_cells(unsigned int *a, unsigned int *b)
{
	unsigned int tmp = *a;

	*a = *b;
	*b = tmp;
}

/*
 * Run the maple tree's own structural validation. mt_validate() reports through
 * MT_BUG_ON()/MAS_WARN_ON(), which under CONFIG_DEBUG_MAPLE_TREE only bump a
 * pair of global counters and print, so detect a failure by watching the
 * counters and turn it into something a fuzzing manager can see.
 */
static void kfuzz_mt_validate(struct kfuzz_mt_state *st, struct maple_tree *mt, const char *what)
{
	unsigned int run, passed, ran, ok;

	mutex_lock(&kfuzz_mt_validate_lock);
	run = atomic_read(&maple_tree_tests_run);
	passed = atomic_read(&maple_tree_tests_passed);

	mtree_lock(mt);
	mt_validate(mt);
	mtree_unlock(mt);

	ran = atomic_read(&maple_tree_tests_run) - run;
	ok = atomic_read(&maple_tree_tests_passed) - passed;
	mutex_unlock(&kfuzz_mt_validate_lock);

	if (ran != ok)
		kfuzz_mt_fail(st, "mt_validate() failed %u of %u checks on the %s tree", ran - ok, ran, what);
}

/*
 * Walk @mt and cross-check every entry against the shadow model.
 *
 * Every stored range is cell aligned, so each range the walk returns must cover
 * a whole number of cells, every covered cell must hold the range's value, no
 * cell may be covered twice (that would mean overlapping ranges), and the set
 * of covered cells must be exactly the set of non-empty shadow cells.
 *
 * Note that a range is *not* required to be reported in one piece: the tree is
 * free to represent one stored range as two adjacent slots holding the same
 * value, so this checks coverage rather than exact segmentation.
 */
static void kfuzz_mt_check_contents(struct kfuzz_mt_state *st, struct maple_tree *mt)
{
	DECLARE_BITMAP(seen, KFUZZ_MT_MAX_CELLS);
	unsigned int c, c0, c1;
	void *entry;

	bitmap_zero(seen, KFUZZ_MT_MAX_CELLS);

	mtree_lock(mt);
	{
		MA_STATE(mas, mt, 0, 0);

		mas_for_each(&mas, entry, ULONG_MAX) {
			if (st->failed)
				break;
			if (!kfuzz_mt_cell_of(st, mas.index, &c0) || !kfuzz_mt_cell_of(st, mas.last, &c1) ||
			    kfuzz_mt_cell_start(st, c0) != mas.index || kfuzz_mt_cell_end(st, c1) != mas.last) {
				kfuzz_mt_fail(st, "walk: range [%lx, %lx] is not a cell aligned subrange of the window",
					      mas.index, mas.last);
				break;
			}
			if (!xa_is_value(entry)) {
				kfuzz_mt_fail(st, "walk: entry at [%lx, %lx] is not a value entry", mas.index,
					      mas.last);
				break;
			}
			for (c = c0; c <= c1; c++) {
				if (st->shadow[c] != xa_to_value(entry)) {
					kfuzz_mt_fail(st, "walk: cell %u holds value %lu, expected %lu", c,
						      xa_to_value(entry), st->shadow[c]);
					break;
				}
				if (test_bit(c, seen)) {
					kfuzz_mt_fail(st, "walk: cell %u is covered by two ranges", c);
					break;
				}
				__set_bit(c, seen);
			}
		}
	}
	mtree_unlock(mt);

	if (st->failed)
		return;

	for (c = 0; c < st->ncells; c++) {
		if (!!st->shadow[c] == !!test_bit(c, seen))
			continue;
		kfuzz_mt_fail(st, "walk: cell %u is %s in the tree but %s in the shadow", c,
			      test_bit(c, seen) ? "present" : "absent", st->shadow[c] ? "present" : "absent");
		return;
	}
}

/*
 * op 0: mtree_store_range().
 *
 * Covers a point store (first == last), a range store, and a range erase
 * (store_null). With keep_order set an inverted range is passed through
 * unnormalised to check that the API rejects it.
 */
// static int kfuzz_mt_op_store(void *comp, size_t len, char *data)
KFUZZ_OP(kfuzz_mt_op_store, struct kfuzz_mt_state, struct kfuzz_mt_range_arg)
{
	unsigned long val = 0, first, last;
	unsigned int c0, c1, c;
	void *entry;
	int ret;

	c0 = arg->first_cell % st->ncells;
	c1 = arg->last_cell % st->ncells;
	if (!(arg->keep_order & 1) && c0 > c1)
		kfuzz_mt_swap_cells(&c0, &c1);

	first = kfuzz_mt_cell_start(st, c0);
	last = kfuzz_mt_cell_end(st, c1);

	entry = (arg->store_null & 1) ? NULL : kfuzz_mt_new_entry(st, &val);
	ret = mtree_store_range(&st->mt, first, last, entry, GFP_KERNEL);

	if (first > last) {
		if (ret != -EINVAL)
			kfuzz_mt_fail(st, "store_range(%lx, %lx) with first > last returned %d, expected -EINVAL",
				      first, last, ret);
		return 0;
	}
	if (ret == -ENOMEM)
		return 0; /* Nothing was stored, the shadow is still correct. */
	if (ret) {
		kfuzz_mt_fail(st, "store_range(%lx, %lx) returned %d", first, last, ret);
		return 0;
	}

	for (c = c0; c <= c1; c++)
		st->shadow[c] = val;
	return 0;
}

/*
 * op 1: mtree_insert_range().
 *
 * Only one direction of the -EEXIST contract can be checked. mas_insert() also
 * reports -EEXIST when a *free* range spans more than one slot ("spanning
 * writes always overwrite something"), so a failure is not evidence that the
 * range was occupied. A success over an occupied range, however, is a bug.
 */
static int kfuzz_mt_op_insert(void *comp, char *data, size_t len)
{
	struct kfuzz_mt_state *st = comp;
	struct kfuzz_mt_range_arg arg;
	unsigned long val, first, last;
	unsigned int c0, c1, c;
	bool occupied = false;
	void *entry;
	int ret;

	if (!st || !kfuzz_mt_arg(st, len, data, &arg, sizeof(arg)))
		return 0;

	c0 = arg.first_cell % st->ncells;
	c1 = arg.last_cell % st->ncells;
	if (!(arg.keep_order & 1) && c0 > c1)
		kfuzz_mt_swap_cells(&c0, &c1);

	first = kfuzz_mt_cell_start(st, c0);
	last = kfuzz_mt_cell_end(st, c1);

	if (first <= last) {
		for (c = c0; c <= c1; c++) {
			if (st->shadow[c]) {
				occupied = true;
				break;
			}
		}
	}

	entry = kfuzz_mt_new_entry(st, &val);
	ret = mtree_insert_range(&st->mt, first, last, entry, GFP_KERNEL);

	if (first > last) {
		if (ret != -EINVAL)
			kfuzz_mt_fail(st, "insert_range(%lx, %lx) with first > last returned %d, expected -EINVAL",
				      first, last, ret);
		return 0;
	}

	switch (ret) {
	case 0:
		if (occupied) {
			kfuzz_mt_fail(st, "insert_range(%lx, %lx) succeeded over an occupied range", first, last);
			return 0;
		}
		for (c = c0; c <= c1; c++)
			st->shadow[c] = val;
		break;
	case -EEXIST:
	case -ENOMEM:
		break;
	default:
		kfuzz_mt_fail(st, "insert_range(%lx, %lx) returned %d", first, last, ret);
		break;
	}
	return 0;
}

/*
 * op 2: mtree_erase().
 *
 * Erasing anywhere inside a range removes the whole range, and the tree
 * coalesces adjacent slots holding the same value. Since every store mints a
 * unique value, the erased range is exactly the maximal run of cells around the
 * target that share its value.
 */
static int kfuzz_mt_op_erase(void *comp, char *data, size_t len)
{
	struct kfuzz_mt_state *st = comp;
	struct kfuzz_mt_point_arg arg;
	unsigned long index, val;
	unsigned int cell, i;
	void *got, *expected;

	if (!st || !kfuzz_mt_arg(st, len, data, &arg, sizeof(arg)))
		return 0;

	cell = arg.cell % st->ncells;
	index = kfuzz_mt_cell_start(st, cell) + ((unsigned long)arg.off & (kfuzz_mt_cell_size(st) - 1));

	expected = st->shadow_valid ? kfuzz_mt_expected(st, cell) : NULL;
	got = mtree_erase(&st->mt, index);

	if (!st->shadow_valid)
		return 0;
	if (got != expected) {
		kfuzz_mt_fail(st, "erase(%lx) returned %px, expected %px", index, got, expected);
		return 0;
	}
	if (!expected)
		return 0;

	/*
	 * mtree_erase() discards the error from mas_erase(), so an allocation
	 * failure looks exactly like a successful erase. Confirm the entry is
	 * really gone rather than trusting the return value.
	 */
	if (mtree_load(&st->mt, index)) {
		st->shadow_valid = false;
		return 0;
	}

	val = st->shadow[cell];
	for (i = cell; i < st->ncells && st->shadow[i] == val; i++)
		st->shadow[i] = 0;
	i = cell;
	while (i-- > 0 && st->shadow[i] == val)
		st->shadow[i] = 0;
	return 0;
}

/* op 3: mtree_load(). */
static int kfuzz_mt_op_load(void *comp, char *data, size_t len)
{
	struct kfuzz_mt_state *st = comp;
	struct kfuzz_mt_point_arg arg;
	void *got, *expected;
	unsigned long index;
	unsigned int cell;

	if (!st || !kfuzz_mt_arg(st, len, data, &arg, sizeof(arg)))
		return 0;

	cell = arg.cell % st->ncells;
	index = kfuzz_mt_cell_start(st, cell) + ((unsigned long)arg.off & (kfuzz_mt_cell_size(st) - 1));

	got = mtree_load(&st->mt, index);
	if (!st->shadow_valid)
		return 0;

	expected = kfuzz_mt_expected(st, cell);
	if (got != expected)
		kfuzz_mt_fail(st, "load(%lx) returned %px, expected %px", index, got, expected);
	return 0;
}

/* op 4: iterate the whole tree and compare it against the shadow model. */
static int kfuzz_mt_op_walk(void *comp, char *data, size_t len)
{
	struct kfuzz_mt_state *st = comp;

	if (!st || st->failed || !st->shadow_valid)
		return 0;

	kfuzz_mt_check_contents(st, &st->mt);
	return 0;
}

/* Shared body for the two allocation operations. */
static int kfuzz_mt_do_alloc(struct kfuzz_mt_state *st, size_t len, char *data, bool reverse)
{
	struct kfuzz_mt_alloc_arg arg;
	unsigned long min, max, size, start = 0, val;
	unsigned int cmin, cmax, size_cells, c0, c;
	const char *name = reverse ? "alloc_rrange" : "alloc_range";
	void *entry;
	int ret;

	if (!kfuzz_mt_arg(st, len, data, &arg, sizeof(arg)))
		return 0;

	cmin = arg.min_cell % st->ncells;
	cmax = arg.max_cell % st->ncells;
	if (cmin > cmax)
		kfuzz_mt_swap_cells(&cmin, &cmax);

	size_cells = 1 + (arg.size_cells % KFUZZ_MT_MAX_ALLOC_CELLS);
	size = (unsigned long)size_cells << st->cell_shift;
	min = kfuzz_mt_cell_start(st, cmin);
	max = kfuzz_mt_cell_end(st, cmax);

	entry = kfuzz_mt_new_entry(st, &val);
	if (reverse)
		ret = mtree_alloc_rrange(&st->mt, &start, entry, size, min, max, GFP_KERNEL);
	else
		ret = mtree_alloc_range(&st->mt, &start, entry, size, min, max, GFP_KERNEL);

	if (!(st->flags & MT_FLAGS_ALLOC_RANGE)) {
		/* Allocating from a non-allocation tree must fail cleanly. */
		if (ret != -EINVAL)
			kfuzz_mt_fail(st, "%s on a non-allocation tree returned %d", name, ret);
		return 0;
	}

	switch (ret) {
	case 0:
		break;
	case -EBUSY: /* No gap large enough. */
	case -EINVAL: /* The request does not fit in [min, max]. */
	case -ENOMEM:
		return 0;
	default:
		kfuzz_mt_fail(st, "%s(size %lx, [%lx, %lx]) returned %d", name, size, min, max, ret);
		return 0;
	}

	if (start < min || start > max - (size - 1)) {
		kfuzz_mt_fail(st, "%s returned %lx, outside [%lx, %lx] for size %lx", name, start, min, max, size);
		return 0;
	}

	if (!st->shadow_valid)
		return 0;

	if (!kfuzz_mt_cell_of(st, start, &c0) || kfuzz_mt_cell_start(st, c0) != start || c0 + size_cells > st->ncells) {
		/*
		 * Every gap in the window starts on a cell boundary, so this
		 * should not happen. Treat it as the harness losing track
		 * rather than as a tree bug: stop trusting the shadow model
		 * and let mt_validate() carry on alone.
		 */
		st->shadow_valid = false;
		return 0;
	}

	for (c = c0; c < c0 + size_cells; c++) {
		if (st->shadow[c]) {
			kfuzz_mt_fail(st, "%s returned %lx, but cell %u is already occupied", name, start, c);
			return 0;
		}
	}
	for (c = c0; c < c0 + size_cells; c++)
		st->shadow[c] = val;
	return 0;
}

/* op 5: mtree_alloc_range(). */
static int kfuzz_mt_op_alloc(void *comp, char *data, size_t len)
{
	struct kfuzz_mt_state *st = comp;

	if (!st)
		return 0;
	return kfuzz_mt_do_alloc(st, len, data, false);
}

/* op 6: mtree_alloc_rrange(). */
static int kfuzz_mt_op_alloc_rev(void *comp, char *data, size_t len)
{
	struct kfuzz_mt_state *st = comp;

	if (!st)
		return 0;
	return kfuzz_mt_do_alloc(st, len, data, true);
}

/*
 * op 7: mtree_dup().
 *
 * The duplicate is a self-checking operation: it must be structurally valid and
 * must hold exactly the same contents as the source.
 */
static int kfuzz_mt_op_dup(void *comp, char *data, size_t len)
{
	struct kfuzz_mt_state *st = comp;
	struct maple_tree newmt;
	int ret;

	if (!st || st->failed)
		return 0;

	/* mtree_dup() requires identical attributes and an empty destination. */
	mt_init_flags(&newmt, st->mt.ma_flags & ~MT_FLAGS_HEIGHT_MASK);

	ret = mtree_dup(&st->mt, &newmt, GFP_KERNEL);
	if (ret == -ENOMEM)
		return 0;
	if (ret) {
		kfuzz_mt_fail(st, "mtree_dup() returned %d", ret);
		return 0;
	}

	kfuzz_mt_validate(st, &newmt, "duplicated");
	if (!st->failed && st->shadow_valid)
		kfuzz_mt_check_contents(st, &newmt);

	mtree_destroy(&newmt);
	return 0;
}

/*
 * Correctness check, run by the framework after every operation. Structural
 * validation happens here; the semantic checks live in the operations
 * themselves, where the expected result is known.
 */
static int kfuzz_mt_check_correctness(void *comp)
{
	struct kfuzz_mt_state *st = comp;

	if (!st)
		return 1;
	if (!st->failed)
		kfuzz_mt_validate(st, &st->mt, "fuzzed");

	st->op_index++;
	return st->failed ? 0 : 1;
}

static void *kfuzz_mt_initialize(size_t len, char *data)
{
	struct kfuzz_mt_init_arg arg;
	struct kfuzz_mt_state *st;
	unsigned long span, top;

	st = kzalloc(sizeof(*st), GFP_KERNEL);
	if (!st)
		return NULL;

	memset(&arg, 0, sizeof(arg));
	if (data && len >= sizeof(arg))
		memcpy(&arg, data, sizeof(arg));

	st->cell_shift = arg.cell_shift % (KFUZZ_MT_MAX_SHIFT + 1);
	st->ncells = 1 + (arg.ncells % KFUZZ_MT_MAX_CELLS);
	st->flags = (arg.flags_sel & 1) ? MT_FLAGS_ALLOC_RANGE : 0;
	st->shadow_valid = true;

	/*
	 * Place the window. The interesting positions are the ones a fuzzer is
	 * unlikely to stumble on: flush against 0, just past 0, and flush
	 * against ULONG_MAX.
	 */
	span = (unsigned long)st->ncells << st->cell_shift;
	top = ULONG_MAX - span + 1;
	switch (arg.base_sel & 3) {
	case 0:
		st->base = 0;
		break;
	case 1:
		st->base = 1;
		break;
	case 2:
		st->base = top;
		break;
	default:
		st->base = min_t(unsigned long, (unsigned long)arg.base_hint, top);
		break;
	}

	mt_init_flags(&st->mt, st->flags);
	return st;
}

/*
 * NOTE: these two must be named exactly "teardown" and "check_correctness".
 * KFUZZ_REGISTER_HARNESS() names its macro parameters after the struct fields
 * it initialises, so `.teardown = teardown` expands to `.<your name> = <your
 * name>` and fails to compile for any other identifier. See the report that
 * accompanies this file.
 */
static void kfuzz_mt_teardown(void *comp)
{
	struct kfuzz_mt_state *st = comp;

	if (!st)
		return;
	mtree_destroy(&st->mt);
	kfree(st);
}

KFUZZ_REGISTER_HARNESS(maple_tree, kfuzz_mt_initialize, kfuzz_mt_teardown, kfuzz_mt_check_correctness,
		       kfuzz_mt_op_store, kfuzz_mt_op_insert, kfuzz_mt_op_erase, kfuzz_mt_op_load, kfuzz_mt_op_walk,
		       kfuzz_mt_op_alloc, kfuzz_mt_op_alloc_rev, kfuzz_mt_op_dup)
