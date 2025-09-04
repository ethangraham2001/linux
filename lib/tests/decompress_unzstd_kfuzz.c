#include <linux/kfuzztest.h>

struct decompress_single_arg {
	const char *in_buf;
	long in_len;
	long out_len;
};

static void error(char *c)
{
	pr_info("%s", c);
}

FUZZ_TEST(test_decompress_single, struct decompress_single_arg)
{
	char *out_buf;
	long in_pos;
	KFUZZTEST_EXPECT_NOT_NULL(decompress_single_arg, in_buf);
	KFUZZTEST_ANNOTATE_LEN(decompress_single_arg, in_len, in_buf);
	KFUZZTEST_EXPECT_IN_RANGE(decompress_single_arg, out_len, 128, 1024);

	out_buf = kmalloc(arg->out_len, GFP_KERNEL);
	if (!out_buf)
		return;
	decompress_single(arg->in_buf, arg->in_len, out_buf, arg->out_len, &in_pos, error);
	kfree(out_buf);
}
