#include <linux/kfuzztest.h>
#include <linux/binfmts.h>

struct load_script_arg {
	char buf[BINPRM_BUF_SIZE];
	const char *interp;
	int argc;
	unsigned int interp_flags;
};

FUZZ_TEST(test_load_script, struct load_script_arg)
{
	struct linux_binprm brpm = {};

	KFUZZTEST_ANNOTATE_STRING(load_script_arg, interp);

	memcpy(brpm.buf, arg->buf, BINPRM_BUF_SIZE);
	brpm.interp = arg->interp;
	brpm.argc = arg->argc;
	brpm.interp_flags = arg->interp_flags;
	brpm.p = (unsigned long)kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!brpm.p)
		return;
	load_script(&brpm);
	kfree((void *)brpm.p);
}
