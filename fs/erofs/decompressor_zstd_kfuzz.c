#include <linux/kfuzztest.h>

#include "erofs_fs.h"

struct z_erofs_load_zstd_config_arg {
	void *data;
	int size;
};

FUZZ_TEST(test_z_erofs_load_zstd_config, struct z_erofs_load_zstd_config_arg)
{
	struct super_block sb = {};
	struct erofs_super_block dsb = {};
	KFUZZTEST_EXPECT_NOT_NULL(z_erofs_load_zstd_config_arg, data);
	KFUZZTEST_ANNOTATE_LEN(z_erofs_load_zstd_config_arg, size, data);
	z_erofs_load_zstd_config(&sb, &dsb, arg->data, arg->size);
}
