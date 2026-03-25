#include <crypto/internal/rsa.h>
#include <kunit/test.h>

static void fuzz_rsa_parse_pub_key(struct kunit *test, char *data,
				   size_t datalen)
{
	struct rsa_key out;

	rsa_parse_priv_key(&out, data, datalen);
}

static void fuzz_rsa_parse_priv_key(struct kunit *test, char *data,
				    size_t datalen)
{
	struct rsa_key out;

	rsa_parse_priv_key(&out, data, datalen);
}

static struct kunit_case rsa_helper_test_cases[] = {
	KUNIT_CASE_FUZZ(fuzz_rsa_parse_pub_key),
	KUNIT_CASE_FUZZ(fuzz_rsa_parse_priv_key),
	{}
};

static struct kunit_suite rsa_helper_test_suite = {
	.name = "rsa_helper",
	.test_cases = rsa_helper_test_cases,
};

kunit_test_suites(&rsa_helper_test_suite);
