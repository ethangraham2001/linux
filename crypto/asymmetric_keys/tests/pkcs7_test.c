#include <crypto/pkcs7.h>
#include <kunit/test.h>

static void fuzz_pkcs7_parse_message(struct kunit *test, char *data,
				     size_t datalen)
{
	struct pkcs7_message *msg;

	msg = pkcs7_parse_message(data, datalen);
	if (msg && !IS_ERR(msg))
		pkcs7_free_message(msg);
}

static struct kunit_case pkcs7_test_cases[] = {
	KUNIT_CASE_FUZZ(fuzz_pkcs7_parse_message),
	{}
};

static struct kunit_suite pkcs7_test_suite = {
	.name = "pkcs7",
	.test_cases = pkcs7_test_cases,
};

kunit_test_suites(&pkcs7_test_suite);
