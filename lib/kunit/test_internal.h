#ifndef KUNIT_TEST_INTERNAL_H
#define KUNIT_TEST_INTERNAL_H

#include <kunit/test.h>

void kunit_run_case_catch_errors(struct kunit_suite *suite,
				 struct kunit_case *test_case,
				 struct kunit *test);

#endif /* KUNIT_TEST_INTERNAL_H */
