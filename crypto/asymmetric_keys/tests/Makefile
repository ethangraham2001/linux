pkcs7-test-y := $(and $(CONFIG_KUNIT),$(filter y, $(CONFIG_PKCS7_MESSAGE_PARSER)))
rsa-helper-test-y := $(and $(CONFIG_KUNIT),$(filter y, $(CONFIG_CRYPTO_RSA)))
obj-$(pkcs7-test-y) += pkcs7_test.o
obj-$(rsa-helper-test-y) += rsa_helper_test.o
