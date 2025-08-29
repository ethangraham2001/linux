# SPDX-License-Identifier: GPL-2.0
export srctree := $(abspath ../..)
export CC      := gcc
export LD      := ld
export AR      := ar

kfuzztest-bridge:

include $(srctree)/tools/build/Makefile.include

kfuzztest-bridge: kfuzztest_bridge.o byte_buffer.o kfuzztest_encoder.o kfuzztest_input_lexer.o kfuzztest_input_parser.o rand_stream.o
	$(CC) -o $@ $^

kfuzztest-bridge.%: fixdep FORCE
	make -f $(srctree)/tools/build/Makefile.build dir=. $@

kfuzztest-bridge-in.o: fixdep FORCE
	make $(build)=ex

clean:
	find . -name '*.o' -delete -o -name '\.*.cmd' -delete -o -name '\.*.d' -delete
	rm -f ex ex.i ex.s

.PHONY: FORCE
