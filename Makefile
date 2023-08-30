CC = /usr/bin/gcc
CFLAGS = -Wall -g -O3 -Wextra -Wpedantic
LDLIBS = -lcrypto -lm

SOURCES = params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss.c xmss_core.c xmss_commons.c utils.c thpool.c
HEADERS = params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss.h xmss_core.h xmss_commons.h utils.h thpool.h

SOURCES_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(SOURCES))
HEADERS_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(HEADERS))

TESTS = test/performance_sign \
        test/performance_verify \

UI = ui/xmss_keypair \
     ui/xmss_sign \
     ui/xmss_open \
     ui/xmssmt_keypair \
     ui/xmssmt_sign \
     ui/xmssmt_open \
     ui/xmss_keypair_fast \
     ui/xmss_sign_fast \
     ui/xmss_open_fast \
     ui/xmssmt_keypair_fast \
     ui/xmssmt_sign_fast \
     ui/xmssmt_open_fast \

all: tests ui

tests: $(TESTS)

ui: $(UI)

.PHONY: clean test

test/performance_sign: test/xmss_multi_sign.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) -DXMSS -DXMSS_VARIANT=\"XMSS-SHA2_10_256\" -DPERFORMANCE_TYPE=\"sign\" $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS) -pthread -lpthread

test/performance_verify: test/xmss_multi_verify.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) -DXMSS -DXMSS_VARIANT=\"XMSS-SHA2_10_256\" -DPERFORMANCE_TYPE=\"verify\" $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

ui/xmss_%_fast: ui/%.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

ui/xmssmt_%_fast: ui/%.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

ui/xmss_%: ui/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

ui/xmssmt_%: ui/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

clean:
	-$(RM) $(TESTS)
	-$(RM) $(UI)