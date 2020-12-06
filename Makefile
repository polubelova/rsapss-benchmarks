BORINGSSL_HOME ?= ../boringssl
OPENSSL_HOME ?= ../openssl

TARGETS = $(patsubst %.c,%.exe,$(wildcard *.c))
CFLAGS := -I$(KREMLIN_HOME)/include -I$(HACL_HOME)/dist/gcc-compatible \
	-I$(HACL_HOME)/code/bignum/dist \
	-I$(KREMLIN_HOME)/kremlib/dist/minimal \
	-I$(BORINGSSL_HOME)/include -I$(BORINGSSL_HOME)/include/openssl \
	-I$(OPENSSL_HOME)/include -I$(OPENSSL_HOME)/include/crypto -I$(OPENSSL_HOME)/crypto \
	-O3 -march=native -mtune=native $(CFLAGS)

all: librsapss.a \
	$(TARGETS)

# Dependency
%.d: %.c
	@set -e; rm -f $@; \
	  $(CC) -MM $(CFLAGS) $< > $@.$$$$; \
	  sed 's,\($(notdir $*)\)\.o[ :]*,$(dir $@)\1.o $@ : ,g' < $@.$$$$ > $@; \
	  rm -f $@.$$$$

librsapss.a:
	rm -rf $(HACL_HOME)/code/rsapss/dist/*.a $(HACL_HOME)/code/rsapss/dist/*.o && \
	OTHERFLAGS="--admit_smt_queries true" make -C $(HACL_HOME)/code/rsapss dist/librsapss.a && \
	cp $(HACL_HOME)/code/rsapss/dist/librsapss.a librsapss.a

libbignum.a:
	rm -rf $(HACL_HOME)/code/bignum/dist/*.a $(HACL_HOME)/code/bignum/dist/*.o && \
	OTHERFLAGS="--admit_smt_queries true" make -C $(HACL_HOME)/code/bignum dist/libbignum.a && \
	cp $(HACL_HOME)/code/bignum/dist/libbignum.a libbignum.a

rsapss-openssl-test.exe: librsapss.a rsapss-openssl-test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ librsapss.a -o $@ $(OPENSSL_HOME)/libcrypto.a -lpthread -ldl

rsapss-openssl-test-4096.exe: librsapss.a rsapss-openssl-test-4096.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ librsapss.a -o $@ $(OPENSSL_HOME)/libcrypto.a -lpthread -ldl

rsapss-boringssl-test.exe: librsapss.a rsapss-boringssl-test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ librsapss.a -o $@ $(BORINGSSL_HOME)/build/crypto/libcrypto.a -lpthread -ldl

bignum-openssl-test.exe: libbignum.a bignum-openssl-test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ libbignum.a -o $@ $(OPENSSL_HOME)/libcrypto.a -lpthread -ldl

mul-openssl-test.exe: libbignum.a mul-openssl-test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ libbignum.a -o $@ $(OPENSSL_HOME)/libcrypto.a -lpthread -ldl

%.exe: %.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ librsapss.a -o $@

clean:
	rm -rf *.o *.d *.exe *.a
