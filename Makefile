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

libed25519.a:
	rm -rf $(HACL_HOME)/code/ed25519/dist/*.a $(HACL_HOME)/code/ed25519/dist/*.o && \
	OTHERFLAGS="--admit_smt_queries true" make -C $(HACL_HOME)/code/ed25519 dist/libed25519.a && \
	cp $(HACL_HOME)/code/ed25519/dist/libed25519.a libed25519.a

copy-libs: libbignum.a librsapss.a libed25519.a
	cp libbignum.a libraries/libbignum.a && \
	cp librsapss.a libraries/librsapss.a && \
	cp libed25519.a libraries/libed25519.a

libbignumhacl.a:
	cp libraries/Hacl.BenchBignum.fst $(HACL_HOME)/code/bignum/Hacl.BenchBignum.fst && \
	cp libraries/Hacl.BenchKaratsuba.fst $(HACL_HOME)/code/bignum/Hacl.BenchKaratsuba.fst && \
	rm -rf $(HACL_HOME)/code/bignum/dist/*.a $(HACL_HOME)/code/bignum/dist/*.o && \
	OTHERFLAGS="--admit_smt_queries true" make -C $(HACL_HOME)/code/bignum dist/libbignum.a && \
	cp $(HACL_HOME)/code/bignum/dist/libbignum.a libbignumhacl.a

rsapss-boringssl-test.exe: librsapss.a rsapss-openssl-test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ librsapss.a -o $@ $(BORINGSSL_HOME)/build/crypto/libcrypto.a -lpthread -ldl

modexp-hacl-test.exe: libbignumhacl.a modexp-hacl-test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ libbignumhacl.a -o $@ $(BORINGSSL_HOME)/build/crypto/libcrypto.a -lpthread -ldl

mul-hacl-test.exe: libbignumhacl.a mul-hacl-test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ libbignumhacl.a -o $@ $(BORINGSSL_HOME)/build/crypto/libcrypto.a -lpthread -ldl

%.exe: libbignum.a librsapss.a %.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ libbignum.a librsapss.a -o $@ $(OPENSSL_HOME)/libcrypto.a -lpthread -ldl

clean:
	rm -rf *.o *.d *.exe *.a
