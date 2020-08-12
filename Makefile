BORINGSSL_HOME ?= ../boringssl
OPENSSL_HOME ?= ../openssl

TARGETS = $(patsubst %.c,%.exe,$(wildcard *.c))
CFLAGS := -I$(KREMLIN_HOME)/include -I$(HACL_HOME)/dist/gcc-compatible \
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

rsapss-openssl-test.exe: rsapss-openssl-test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ librsapss.a -o $@ $(OPENSSL_HOME)/libcrypto.a -lpthread -ldl

rsapss-boringssl-test.exe: rsapss-boringssl-test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ librsapss.a -o $@ $(BORINGSSL_HOME)/build/crypto/libcrypto.a -lpthread -ldl

%.exe: %.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ librsapss.a -o $@

clean:
	rm -rf *.o *.d *.exe *.a
