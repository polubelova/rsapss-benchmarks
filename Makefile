BORINGSSL_HOME ?= ../boringssl
OPENSSL_HOME ?= ../openssl

TARGETS = $(patsubst %.c,%.exe,$(wildcard *.c))
CFLAGS := -I$(KREMLIN_HOME)/include -I$(HACL_HOME)/dist/gcc-compatible \
	-I$(KREMLIN_HOME)/kremlib/dist/minimal \
	-I$(BORINGSSL_HOME)/include -I$(BORINGSSL_HOME)/include/openssl \
	-I$(OPENSSL_HOME)/include -I$(OPENSSL_HOME)/include/crypto -I$(OPENSSL_HOME)/crypto \
	-O3 -march=native -mtune=native $(CFLAGS)

all: $(TARGETS)

test: $(patsubst %.exe,%.test,$(TARGETS))

# Dependency
%.d: %.c
	@set -e; rm -f $@; \
	  $(CC) -MM $(CFLAGS) $< > $@.$$$$; \
	  sed 's,\($(notdir $*)\)\.o[ :]*,$(dir $@)\1.o $@ : ,g' < $@.$$$$ > $@; \
	  rm -f $@.$$$$

rsapss-openssl-test.exe: rsapss-openssl-test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ librsapss.a -o $@ $(OPENSSL_HOME)/libcrypto.a -lpthread -ldl

rsapss-boringssl-test.exe: rsapss-boringssl-test.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ librsapss.a -o $@ $(BORINGSSL_HOME)/build/crypto/libcrypto.a -lpthread -ldl

%.exe: %.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ librsapss.a -o $@

# Running tests
%.test: %.exe
	./$<

clean:
	rm -rf *.o *.d *.exe
