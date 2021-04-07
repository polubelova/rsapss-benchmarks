OPENSSL_HOME ?= ../../openssl

objs := main.o rsapss-openssl.o rsapss-hacl.o

CFLAGS += -I$(KREMLIN_HOME)/include -I$(HACL_HOME)/dist/gcc-compatible \
	-I$(HACL_HOME)/code/bignum/dist \
	-I$(KREMLIN_HOME)/kremlib/dist/minimal \
	-I$(OPENSSL_HOME)/include -I$(OPENSSL_HOME)/include/crypto -I$(OPENSSL_HOME)/crypto

CFLAGS += -O3 -g -march=native -mtune=native
CFLAGS += -Wno-deprecated-declarations

default: build

run: build
	sudo ./run.sh rsapss_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o rsapss_bench.exe $^ -L ./../libraries $(OPENSSL_HOME)/libcrypto.a -lpthread -ldl -lrsapss

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
