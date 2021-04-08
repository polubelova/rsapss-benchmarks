objs := main.o curve25519-hacl51.o curve25519-hacl64.o curve25519-vale64.o curve25519-libsodium.o

CFLAGS += -O3 -g -march=native -mtune=native

default: build

run: build
	sudo ./run.sh curve25519_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o curve25519_bench.exe $^ -L ./ -levercrypt -lsodium

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
