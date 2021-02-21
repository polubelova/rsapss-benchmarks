objs := main.o ed25519-hacl.o ed25519-libsodium.o

CFLAGS += -O3 -g -march=native -mtune=native

default: build

run: build
	sudo ./run.sh ed25519_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o ed25519_bench.exe $^ -L ./ -led25519 -lsodium

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
