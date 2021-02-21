objs := main.o rsapss-openssl.o rsapss-hacl.o

CFLAGS += -O3 -g -march=native -mtune=native

default: build

run: build
	sudo ./run.sh rsapss_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o rsapss_bench.exe $^ -L ./../libraries -lcrypto_no_asm_pre -lcrypto_asm_pre -lpthread -ldl -lrsapss

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
