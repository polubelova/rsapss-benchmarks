objs := main.o modexp-openssl.o modexp-openssl_c.o modexp-openssl_no_mulx.o modexp-gmp.o modexp-gmp_c.o modexp-hacl_fw.o modexp-hacl_bm.o

CFLAGS += -O3 -g -march=native -mtune=native

default: build

run: build
	sudo ./run.sh modexp_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o modexp_bench.exe $^ -L ./../libraries -lcrypto_no_asm_pre -lcrypto_no_mulx_pre -lcrypto_asm_pre -lpthread -ldl -lgmp_asm -lgmp_no_asm_pre -lbignum

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
