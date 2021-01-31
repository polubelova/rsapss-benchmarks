Required libraries
==================
- libcrypto_asm.a
- libcrypto_no_mulx.a
- libcrypto_no_asm.a (compiled with the `no-asm` flag)
- libgmp_asm.a
- libgmp_no_asm.a (compiled with the `disable-assembly` flag)
- libbignum.a (from hacl-star/code/bignum)

To get `libcrypto_no_asm_pre.a`, `libcrypto_asm_pre.a`, `libcrypto_no_mulx_pre.a`, and `libgmp_no_asm_pre.a`, one needs to run `./rename-libs`


INSTALL
=======
- openssl
```
git clone https://github.com/openssl/openssl
./config && make
```

- openssl-no-asm
```
git clone https://github.com/openssl/openssl
./config no-asm && make
```

- openssl-no-mulx
```
git clone https://github.com/openssl/openssl
```
  * To control the capability vector, the particular bit should be set to 0: https://www.openssl.org/docs/manmaster/man3/OPENSSL_ia32cap.html
  * To disable the BMI2 instructions (e.g. MULX and RORX) and the ADCX and ADOX instructions, one needs to modify the bn_mod_exp_mont_consttime function from the https://github.com/openssl/openssl/blob/master/crypto/bn/bn_exp.c#L590 file:
```
    extern unsigned int OPENSSL_ia32cap_P[4];
    OPENSSL_ia32cap_P[2] &= ~0x100; //BMI2 instructions, e.g. MULX and RORX
    OPENSSL_ia32cap_P[2] &= ~0x80000; //ADCX and ADOX instructions
```
and then compile the source code
```
./config && make
```

- gmp
  * Download gmp from https://gmplib.org/#DOWNLOAD
```
./configure && make
make check
make install
```

- gmp-no-asm
  * Download gmp from https://gmplib.org/#DOWNLOAD
```
./configure --disable-assembly && make
make check
make install
```

Example
======
```
cp /home/marina/openssl/libcrypto.a libcrypto_asm.a
cp /home/marina/openssl-no-asm/openssl/libcrypto.a libcrypto_no_asm.a
./rename-libs
```
