#include "kbench-common.h"

#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"
#include "openssl/digest.h"
#include "openssl/bn.h"


int
openssl_sign(
  RSA* pRsaKey,
  size_t salt_len,
  uint8_t* msg,
  uint32_t msg_len,
  uint8_t* sig,
  size_t sig_len
)
{
  const EVP_MD *digest_algo;
  unsigned char md[128];
  unsigned digest_len;
  EVP_MD_CTX *md_ctx;

  digest_algo = EVP_sha256();
  md_ctx = EVP_MD_CTX_new();
  EVP_DigestInit(md_ctx, digest_algo);
  EVP_DigestUpdate(md_ctx, msg, msg_len);
  EVP_DigestFinal(md_ctx, md, &digest_len);

  EVP_PKEY *pkey = NULL;
  pkey = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(pkey, pRsaKey);

  EVP_PKEY_CTX *pkey_ctx;
  pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);

  EVP_PKEY_sign_init(pkey_ctx);
  EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
  EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, salt_len);
  EVP_PKEY_CTX_set_signature_md(pkey_ctx, digest_algo);
  EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, digest_algo);

  int ret = EVP_PKEY_sign(pkey_ctx, sig, &sig_len, md, digest_len);

  return ret;
}

int
openssl_verify(
  RSA* pRsaKey,
  size_t salt_len,
  uint8_t* msg,
  uint32_t msg_len,
  uint8_t* sig,
  size_t sig_len
)
{
  const EVP_MD *digest_algo;
  unsigned char md[128];
  unsigned digest_len;
  EVP_MD_CTX *md_ctx;

  digest_algo = EVP_sha256();
  md_ctx = EVP_MD_CTX_new();
  EVP_DigestInit(md_ctx, digest_algo);
  EVP_DigestUpdate(md_ctx, msg, msg_len);
  EVP_DigestFinal(md_ctx, md, &digest_len);

  EVP_PKEY *pkey = NULL;
  pkey = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(pkey, pRsaKey);

  EVP_PKEY_CTX *pkey_ctx;
  pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);

  EVP_PKEY_verify_init(pkey_ctx);
  EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
  EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, salt_len);
  EVP_PKEY_CTX_set_signature_md(pkey_ctx, digest_algo);
  EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, digest_algo);

  int ret = EVP_PKEY_verify(pkey_ctx, sig, sig_len, md, digest_len);
  return ret;
}

void rsapss_sign_openssl(uint32_t modBits, uint8_t *sgnt, uint64_t *skey, RSA* privkey){
  uint32_t nbLen = (modBits - (uint32_t)1U) / (uint32_t)8U + (uint32_t)1U;
  size_t msg_len = 24;
  uint8_t msg[msg_len];
  memset(msg, 0U, msg_len * sizeof (msg[0U]));

  openssl_sign(privkey, 0U, msg, msg_len, sgnt, nbLen);
}
