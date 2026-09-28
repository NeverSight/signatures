/* A program that pulls a slice of libcrypto into a static link: digests,
   HMAC, AES-GCM, big numbers and the random number generator. */
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  unsigned char digest[EVP_MAX_MD_SIZE], mac[EVP_MAX_MD_SIZE], key[32], iv[12];
  unsigned int length = 0, mac_length = 0;
  const char *text = argc > 1 ? argv[1] : "probe";
  EVP_Digest(text, strlen(text), digest, &length, EVP_sha256(), NULL);
  HMAC(EVP_sha512(), text, (int)strlen(text), (const unsigned char *)text,
       strlen(text), mac, &mac_length);
  if (RAND_bytes(key, sizeof key) != 1 || RAND_bytes(iv, sizeof iv) != 1)
    ERR_print_errors_fp(stderr);
  EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
  unsigned char sealed[256], tag[16];
  int out = 0, final = 0;
  EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_EncryptUpdate(context, sealed, &out, (const unsigned char *)text, (int)strlen(text));
  EVP_EncryptFinal_ex(context, sealed + out, &final);
  EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, sizeof tag, tag);
  EVP_CIPHER_CTX_free(context);
  BIGNUM *a = BN_new(), *b = BN_new(), *r = BN_new();
  BN_CTX *bn = BN_CTX_new();
  BN_set_word(a, 65537);
  BN_dec2bn(&b, "123456789012345678901234567890");
  BN_mod_exp(r, b, a, b, bn);
  char *decimal = BN_bn2dec(r);
  printf("%u %u %d %s %02x\n", length, mac_length, out + final, decimal, tag[0]);
  OPENSSL_free(decimal);
  BN_free(a); BN_free(b); BN_free(r); BN_CTX_free(bn);
  return 0;
}
