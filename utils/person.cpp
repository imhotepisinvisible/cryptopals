#include <cstring>

#include <openssl/sha.h>

#include "person.h"
#include "crypto.h"

Person::Person(const char *p_str, const char *g_str) {
  p = NULL;
  g = NULL;
  B = NULL;
  hash = NULL;
  BN_hex2bn(&p, p_str);
  BN_hex2bn(&g, g_str);
  set_keys();
}

Person::Person(BIGNUM *_p, BIGNUM *_g, BIGNUM *_B) {
  p = BN_dup(_p);
  g = BN_dup(_g);
  B = BN_dup(_B);
  set_keys();
  calculate_hash();
}

Person::~Person() {
  if (p) BN_free(p);
  if (g) BN_free(g);
  if (a) BN_free(a);
  if (A) BN_free(A);
  if (B) BN_free(B);
  if (hash) delete [] hash;
}

void Person::set_keys() {
  a = BN_new();
  BN_rand_range(a, p);
  A = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  BN_mod_exp(A, g, a, p, ctx);

  if (ctx) BN_CTX_free(ctx);
}

BIGNUM *Person::get_pub() {
  return A;
}

BIGNUM *Person::get_p() {
  return p;
}

BIGNUM *Person::get_g() {
  return g;
}

void Person::set_g(const char *g_str) {
  if (g) BN_free(g);
  g = NULL;
  BN_hex2bn(&g, g_str);

  // Recalculate keys
  if (a) BN_free(a);
  if (A) BN_free(A);
  set_keys();
}

void Person::set_recipient_pub(BIGNUM *_B) {
  B = BN_dup(_B);
  calculate_hash();
}

unsigned char *Person::calculate_hash() {
  unsigned char *bn_bin = NULL;
  BIGNUM *s = NULL;
  BN_CTX *ctx = NULL;
  SHA_CTX sha_ctx;

  if (!B)
    goto err;
  
  if (!(s = BN_new()))
    goto err;

  if (!(ctx = BN_CTX_new()))
    goto err;
  
  if (!BN_mod_exp(s, B, a, p, ctx))
    goto err;

  hash = new unsigned char[SHA1_HASH_LEN];
  bn_bin = new unsigned char[BN_num_bytes(s)];
  BN_bn2bin(s, bn_bin);

  if (!SHA1_Init(&sha_ctx))
    goto err;
  
  if (!SHA1_Update(&sha_ctx, bn_bin, BN_num_bytes(s)))
    goto err;
  
  if (!SHA1_Final(hash, &sha_ctx))
    goto err;

 err:
  if (s) BN_free(s);
  if (bn_bin) delete [] bn_bin;
  if (ctx) BN_CTX_free(ctx);

  return hash;
}

int Person::encrypt(const char *plaintext, unsigned char *iv, unsigned char *ciphertext) {
  int ciphertext_len = 0;
  if (ciphertext && iv && plaintext && hash) {
    arc4random_buf(iv, 16);
    ciphertext_len = encryptCbc((unsigned char*)plaintext, strlen(plaintext), hash, iv, ciphertext);
  }

  return ciphertext_len;
}

int Person::decrypt(unsigned char *ciphertext, const int ciphertext_len, unsigned char *iv, char *plaintext) {
  int plaintext_len = 0;
  if (ciphertext && iv && plaintext && B) {
    plaintext_len = decryptCbc(ciphertext, ciphertext_len, hash, iv, (unsigned char *)plaintext);
    plaintext[plaintext_len] = '\0';
  }

  return plaintext_len;
}
