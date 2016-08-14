#include <cstring>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "simple_server.h"
#include "crypto.h"

SimpleServer::SimpleServer(const char *N_str, const char *g_str, const char *k_str, const char *_I, const char *_P) {
  N = NULL;
  g = NULL;
  k = NULL;
  v = NULL;
  hmac = NULL;
  SHA256_CTX sha_ctx;

  if (N_str) BN_hex2bn(&N, N_str);
  if (g_str) BN_hex2bn(&g, g_str);
  if (k_str) BN_hex2bn(&k, k_str);

  if (_I) {
    I = new char[strlen(_I)+1];
    strcpy(I, _I);
  }
  if (_P) {
    P = new char[strlen(_P)+1];
    strcpy(P, _P);
  }

  // S
  // x = SHA256(salt|password)
  // v = g**x % n
  salt = arc4random();

  unsigned char xH[SHA256_HASH_LEN];

  SHA256_Init(&sha_ctx);
  SHA256_Update(&sha_ctx, &salt, sizeof salt);
  SHA256_Update(&sha_ctx, P, strlen(P));
  SHA256_Final(xH, &sha_ctx);
  
  BIGNUM *x = BN_new();
  BN_bin2bn(xH, SHA256_HASH_LEN, x);
  
  v = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  BN_mod_exp(v, g, x, N, ctx);

  if (x) BN_free(x);
  if (ctx) BN_CTX_free(ctx);
}

SimpleServer::~SimpleServer() {
  if (N) BN_free(N);
  if (g) BN_free(g);
  if (k) BN_free(k);
  if (v) BN_free(v);
  if (I) delete [] I;
  if (P) delete [] P;
  if (hmac) delete [] hmac;
}

void SimpleServer::handshake(const char *_I, BIGNUM *A, BIGNUM **B, BIGNUM **u, uint32_t *_salt) {
  if (I && _I && strcmp(I, _I) == 0) {
    BIGNUM *b = NULL;
    BIGNUM *vu = NULL;
    BIGNUM *Avu = NULL;
    BIGNUM *S = NULL;
    unsigned char K[SHA256_HASH_LEN];
    unsigned char *bn_bin = NULL;
    BN_CTX *ctx = NULL;
    SHA256_CTX sha_ctx;
    uint32_t md_len = 0;

    if (!N || !g || !k || !v || !P || !A)
      goto err;

    // S->C
    // salt, B = g**b % n, u = 128 bit random number
    if (!(b = BN_new()))
      goto err;
  
    if (!BN_rand_range(b, N))
      goto err;
  
    if (!(*B = BN_new()))
      goto err;

    if (!(ctx = BN_CTX_new()))
      goto err;
  
    if (!BN_mod_exp(*B, g, b, N, ctx))
      goto err;

    if (!(*u = BN_new()))
      goto err;

    if (!BN_rand(*u, 128, -1, 0))
      goto err;

    // S
    // S = (A * v ** u)**b % n
    // K = SHA256(S)
    if (!(vu = BN_new()))
      goto err;
    
    if (!BN_mod_exp(vu, v, *u, N, ctx))
      goto err;

    if (!(Avu = BN_new()))
      goto err;

    if (!BN_mul(Avu, A, vu, ctx))
      goto err;

    if (!(S = BN_new()))
      goto err;

    if (!BN_mod_exp(S, Avu, b, N, ctx))
      goto err;

    bn_bin = new unsigned char[BN_num_bytes(S)];
    BN_bn2bin(S, bn_bin);

    if (!SHA256_Init(&sha_ctx))
      goto err;

    if (!SHA256_Update(&sha_ctx, bn_bin, BN_num_bytes(S)))
      goto err;
  
    if (!SHA256_Final(K, &sha_ctx))
      goto err;

    hmac = new unsigned char[SHA256_HASH_LEN];
    hmac = HMAC(EVP_sha256(), K, SHA256_HASH_LEN, (unsigned char *)(&salt), sizeof salt, hmac, &md_len);

    *_salt = salt;

  err:
    if (b) BN_free(b);
    if (S) BN_free(S);
    if (vu) BN_free(vu);
    if (Avu) BN_free(Avu);
    if (ctx) BN_CTX_free(ctx);
    if (bn_bin) delete [] bn_bin;
  }
}

bool SimpleServer::validate_hmac(const unsigned char *_hmac) {
  // S->C
  // Send "OK" if HMAC-SHA256(K, salt) validates
  bool ret = false;
  if (hmac) {
    ret = (CRYPTO_memcmp(hmac, _hmac, SHA256_HASH_LEN) == 0);
    delete [] hmac;
    hmac = NULL;
  }
  return ret;
}
