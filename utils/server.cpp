#include <cstring>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "server.h"
#include "crypto.h"

Server::Server(const char *N_str, const char *g_str, const char *k_str, const char *_I, const char *_P) {
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
  // Generate salt as random integer
  // Generate string xH=SHA256(salt|password)
  // Convert xH to integer x somehow (put 0x on hexdigest)
  // Generate v=g**x % N
  // Save everything but x, xH
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

Server::~Server() {
  if (N) BN_free(N);
  if (g) BN_free(g);
  if (k) BN_free(k);
  if (v) BN_free(v);
  if (I) delete [] I;
  if (P) delete [] P;
  if (hmac) delete [] hmac;
}

void Server::handshake(const char *_I, BIGNUM *A, BIGNUM **B, uint32_t *_salt) {
  if (I && _I && strcmp(I, _I) == 0) {
    BIGNUM *b = NULL;
    BIGNUM *kv = NULL;
    BIGNUM *u = NULL;
    BIGNUM *vu = NULL;
    BIGNUM *Avu = NULL;
    BIGNUM *S = NULL;
    unsigned char uH[SHA256_HASH_LEN];
    unsigned char K[SHA256_HASH_LEN];
    unsigned char *bn_bin1 = NULL;
    unsigned char *bn_bin2 = NULL;
    unsigned char *bn_bin3 = NULL;
    BN_CTX *ctx = NULL;
    SHA256_CTX sha_ctx;
    uint32_t md_len = 0;

    if (!N || !g || !k || !v || !P || !A)
      goto err;

    // S->C
    // Send salt, B=kv + g**b % N
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

    if (!(kv = BN_new()))
      goto err;

    if (!BN_mul(kv, k, v, ctx))
      goto err;

    if (!BN_add(*B, kv, *B))
      goto err;

    // S, C
    // Compute string uH = SHA256(A|B), u = integer of uH
    bn_bin1 = new unsigned char[BN_num_bytes(A)];
    BN_bn2bin(A, bn_bin1);
  
    bn_bin2 = new unsigned char[BN_num_bytes(*B)];
    BN_bn2bin(*B, bn_bin2);

    if (!SHA256_Init(&sha_ctx))
      goto err;

    if (!SHA256_Update(&sha_ctx, bn_bin1, BN_num_bytes(A)))
      goto err;
  
    if (!SHA256_Update(&sha_ctx, bn_bin2, BN_num_bytes(*B)))
      goto err;
  
    if (!SHA256_Final(uH, &sha_ctx))
      goto err;

    if (!(u = BN_new()))
      goto err;
  
    if (!BN_bin2bn(uH, SHA256_HASH_LEN, u))
      goto err;

    // S
    // Generate S = (A * v**u) ** b % N
    // Generate K = SHA256(S)
    if (!(vu = BN_new()))
      goto err;
    
    if (!BN_mod_exp(vu, v, u, N, ctx))
      goto err;

    if (!(Avu = BN_new()))
      goto err;

    if (!BN_mul(Avu, A, vu, ctx))
      goto err;

    if (!(S = BN_new()))
      goto err;

    if (!BN_mod_exp(S, Avu, b, N, ctx))
      goto err;

    bn_bin3 = new unsigned char[BN_num_bytes(S)];
    BN_bn2bin(S, bn_bin3);

    if (!SHA256_Init(&sha_ctx))
      goto err;

    if (!SHA256_Update(&sha_ctx, bn_bin3, BN_num_bytes(S)))
      goto err;
  
    if (!SHA256_Final(K, &sha_ctx))
      goto err;

    hmac = new unsigned char[SHA256_HASH_LEN];
    hmac = HMAC(EVP_sha256(), K, SHA256_HASH_LEN, (unsigned char *)(&salt), sizeof salt, hmac, &md_len);

    *_salt = salt;

  err:
    if (b) BN_free(b);
    if (kv) BN_free(kv);
    if (u) BN_free(u);
    if (S) BN_free(S);
    if (vu) BN_free(vu);
    if (Avu) BN_free(Avu);
    if (ctx) BN_CTX_free(ctx);
    if (bn_bin1) delete [] bn_bin1;
    if (bn_bin2) delete [] bn_bin2;
    if (bn_bin3) delete [] bn_bin3;
  }
}

bool Server::validate_hmac(const unsigned char *_hmac) {
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
