#include <cstring>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "simple_client.h"
#include "crypto.h"

SimpleClient::SimpleClient(const char *N_str, const char *g_str, const char *k_str, const char *_I, const char *_P) {
  N = NULL;
  g = NULL;
  k = NULL;
  A = NULL;
  a = NULL;

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
}

SimpleClient::~SimpleClient() {
  if (N) BN_free(N);
  if (g) BN_free(g);
  if (k) BN_free(k);
  if (A) BN_free(A);
  if (a) BN_free(a);
  if (I) delete [] I;
  if (P) delete [] P;
}

BIGNUM *SimpleClient::generate_A() {
  BN_CTX *ctx = NULL;
  
  if (!(a = BN_new()))
    goto err;
  
  if (!BN_rand_range(a, N))
  goto err;

  if (!(A = BN_new()))
    goto err;

  if (!(ctx = BN_CTX_new()))
    goto err;
  
  if (!BN_mod_exp(A, g, a, N, ctx))
    goto err;
  
 err:
  if (ctx) BN_CTX_free(ctx);

  return A;
}

char *SimpleClient::get_I() {
  return I;
}

unsigned char *SimpleClient::handshake(uint32_t salt, BIGNUM *B, BIGNUM *u) {
  BIGNUM *S = NULL;
  BIGNUM *x = NULL;
  BIGNUM *ux = NULL;
  BIGNUM *aux = NULL;
  unsigned char xH[SHA256_HASH_LEN];
  unsigned char K[SHA256_HASH_LEN];
  unsigned char *bn_bin = NULL;
  unsigned char *hmac = NULL;
  BN_CTX *ctx = NULL;
  SHA256_CTX sha_ctx;
  uint32_t md_len = 0;

  if (!N || !g || !k || !A || !a || !I || !P || !B || !u)
    goto err;

  // C
  // x = SHA256(salt|password)
  // S = B**(a + ux) % n
  // K = SHA256(S)
  if (!SHA256_Init(&sha_ctx))
    goto err;
  
  if (!SHA256_Update(&sha_ctx, &salt, sizeof salt))
    goto err;

  if (!SHA256_Update(&sha_ctx, P, strlen(P)))
    goto err;
  
  if (!SHA256_Final(xH, &sha_ctx))
    goto err;

  if (!(x = BN_new()))
    goto err;

  if (!BN_bin2bn(xH, SHA256_HASH_LEN, x))
    goto err;

  if (!(ux = BN_new()))
    goto err;

  if (!(ctx = BN_CTX_new()))
    goto err;

  if (!BN_mul(ux, u, x, ctx))
    goto err;

  if (!(aux = BN_new()))
    goto err;

  if (!BN_add(aux, a, ux))
    goto err;

  if (!(S = BN_new()))
    goto err;

  if (!BN_mod_exp(S, B, aux, N, ctx))
    goto err;

  bn_bin = new unsigned char[BN_num_bytes(S)];
  BN_bn2bin(S, bn_bin);

  if (!SHA256_Init(&sha_ctx))
    goto err;

  if (!SHA256_Update(&sha_ctx, bn_bin, BN_num_bytes(S)))
    goto err;
  
  if (!SHA256_Final(K, &sha_ctx))
    goto err;

  // C->S
  // Send HMAC-SHA256(K, salt)
  hmac = new unsigned char[SHA256_HASH_LEN];
  hmac = HMAC(EVP_sha256(), K, SHA256_HASH_LEN, (unsigned char *)(&salt), sizeof salt, hmac, &md_len);

 err:
  if (S) BN_free(S);
  if (x) BN_free(x);
  if (ux) BN_free(ux);
  if (aux) BN_free(aux);
  if (a) {
    BN_free(a);
    a = NULL;
  }
  if (A) {
    BN_free(A);
    A = NULL;
  }
  if (ctx) BN_CTX_free(ctx);
  if (bn_bin) delete [] bn_bin;

  return hmac;
}
