#include <iostream>
#include <sstream>

#include <openssl/bn.h>
#include <openssl/sha.h>

#include "crypto.h"

using namespace std;

BIGNUM *find_k(const unsigned char *hash1, const int hash1_len, const unsigned char *hash2, const int hash2_len, const BIGNUM *s1, const BIGNUM *s2, BN_CTX *ctx) {
  //     (m1 - m2)
  // k = --------- mod q
  //     (s1 - s2)

  const char *q_str = "f4f47f05794b256174bba6e9b396a7707e563c5b";

  BIGNUM *q = NULL;
  BIGNUM *k = NULL;
  BIGNUM *m1 = NULL;
  BIGNUM *m2 = NULL;
  BIGNUM *m1m2 = NULL;
  BIGNUM *s1s2 = NULL;

  BN_CTX_start(ctx);

  if (!BN_hex2bn(&q, q_str))
    goto err;

  if (!(m1 = BN_CTX_get(ctx)))
    goto err;

  if (!BN_bin2bn(hash1, hash1_len, m1))
    goto err;

  if (!(m2 = BN_CTX_get(ctx)))
    goto err;

  if (!BN_bin2bn(hash2, hash2_len, m2))
    goto err;

  if (!(m1m2 = BN_CTX_get(ctx)))
    goto err;

  if(!BN_mod_sub(m1m2, m1, m2, q, ctx))
    goto err;

  if (!(s1s2 = BN_CTX_get(ctx)))
    goto err;

  if(!BN_mod_sub(s1s2, s1, s2, q, ctx))
    goto err;

  if (!(k = modinv(s1s2, q, ctx)))
    goto err;

  if (!BN_mod_mul(k, m1m2, k, q, ctx))
    goto err;

 err:
  if (q) BN_free (q);
  BN_CTX_end(ctx);

  return k;
}

int main() {
  // Messages with a repeated k will have the same r.  44.txt contains 3 such messages
  
  const char *msg1 = "Listen for me, you better listen for me now. ";
  const char *r1_str = "1105520928110492191417703162650245113664610474875";
  const char *s1_str = "1267396447369736888040262262183731677867615804316";
  
  unsigned char hash1[SHA1_HASH_LEN];
  SHA1((unsigned char *)msg1, strlen(msg1), hash1);

  DSASig *sig1 = new DSASig;
  BN_dec2bn(&sig1->r, r1_str);
  BN_dec2bn(&sig1->s, s1_str);
  
  const char *msg2 = "Pure black people mon is all I mon know. ";
  const char *r2_str = "1105520928110492191417703162650245113664610474875";
  const char *s2_str = "1021643638653719618255840562522049391608552714967";
  
  unsigned char hash2[SHA1_HASH_LEN];
  SHA1((unsigned char *)msg2, strlen(msg2), hash2);

  DSASig *sig2 = new DSASig;
  BN_dec2bn(&sig2->r, r2_str);
  BN_dec2bn(&sig2->s, s2_str);
  
  const char *y_str = "2d026f4bf30195ede3a088da85e398ef869611d0f68f07"
    "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"
    "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"
    "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"
    "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"
    "2971c3de5084cce04a2e147821";

  BIGNUM *y = NULL;
  BN_hex2bn(&y, y_str);

  if (DSA_verify(y, sig1, hash1, SHA1_HASH_LEN)) {
    cout << "Signature valid" << endl;
  } else {
    cout << "Signature invalid" << endl;
  }

  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *k = find_k(hash1, SHA1_HASH_LEN, hash2, SHA1_HASH_LEN, sig1->s, sig2->s, ctx);

  BIGNUM *x = find_x(sig1, k, hash1, SHA1_HASH_LEN, ctx);

  cout << "k: " << BN_bn2hex(k) << " x: " << BN_bn2hex(x) << endl;
  
  if (y) BN_free(y);
  if (k) BN_free(k);
  if (x) BN_free(x);
  if (ctx) BN_CTX_free(ctx);
  if (sig1) delete sig1;
  if (sig2) delete sig2;
  
  return 0;
}
