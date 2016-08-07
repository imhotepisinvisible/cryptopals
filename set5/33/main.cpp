#include <iostream>
#include <cmath>

#include <openssl/bn.h>
#include <openssl/sha.h>

#include "crypto.h"
#include "conversions.h"

using namespace std;

uint32_t power(uint32_t base, uint32_t exp, uint32_t mod) {
  uint32_t t;
  if(exp == 1) {
    return base;
  }
 
  t = power(base, exp/2, mod);
 
  if (exp % 2 == 0) {
    return (t * t) % mod;
  } else {
    return (((t * t) % mod) * base) % mod;
  }
}

unsigned char *easy_dh() {
  unsigned char *hash = NULL;
  // Set a variable "p" to 37 and "g" to 5.
  uint32_t p = 37;
  uint32_t g = 5;

  // Generate "a", a random number mod 37.
  uint32_t a = arc4random_uniform(p);

  // Now generate "A", which is "g" raised to the "a" power mode 37 --- A = (g**a) % p.
  uint32_t A = power(g, a, p);

  // Do the same for "b" and "B".
  uint32_t b = arc4random_uniform(p);
  uint32_t B = power(g, b, p);

  // "A" and "B" are public keys. Generate a session key with them; set "s" to "B" raised to the "a" power mod 37 --- s = (B**a) % p.
  uint32_t s1 = power(B, a, p);

  // Do the same with A**b, check that you come up with the same "s".
  uint32_t s2 = power(A, b, p);

  if (s1 != s2) {
    cout << "Err" << endl;
  } else {
    // To turn "s" into a key, you can just hash it to create 128 bits of key material (or SHA256 it to create a key for encrypting and a key for a MAC).
    hash = new unsigned char[SHA1_HASH_LEN];
    SHA_CTX sha_ctx;
    SHA1_Init(&sha_ctx);
    SHA1_Update(&sha_ctx, &s1, sizeof(s1));
    SHA1_Final(hash, &sha_ctx);
  }
  
  return hash;
}

unsigned char *bignum_dh() {
  unsigned char *hash = NULL;
  unsigned char *bn_bin = NULL;
  const char *p_str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
    "fffffffffffff";
  const char *g_str = "2";
  BIGNUM *p = NULL;
  BIGNUM *g = NULL;
  BIGNUM *a = NULL;
  BIGNUM *A = NULL;
  BIGNUM *b = NULL;
  BIGNUM *B = NULL;
  BIGNUM *s1 = NULL;
  BIGNUM *s2 = NULL;
  BN_CTX *ctx = NULL;
  SHA_CTX sha_ctx;

  if (!BN_hex2bn(&p, p_str))
    goto err;
 
  if (!BN_hex2bn(&g, g_str))
    goto err;

  if (!(a = BN_new()))
    goto err;
  
  if (!BN_rand_range(a, p))
    goto err;
  
  if (!(A = BN_new()))
    goto err;
  
  if (!(ctx = BN_CTX_new()))
    goto err;
  
  if (!BN_mod_exp(A, g, a, p, ctx))
    goto err;

  if (!(b = BN_new()))
    goto err;
  
  if (!BN_rand_range(b, p))
    goto err;
  
  if (!(B = BN_new()))
    goto err;
  
  if (!BN_mod_exp(B, g, b, p, ctx))
    goto err;

  if (!(s1 = BN_new()))
    goto err;
  
  if (!BN_mod_exp(s1, B, a, p, ctx))
    goto err;

  if (!(s2 = BN_new()))
    goto err;
  
  if (!BN_mod_exp(s2, B, a, p, ctx))
    goto err;

  if (BN_cmp(s1, s2) != 0)
    goto err;

  hash = new unsigned char[SHA1_HASH_LEN];
  bn_bin = new unsigned char[BN_num_bytes(s1)];
  BN_bn2bin(s1, bn_bin);

  if (!SHA1_Init(&sha_ctx))
    goto err;
  
  if (!SHA1_Update(&sha_ctx, bn_bin, BN_num_bytes(s1)))
    goto err;
  
  if (!SHA1_Final(hash, &sha_ctx))
    goto err;

 err:
  if (p) BN_free(p);
  if (g) BN_free(g);
  if (a) BN_free(a);
  if (A) BN_free(A);
  if (b) BN_free(b);
  if (B) BN_free(B);
  if (s1) BN_free(s1);
  if (s2) BN_free(s2);
  if (bn_bin) delete [] bn_bin;
  if (ctx) BN_CTX_free(ctx);

  return hash;
}

int main() {
  init_openssl();
  
  char hashStr[SHA1_HASH_LEN*2+1];

  unsigned char *hash = easy_dh();
  if (hash) {
    bytesToHex(hashStr, hash, SHA1_HASH_LEN);
    cout << hashStr << endl;
    delete [] hash;
  }

  unsigned char *hash2 = bignum_dh();
  if (hash2) {
    bytesToHex(hashStr, hash2, SHA1_HASH_LEN);
    cout << hashStr << endl;
    delete [] hash2;
  }

  close_openssl();

  return 0;
}
