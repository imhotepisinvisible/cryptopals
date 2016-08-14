#include <iostream>
#include <fstream>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "simple_client.h"
#include "simple_server.h"

#include "crypto.h"

using namespace std;

bool attack_hmac(const char *password, const uint32_t salt, const BIGNUM *A, const BIGNUM *B, const BIGNUM *N, const unsigned char *hmac, BN_CTX *ctx) {
  bool ret = false;

  BIGNUM *x = NULL;
  BIGNUM *twox = NULL;
  BIGNUM *S = NULL;
  unsigned char xH[SHA256_HASH_LEN];
  unsigned char K[SHA256_HASH_LEN];
  unsigned char *guessed_hmac = NULL;
  unsigned char *bn_bin = NULL;
  uint32_t md_len = 0;
  SHA256_CTX sha_ctx;

  BN_CTX_start(ctx);
  
  if (!SHA256_Init(&sha_ctx))
    goto err;
  
  if (!SHA256_Update(&sha_ctx, &salt, sizeof salt))
    goto err;
  
  if (!SHA256_Update(&sha_ctx, password, strlen(password)))
    goto err;
  
  if (!SHA256_Final(xH, &sha_ctx))
    goto err;
  
  if (!(x = BN_CTX_get(ctx)))
    goto err;

  if (!BN_bin2bn(xH, SHA256_HASH_LEN, x))
    goto err;

  if (!(twox = BN_CTX_get(ctx)))
    goto err;
      
  if (!BN_mod_exp(twox, B, x, N, ctx))
    goto err;

  if (!(S = BN_CTX_get(ctx)))
    goto err;

  if (!BN_mod_mul(S, A, twox, N, ctx))
    goto err;

  bn_bin = new unsigned char[BN_num_bytes(S)];
  if (!BN_bn2bin(S, bn_bin))
    goto err;

  if (!SHA256_Init(&sha_ctx))
    goto err;
  
  if (!SHA256_Update(&sha_ctx, bn_bin, BN_num_bytes(S)))
    goto err;
  
  if (!SHA256_Final(K, &sha_ctx))
    goto err;
  
  guessed_hmac = new unsigned char[SHA256_HASH_LEN];
  guessed_hmac = HMAC(EVP_sha256(), K, SHA256_HASH_LEN, (unsigned char *)(&salt), sizeof salt, guessed_hmac, &md_len);
  
  ret = (CRYPTO_memcmp(hmac, guessed_hmac, SHA256_HASH_LEN) == 0);

 err:
  BN_CTX_end(ctx);
  if (bn_bin) delete [] bn_bin;
  if (guessed_hmac) delete [] guessed_hmac;

  return ret;
}

int main() {
  init_openssl();

  // C & S
  // Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
  const char *N_str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
    "fffffffffffff";
  const char *g_str = "2";
  const char *k_str = "3";
  const char *username = "admin@example.com";
  
  char password[64];
  ifstream in_file("/usr/share/dict/words");
  int line = arc4random_uniform(235886)+1; //length of /usr/share/dict/words
  for (int i = 0; i < line; i++) {
    in_file.getline(password, 64);
  }

  SimpleServer server(N_str, g_str, k_str, username, password);

  SimpleClient client(N_str, g_str, k_str, username, password);

  BIGNUM *_A = client.generate_A();
  BIGNUM *A = BN_dup(_A);
  char *I = client.get_I();
  BIGNUM *B = NULL;
  BIGNUM *u = NULL;
  uint32_t salt = 0;
  server.handshake(I, A, &B, &u, &salt);

  // Pose as the server and use arbitrary values for b, B, u, and salt.
  // Let b = 1 (thus B = g = 2), u = 1, salt = 0
  uint32_t bad_salt = 0;
  BIGNUM *bad_B = NULL;
  BN_hex2bn(&bad_B, "2");
  BIGNUM *bad_u = NULL;
  BN_hex2bn(&bad_u, "1");

  unsigned char *hmac = client.handshake(bad_salt, bad_B, bad_u);

  // Now, from the client's perspective
  // S = B**(a + ux) % n
  //   = 2**(a + x) % n
  //   = (2**a * 2**x) % n
  //   = (A * 2**x) % n
  // Since x = SHA256(salt|password) and we know salt,
  // We can generate our own x, then get S, K and hmac
  // If hmac matches, we got the password
  ifstream dictionary("/usr/share/dict/words");
  char guessed_password[64];
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *N = NULL;
  BN_hex2bn(&N, N_str);
  while (dictionary.getline(guessed_password, 64)) {
    if (attack_hmac(guessed_password, bad_salt, A, bad_B, N, hmac, ctx)) {
      cout << "Password found: " << guessed_password << endl;
      break;
    }
  }

  if (A) BN_free(A);
  if (B) BN_free(B);
  if (bad_B) BN_free(bad_B);
  if (u) BN_free(u);
  if (bad_u) BN_free(bad_u);
  if (N) BN_free(N);
  if (ctx) BN_CTX_free(ctx);
  if (hmac) delete [] hmac;
  
  close_openssl();

  return 0;
}
