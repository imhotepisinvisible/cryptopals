#include <iostream>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "client.h"
#include "server.h"

#include "crypto.h"

using namespace std;

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
  const char *password = "password";

  // S
  // Generate salt as random integer
  // Generate string xH=SHA256(salt|password)
  // Convert xH to integer x somehow (put 0x on hexdigest)
  // Generate v=g**x % N
  // Save everything but x, xH
  Server server(N_str, g_str, k_str, username, password);

  Client client(N_str, g_str, k_str, username, password);

  // C->S
  // Send I, A=g**a % N (a la Diffie Hellman)
  // NOTE: A/a are ephemeral
  // S, C
  // Compute string uH = SHA256(A|B), u = integer of uH
  // S
  // Generate S = (A * v**u) ** b % N
  // Generate K = SHA256(S)
  char *I = client.get_I();
  BIGNUM *B = NULL;
  uint32_t salt = 0;

  // Send 0 as A value
  BIGNUM *bad_A = NULL;
  BN_hex2bn(&bad_A, "0");
  server.handshake(I, bad_A, &B, &salt);

  // Having sent 0, we know that S = (0 * v**u) ** b % N = 0
  // So K = SHA256(0)
  unsigned char K[SHA256_HASH_LEN];
  uint32_t md_len = 0;
  SHA256_CTX sha_ctx;
  SHA256_Init(&sha_ctx);
  SHA256_Update(&sha_ctx, 0, 0);
  SHA256_Final(K, &sha_ctx);
  
  unsigned char *hmac = new unsigned char[SHA256_HASH_LEN];
  hmac = HMAC(EVP_sha256(), K, SHA256_HASH_LEN, (unsigned char *)(&salt), sizeof salt, hmac, &md_len);
  
  // C->S
  // Send HMAC-SHA256(K, salt)
  // S->C
  // Send "OK" if HMAC-SHA256(K, salt) validates
  if (server.validate_hmac(hmac)) {
    cout << "User authenticated" << endl;
  } else {
    cout << "User not authenticated" << endl;
  }

  // Now send a multiple of N as A value
  if (bad_A) {
    BN_free(bad_A);
    bad_A = NULL;
  }
  BN_hex2bn(&bad_A, N_str);
  server.handshake(I, bad_A, &B, &salt);

  // We know that S = (N * v**u) ** b % N = 0
  // So K = SHA256(0) (which we have already)
  
  // C->S
  // Send HMAC-SHA256(K, salt)
  // S->C
  // Send "OK" if HMAC-SHA256(K, salt) validates
  if (server.validate_hmac(hmac)) {
    cout << "User authenticated" << endl;
  } else {
    cout << "User not authenticated" << endl;
  }

  if (B) BN_free(B);
  if (bad_A) BN_free(bad_A);
  if (hmac) delete [] hmac;
  
  close_openssl();

  return 0;
}
