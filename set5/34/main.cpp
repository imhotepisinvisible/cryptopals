#include <iostream>

#include <openssl/sha.h>

#include "crypto.h"
#include "conversions.h"
#include "person.h"

using namespace std;

int main() {
  init_openssl();
  
  const char *p_str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
    "fffffffffffff";
  const char *g_str = "2";
  const char *msg = "Hello, world!";

  unsigned char a_iv[16];
  unsigned char b_iv[16];
  unsigned char a_ciphertext[128];
  char b_plaintext[128];
  unsigned char b_ciphertext[128];
  char a_plaintext[128];

  Person a(p_str, g_str);

  // A->M
  // Send "p", "g", "A"
  BIGNUM *p = a.get_p();
  BIGNUM *g = a.get_g();
  BIGNUM *A = a.get_pub();

  // M->B
  // Send "p", "g", "p"
  // Normal operation:
  // Person b(p, g, A);
  Person b(p, g, p);

  // B->M
  // Send "B"
  BIGNUM *B = b.get_pub();

  // M->A
  // Send "p"
  // Normal operation:
  // a.set_recipient_pub(B);
  a.set_recipient_pub(p);

  // A->M
  // Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
  int a_ciphertext_len = a.encrypt(msg, a_iv, a_ciphertext);

  // M should be able to decrypt here...
  // We hash 0 because p^x mod p = 0...
  unsigned char m_hash[SHA1_HASH_LEN];
  SHA_CTX sha_ctx;
  SHA1_Init(&sha_ctx);
  SHA1_Update(&sha_ctx, 0, 0);
  SHA1_Final(m_hash, &sha_ctx);
  
  unsigned char m_plaintext[128];
  int m_plaintext_len = decryptCbc(a_ciphertext, a_ciphertext_len, m_hash, a_iv, m_plaintext);
  m_plaintext[m_plaintext_len] = '\0';
  cout << "M decrypts: " << m_plaintext << endl;

  // M->B
  // Relay that to B
  b.decrypt(a_ciphertext, a_ciphertext_len, a_iv, b_plaintext);

  cout << "B receives: " << b_plaintext << endl;

  // B->M
  // Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
  int b_ciphertext_len = b.encrypt(b_plaintext, b_iv, b_ciphertext);

  // M->A
  // Relay that to A
  a.decrypt(b_ciphertext, b_ciphertext_len, b_iv, a_plaintext);

  cout << "A receives: " << a_plaintext << endl;

  close_openssl();

  return 0;
}
