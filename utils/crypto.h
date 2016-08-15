#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/bn.h>

extern const uint8_t SHA1_HASH_LEN;
extern const uint8_t MD4_HASH_LEN;
extern const uint8_t SHA256_HASH_LEN;

struct RSAKey {
  BIGNUM *e_or_d;
  BIGNUM *n;
  RSAKey(const BIGNUM *_e_or_d, const BIGNUM *_n) {
    e_or_d = BN_dup(_e_or_d);
    n = BN_dup(_n);
  }
  ~RSAKey() {
    if (e_or_d) BN_free(e_or_d);
    if (n) BN_free(n);
  }
};

int encryptEcb(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext, bool disablePadding);

int decryptEcb(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext, bool disablePadding);

int encryptCbc(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);

int decryptCbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

int decryptCtr(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *nonce, unsigned char *plaintext);

int encryptCtr(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *nonce, unsigned char *ciphertext);

bool generate_secret_prefix_mac(const unsigned char *key, const int key_len, const char *message, unsigned char *mac);

bool authenticate_secret_prefix_mac(const unsigned char *key, const int key_len, const char *message, const unsigned char *mac);

bool authenticate_secret_prefix_mac(const unsigned char *key, const int key_len, const unsigned char *message, const int message_len, const unsigned char *mac);

bool generate_secret_prefix_mac_md4(const unsigned char *key, const int key_len, const char *message, unsigned char *mac);

bool authenticate_secret_prefix_mac_md4(const unsigned char *key, const int key_len, const char *message, const unsigned char *mac);

bool authenticate_secret_prefix_mac_md4(const unsigned char *key, const int key_len, const unsigned char *message, const int message_len, const unsigned char *mac);

BIGNUM *modinv(const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

void RSA_genkeys(RSAKey **priv, RSAKey **pub, const int keylen);

BIGNUM *RSA_encrypt(const RSAKey *pub, const char *plaintext);

char *RSA_decrypt(const RSAKey *priv, const BIGNUM *ciphertext);

void init_openssl();

void close_openssl();

#endif
