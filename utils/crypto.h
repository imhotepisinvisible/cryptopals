#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/bn.h>

extern const uint8_t SHA1_HASH_LEN;
extern const uint8_t MD4_HASH_LEN;
extern const uint8_t SHA256_HASH_LEN;
extern const uint16_t MD_MAGIC;
extern const uint32_t MD2_MAGIC;

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

struct DSASig {
  BIGNUM *r;
  BIGNUM *s;
  DSASig() {
    r = BN_new();
    s = BN_new();
  }
  ~DSASig() {
    if (r) BN_free(r);
    if (s) BN_free(s);
  }
};

int encryptEcb(const unsigned char *plaintext, const int plaintext_len, const unsigned char *key, unsigned char *ciphertext, bool disablePadding);

int decryptEcb(const unsigned char *ciphertext, const int ciphertext_len, const unsigned char *key, unsigned char *plaintext, bool disablePadding);

int encryptCbc(const unsigned char *plaintext, const int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext);

int decryptCbc(const unsigned char *ciphertext, const int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext);

int decryptCtr(const unsigned char *ciphertext, const int ciphertext_len, const unsigned char *key, const unsigned char *nonce, unsigned char *plaintext);

int encryptCtr(const unsigned char *plaintext, const int plaintext_len, const unsigned char *key, const unsigned char *nonce, unsigned char *ciphertext);

bool generate_secret_prefix_mac(const unsigned char *key, const int key_len, const char *message, unsigned char *mac);

bool authenticate_secret_prefix_mac(const unsigned char *key, const int key_len, const char *message, const unsigned char *mac);

bool authenticate_secret_prefix_mac(const unsigned char *key, const int key_len, const unsigned char *message, const int message_len, const unsigned char *mac);

bool generate_secret_prefix_mac_md4(const unsigned char *key, const int key_len, const char *message, unsigned char *mac);

bool authenticate_secret_prefix_mac_md4(const unsigned char *key, const int key_len, const char *message, const unsigned char *mac);

bool authenticate_secret_prefix_mac_md4(const unsigned char *key, const int key_len, const unsigned char *message, const int message_len, const unsigned char *mac);

BIGNUM *modinv(const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

void RSA_genkeys(RSAKey **priv, RSAKey **pub, const int keylen);

BIGNUM *RSA_encrypt(const RSAKey *pub, const char *plaintext);

BIGNUM *RSA_encrypt(const RSAKey *pub, const unsigned char *plaintext, const int plaintext_len);

BIGNUM *RSA_encrypt(const RSAKey *pub, const BIGNUM *m);

char *RSA_decrypt(const RSAKey *priv, const BIGNUM *ciphertext);

BIGNUM *RSA_decrypt_toBN(const RSAKey *priv, const BIGNUM *ciphertext);

BIGNUM *RSA_sign(const RSAKey *priv, const unsigned char *hash, const int hash_len);

bool RSA_verify(const RSAKey *pub, const BIGNUM *sig, const unsigned char *hash, const int hash_len);

BIGNUM *nearest_cuberoot(BIGNUM *in, BN_CTX *ctx);

void DSA_genkeys(BIGNUM **x, BIGNUM **y);

DSASig *DSA_sign(const BIGNUM *x, const unsigned char *hash, const int hash_len, BIGNUM *k = NULL);

bool DSA_verify(const BIGNUM *y, const DSASig *sig, const unsigned char *hash, const int hash_len);

BIGNUM *find_x(const DSASig *sig, const BIGNUM *k, const unsigned char *hash, const int hash_len, BN_CTX *ctx);

uint16_t md(const char *M, const int M_len, uint16_t H=MD_MAGIC, const bool pad=true);

uint32_t md2(const char *M, const int M_len, uint32_t H=MD2_MAGIC, bool pad=true);

void init_openssl();

void close_openssl();

#endif
