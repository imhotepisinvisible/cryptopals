#ifndef CRYPTO_H
#define CRYPTO_H

extern const uint8_t SHA1_HASH_LEN;

int encryptEcb(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext, bool disablePadding);

int decryptEcb(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext, bool disablePadding);

int encryptCbc(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);

int decryptCbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

int decryptCtr(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *nonce, unsigned char *plaintext);

int encryptCtr(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *nonce, unsigned char *ciphertext);

bool generate_secret_prefix_mac(const unsigned char *key, int key_len, const char *message, unsigned char *mac);

bool authenticate_secret_prefix_mac(const unsigned char *key, int key_len, const char *message, const unsigned char *mac);

void init_openssl();

void close_openssl();

#endif
