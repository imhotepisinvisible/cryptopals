#ifndef CRYPTO_H
#define CRYPTO_H

int encryptEcb(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext, bool disablePadding);

int decryptEcb(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext, bool disablePadding);

int encryptCbc(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);

int decryptCbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

int decryptCtr(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *nonce, unsigned char *plaintext);

int encryptCtr(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *nonce, unsigned char *ciphertext);

void init_openssl();

void close_openssl();

#endif
