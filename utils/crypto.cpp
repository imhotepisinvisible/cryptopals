#include <iostream>
#include <cstdint>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "crypto.h"
#include "utils.h"
#include "sha1.h"

using namespace std;

const uint8_t SHA1_HASH_LEN = 20;

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

void init_openssl() {
  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
}

void close_openssl() {
  /* Clean up */
  EVP_cleanup();
  ERR_free_strings();
}

int encryptEcb(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext, bool disablePadding)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
    handleErrors();

  /* Disable padding because I'm doing it myself */
  if (disablePadding)
    EVP_CIPHER_CTX_set_padding(ctx, 0);

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decryptEcb(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext, bool disablePadding)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
    handleErrors();

  /* Disable padding because I'm doing it myself */
  if (disablePadding)
    EVP_CIPHER_CTX_set_padding(ctx, 0);
  
  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}


int encryptCbc(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
  int ciphertext_len = 0;
  int blockSize = 16;
  int noBlocks = plaintext_len/blockSize + 1;
  unsigned char **blocks = new unsigned char*[noBlocks];
  for (int i = 0; i < noBlocks; i++) {
    blocks[i] = new unsigned char[blockSize];
  }
  breakIntoBlocks(blocks, plaintext, noBlocks, blockSize);

  /* Add padding */
  int padding = blockSize - (plaintext_len%blockSize);
  if (padding == 0)
    padding = blockSize;
  for(int i = blockSize-padding; i < blockSize; i++) {
    blocks[noBlocks-1][i] = (unsigned char)padding;
  }
  
  unsigned char workingBlock[blockSize];
  unsigned char xorBlock[blockSize];
  memcpy(xorBlock, iv, blockSize);
  /* Encrypt the plaintext */
  for (int i = 0; i < noBlocks; i++) {
    doXor(workingBlock, blocks[i], xorBlock, blockSize);
    ciphertext_len += encryptEcb(workingBlock, blockSize, key, ciphertext, true);
    memcpy(xorBlock, ciphertext, blockSize);
    ciphertext += blockSize;
  }

  for (int i = 0; i < noBlocks; i++)
    delete [] blocks[i];
  delete [] blocks;

  return ciphertext_len;
}

int decryptCbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
  int plaintext_len = 0;
  unsigned char *plaintext_start = plaintext;
  int blockSize = 16;
  int noBlocks = ciphertext_len/blockSize;
  unsigned char **blocks = new unsigned char*[noBlocks];
  for (int i = 0; i < noBlocks; i++) {
    blocks[i] = new unsigned char[blockSize];
  }
  breakIntoBlocks(blocks, ciphertext, noBlocks, blockSize);
  
  unsigned char workingBlock[blockSize];
  unsigned char xorBlock[blockSize];
  memcpy(xorBlock, iv, blockSize);
  /* Decrypt the ciphertext */
  for (int i = 0; i < noBlocks; i++) {
    plaintext_len += decryptEcb(blocks[i], blockSize, key, workingBlock, true);
    if (i > 0) {
      memcpy(xorBlock, blocks[i-1], blockSize);
    }
    doXor(plaintext, workingBlock, xorBlock, blockSize);
    plaintext += blockSize;
  }

  /* Remove Padding */
  plaintext = plaintext_start;
  int padding = plaintext[plaintext_len-1];
  if (padding <= 0 || padding > blockSize)
    return -1;
  for (int i = plaintext_len-1; i >= plaintext_len-padding; i--) {
    if (plaintext[i] != padding)
      return -1;
    plaintext[i] = '\0';
  }
  plaintext_len -= padding;
  
  for (int i = 0; i < noBlocks; i++)
    delete [] blocks[i];
  delete [] blocks;

  return plaintext_len;
}

int decryptCtr(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *nonce, unsigned char *plaintext) {
  int plaintext_len = 0;
  int blockSize = 16;
  int noBlocks = ciphertext_len/blockSize + (ciphertext_len%blockSize ? 1 : 0);
  unsigned char **blocks = new unsigned char*[noBlocks];
  for (int i = 0; i < noBlocks; i++) {
    blocks[i] = new unsigned char[blockSize];
  }
  breakIntoBlocks(blocks, ciphertext, noBlocks, blockSize);
  
  unsigned char workingBlock[blockSize];
  unsigned char keystream[blockSize];
  // Load in nonce
  memcpy(keystream, nonce, blockSize/2);
  /* Encrypt the plaintext */
  for (uint64_t i = 0; i < noBlocks; i++) {
    // Load in counter (Little endian)
    *(uint64_t *)(keystream+(blockSize/2)) = i;
    plaintext_len += encryptEcb(keystream, blockSize, key, workingBlock, true);
    doXor(plaintext, blocks[i], workingBlock, blockSize);
    plaintext += blockSize;
  }

  for (int i = 0; i < noBlocks; i++)
    delete [] blocks[i];
  delete [] blocks;

  plaintext_len = ciphertext_len;
  return plaintext_len;
}

int encryptCtr(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *nonce, unsigned char *ciphertext) {
  return decryptCtr(plaintext, plaintext_len, key, nonce, ciphertext);
}

bool generate_secret_prefix_mac(const unsigned char *key, const int key_len, const char *message, unsigned char *mac) {
  bool ret = false;
  SHA1Context sha;

  SHA1Reset(&sha);
  SHA1Input(&sha, key, key_len);
  SHA1Input(&sha, (const unsigned char *)message, strlen(message));

  if (!SHA1Result(&sha)) {
    cout << "ERROR-- could not compute message digest" << endl;
  }
  else {
    uint32_t bytes = 0;
    for(int i = 0; i < 5 ; i++) {
      bytes = htonl(sha.Message_Digest[i]);
      memcpy(mac+i*4, (unsigned char *)&bytes, sizeof(uint32_t));
    }
    ret = true;
  }

  return ret;
}

bool authenticate_secret_prefix_mac(const unsigned char *key, const int key_len, const char *message, const unsigned char *mac) {
  return authenticate_secret_prefix_mac(key, key_len, (unsigned char *)message, strlen(message), mac);
}

bool authenticate_secret_prefix_mac(const unsigned char *key, const int key_len, const unsigned char *message, const int message_len, const unsigned char *mac) {
  bool ret = false;
  SHA1Context sha;

  SHA1Reset(&sha);
  SHA1Input(&sha, key, key_len);
  SHA1Input(&sha, message, message_len);

  if (!SHA1Result(&sha)) {
    cout << "ERROR-- could not compute message digest" << endl;
  }
  else {
    uint32_t passed_digest[5];
    for(int i = 0; i < 5 ; i++) {
      passed_digest[i] = ntohl(*((uint32_t *)mac+i));
    }
    if (0 == CRYPTO_memcmp((uint8_t *)passed_digest, (uint8_t *)sha.Message_Digest, SHA1_HASH_LEN)) {
      ret = true;
    }
  }

  return ret;
}
