#include <iostream>
#include <cstdint>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "crypto.h"
#include "utils.h"
#include "sha1.h"
#include "md4.h"

using namespace std;

const uint8_t SHA1_HASH_LEN = 20;
const uint8_t MD4_HASH_LEN = 16;
const uint8_t SHA256_HASH_LEN = 32;

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

bool generate_secret_prefix_mac_md4(const unsigned char *key, const int key_len, const char *message, unsigned char *mac) {
  bool ret = false;
  MD4_CTX md4;

  MD4_Init(&md4);
  MD4_Update(&md4, key, key_len);
  MD4_Update(&md4, (const unsigned char *)message, strlen(message));

  MD4_Final(mac, &md4);
  ret = true;

  return ret;
}

bool authenticate_secret_prefix_mac_md4(const unsigned char *key, const int key_len, const char *message, const unsigned char *mac) {
  return authenticate_secret_prefix_mac_md4(key, key_len, (unsigned char *)message, strlen(message), mac);
}

bool authenticate_secret_prefix_mac_md4(const unsigned char *key, const int key_len, const unsigned char *message, const int message_len, const unsigned char *mac) {
  bool ret = false;
  unsigned char calculated_mac[MD4_HASH_LEN];
  MD4_CTX md4;

  MD4_Init(&md4);
  MD4_Update(&md4, key, key_len);
  MD4_Update(&md4, message, message_len);

  MD4_Final(calculated_mac, &md4);
  if (0 == CRYPTO_memcmp(mac, calculated_mac, MD4_HASH_LEN)) {
    ret = true;
  }

  return ret;
}

int egcd(const BIGNUM *a, const BIGNUM *n, BIGNUM *g, BIGNUM *x, BIGNUM *y, BN_CTX *ctx) {
  int ret = 0;

  BIGNUM *x0 = NULL;
  BIGNUM *x1 = NULL;
  BIGNUM *y0 = NULL;
  BIGNUM *y1 = NULL;
  BIGNUM *q = NULL;
  BIGNUM *tmp = NULL;
  BIGNUM *tmp_n = NULL;
  BN_CTX_start(ctx);
  
  if (!(x0 = BN_CTX_get(ctx)))
    goto err;
  
  if (!(x1 = BN_CTX_get(ctx)))
    goto err;
  
  if (!(y0 = BN_CTX_get(ctx)))
    goto err;
  
  if (!(y1 = BN_CTX_get(ctx)))
    goto err;
  
  if (!(q = BN_CTX_get(ctx)))
    goto err;
  
  if (!(tmp = BN_CTX_get(ctx)))
    goto err;
  
  if (!(tmp_n = BN_CTX_get(ctx)))
    goto err;
  
  if (!BN_one(x0))
    goto err;
  
  if (!BN_zero(x1))
    goto err;
  
  if (!BN_zero(y0))
    goto err;
  
  if (!BN_one(y1))
    goto err;
  
  if (!BN_copy(g, a))
    goto err;
  
  if (!BN_copy(tmp_n, n))
    goto err;

  while (!BN_is_zero(tmp_n)) {
    if (!BN_copy(tmp, tmp_n))
      goto err;
  
    if (!BN_div(q, tmp_n, g, tmp_n, ctx))
      goto err;
  
    if (!BN_copy(g, tmp))
      goto err;

    if (!BN_copy(tmp, x1))
      goto err;
  
    if (!BN_mul(x1, q, x1, ctx))
      goto err;
  
    if (!BN_sub(x1, x0, x1))
      goto err;
  
    if (!BN_copy(x0, tmp))
      goto err;

    if (!BN_copy(tmp, y1))
      goto err;
  
    if (!BN_mul(y1, q, y1, ctx))
      goto err;
  
    if (!BN_sub(y1, y0, y1))
      goto err;
  
    if (!BN_copy(y0, tmp))
      goto err;
  }

  if (!BN_copy(x, x0))
    goto err;
  
  if (!BN_copy(y, y0))
    goto err;
  
  ret = 1;

 err:
  BN_CTX_end(ctx);
  return ret;
}

BIGNUM *modinv(const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx) {
  BIGNUM *ret = NULL;
  BIGNUM *g = NULL;
  BIGNUM *x = NULL;
  BIGNUM *y = NULL;
  BN_CTX_start(ctx);
  
  if (!(g = BN_CTX_get(ctx)))
    goto err;
  
  if (!(x = BN_CTX_get(ctx)))
    goto err;
  
  if (!(y = BN_CTX_get(ctx)))
    goto err;

  if (!egcd(a, n, g, x, y, ctx))
    goto err;
  
  if (BN_is_one(g)) {
    if (!(ret = BN_new()))
      goto err;
      
    if (!BN_nnmod(ret, x, n, ctx))
      goto err;
  }

 err:
  BN_CTX_end(ctx);
  return ret;
}

void RSA_genkeys(RSAKey **priv, RSAKey **pub, const int keylen) {
  BIGNUM *p = NULL;
  BIGNUM *q = NULL;
  BIGNUM *n = NULL;
  BIGNUM *et = NULL;
  BIGNUM *e = NULL;
  BIGNUM *d = NULL;
  BN_CTX *ctx = NULL;
  
  // Generate 2 random primes. We'll use small numbers to start, so you can just pick them out of a prime table. Call them "p" and "q".
  if (!(p = BN_new()))
    goto err;
  
  if (!BN_generate_prime_ex(p, keylen, 0, NULL, NULL, NULL))
    goto err;
  
  if (!(q = BN_new()))
    goto err;
  
  if (!BN_generate_prime_ex(q, keylen, 0, NULL, NULL, NULL))
    goto err;

  // Let n be p * q. Your RSA math is modulo n.
  if (!(n = BN_new()))
    goto err;
  
  if (!(ctx = BN_CTX_new()))
    goto err;
  
  if (!BN_mul(n, p, q, ctx))
    goto err;
  
  // Let et be (p-1)*(q-1) (the "totient"). You need this value only for keygen.
  if (!(et = BN_new()))
    goto err;
  
  if (!BN_sub_word(p, 1))
    goto err;
  
  if (!BN_sub_word(q, 1))
    goto err;
  
  if (!BN_mul(et, p, q, ctx))
    goto err;
  
  // Let e be 3.
  if (!BN_hex2bn(&e, "3"))
    goto err;
  
  // Compute d = invmod(e, et). invmod(17, 3120) is 2753.
  if (!(d = modinv(e, et, ctx)))
      goto err;

  // Your public key is [e, n]. Your private key is [d, n].
  *priv = new RSAKey(d, n);
  *pub = new RSAKey(e, n);

 err:
  if (p) BN_free(p);
  if (q) BN_free(q);
  if (n) BN_free(n);
  if (et) BN_free(et);
  if (e) BN_free(e);
  if (d) BN_free(d);
}

BIGNUM *RSA_encrypt(const RSAKey *pub, const char *plaintext) {
  BIGNUM *m = NULL;
  BIGNUM *c = NULL;
  BN_CTX *ctx = NULL;

  if (!(m = BN_new()))
    goto err;
  
  if (!BN_bin2bn((unsigned char *)plaintext, strlen(plaintext), m))
    goto err;
  
  if (!(c = BN_new()))
    goto err;
  
  if (!(ctx = BN_CTX_new()))
    goto err;
  
  if (!BN_mod_exp(c, m, pub->e_or_d, pub->n, ctx))
    goto err;

 err:
  if (m) BN_free(m);
  if (ctx) BN_CTX_free(ctx);
  return c;
}

char *RSA_decrypt(const RSAKey *priv, const BIGNUM *ciphertext) {
  BIGNUM *m = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  unsigned char *plaintext = NULL;
  BN_mod_exp(m, ciphertext, priv->e_or_d, priv->n, ctx);

  plaintext = new unsigned char[BN_num_bytes(m)];
  if (!BN_bn2bin(m, plaintext))
    goto err;

  plaintext[BN_num_bytes(m)] = '\0';

 err:
  if (ctx) BN_CTX_free(ctx);

  return (char *)plaintext;
}
