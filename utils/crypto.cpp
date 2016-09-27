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
const uint16_t MD_MAGIC = 0xbeef;
const uint32_t MD2_MAGIC = 0xdeadcafe;

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

int encryptEcb(const unsigned char *plaintext, const int plaintext_len, const unsigned char *key, unsigned char *ciphertext, bool disablePadding)
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

int decryptEcb(const unsigned char *ciphertext, const int ciphertext_len, const unsigned char *key, unsigned char *plaintext, bool disablePadding)
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


int encryptCbc(const unsigned char *plaintext, const int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext) {
  int ciphertext_len = 0;
  int blockSize = 16;
  int noBlocks = plaintext_len/blockSize + 1;
  unsigned char **blocks = new unsigned char*[noBlocks];
  for (int i = 0; i < noBlocks; i++) {
    blocks[i] = new unsigned char[blockSize];
  }
  breakIntoBlocks(blocks, plaintext, plaintext_len, noBlocks, blockSize);

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

int decryptCbc(const unsigned char *ciphertext, const int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext) {
  int plaintext_len = 0;
  unsigned char *plaintext_start = plaintext;
  int blockSize = 16;
  int noBlocks = ciphertext_len/blockSize;
  unsigned char **blocks = new unsigned char*[noBlocks];
  for (int i = 0; i < noBlocks; i++) {
    blocks[i] = new unsigned char[blockSize];
  }
  breakIntoBlocks(blocks, ciphertext, ciphertext_len, noBlocks, blockSize);
  
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

int decryptCtr(const unsigned char *ciphertext, const int ciphertext_len, const unsigned char *key, const unsigned char *nonce, unsigned char *plaintext) {
  int plaintext_len = 0;
  int blockSize = 16;
  int noBlocks = ciphertext_len/blockSize + (ciphertext_len%blockSize ? 1 : 0);
  unsigned char **blocks = new unsigned char*[noBlocks];
  for (int i = 0; i < noBlocks; i++) {
    blocks[i] = new unsigned char[blockSize];
  }
  breakIntoBlocks(blocks, ciphertext, ciphertext_len, noBlocks, blockSize);
  
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

int encryptCtr(const unsigned char *plaintext, const int plaintext_len, const unsigned char *key, const unsigned char *nonce, unsigned char *ciphertext) {
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

BIGNUM *RSA_encrypt(const RSAKey *pub, const BIGNUM *m) {
  BIGNUM *c = NULL;
  BN_CTX *ctx = NULL;
  
  if (!(c = BN_new()))
    goto err;
  
  if (!(ctx = BN_CTX_new()))
    goto err;
  
  if (!BN_mod_exp(c, m, pub->e_or_d, pub->n, ctx))
    goto err;

 err:
  if (ctx) BN_CTX_free(ctx);
  return c;
}

BIGNUM *RSA_encrypt(const RSAKey *pub, const unsigned char *plaintext, const int plaintext_len) {
  BIGNUM *m = NULL;
  BIGNUM *c = NULL;

  if (!(m = BN_new()))
    goto err;

  if (!BN_bin2bn(plaintext, plaintext_len, m))
    goto err;

  c = RSA_encrypt(pub, m);

 err:
  if (m) BN_free(m);

  return c;
}

BIGNUM *RSA_encrypt(const RSAKey *pub, const char *plaintext) {
  return RSA_encrypt(pub, (unsigned char *)plaintext, strlen(plaintext));
}

char *RSA_decrypt(const RSAKey *priv, const BIGNUM *ciphertext) {
  BIGNUM *m = NULL;
  unsigned char *plaintext = NULL;

  if (!(m = RSA_decrypt_toBN(priv, ciphertext)))
      goto err;

  plaintext = new unsigned char[BN_num_bytes(m)+1];
  if (!BN_bn2bin(m, plaintext))
    goto err;

  plaintext[BN_num_bytes(m)] = '\0';

 err:
  if (m) BN_free(m);

  return (char *)plaintext;
}

BIGNUM *RSA_decrypt_toBN(const RSAKey *priv, const BIGNUM *ciphertext) {
  BIGNUM *m = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  if (!BN_mod_exp(m, ciphertext, priv->e_or_d, priv->n, ctx))
    goto err;

 err:
  if (ctx) BN_CTX_free(ctx);

  return m;
}

BIGNUM *RSA_sign(const RSAKey *priv, const unsigned char *hash, const int hash_len) {
  BIGNUM *h = NULL;
  BIGNUM *sig = NULL;

  if (!(h = BN_new()))
    goto err;

  if (!BN_bin2bn(hash, hash_len, h))
    goto err;

  sig = RSA_decrypt_toBN(priv, h);

 err:
  if (h) BN_free(h);

  return sig;
}

bool RSA_verify(const RSAKey *pub, const BIGNUM *sig, const unsigned char *hash, const int hash_len) {
  bool ret = false;
  BIGNUM *h = NULL;
  BIGNUM *calculated_hash = NULL;

  if (!(h = BN_new()))
    goto err;

  if (!BN_bin2bn(hash, hash_len, h))
    goto err;

  calculated_hash = RSA_encrypt(pub, sig);

  ret = (BN_cmp(calculated_hash, h) == 0);

 err:
  if (h) BN_free(h);
  if (calculated_hash) BN_free(calculated_hash);

  return ret;
}

// https://github.com/androidrbox/aftv-full-unlock/blob/master/jni/aftv-full-unlock.c
BIGNUM *nearest_cuberoot(BIGNUM *in, BN_CTX *ctx) {
  BN_CTX_start(ctx);

  BIGNUM *three = BN_CTX_get(ctx);
  BIGNUM *high = BN_CTX_get(ctx);
  BIGNUM *mid = BN_CTX_get(ctx);
  BIGNUM *low = BN_CTX_get(ctx);
  BIGNUM *tmp = BN_CTX_get(ctx);

  BN_set_word(three, 3); // Create the constant 3
  BN_set_word(high, 1); // high = 1

  do {
    BN_lshift1(high, high); // high = high << 1 (high * 2)
    BN_exp(tmp, high, three, ctx); // tmp = high^3
  } while (BN_ucmp(tmp, in) <= -1); // while (tmp < in)

  BN_rshift1(low, high); // low = high >> 1 (high / 2)

  while (BN_ucmp(low, high) <= -1) { // while (low < high)
    BN_add(tmp, low, high); // tmp = low + high
    BN_rshift1(mid, tmp); // mid = tmp >> 1 (tmp / 2)
    BN_exp(tmp, mid, three, ctx); // tmp = mid^3
    if (BN_ucmp(low, mid) <= -1 && BN_ucmp(tmp, in) <= -1) { // if (low < mid && tmp < in)
      BN_copy(low, mid); // low = mid
    } else if (BN_ucmp(high, mid) >= 1 && BN_ucmp(tmp, in) >= 1) { // else if (high > mid && tmp > in)
      BN_copy(high, mid); // high = mid
    } else {
      // subtract 1 from mid because 1 will be added after the loop
      BN_sub_word(mid, 1); // mid -= 1
      break;
    }
  }

  BN_add_word(mid, 1); // mid += 1

  BIGNUM *result = BN_dup(mid);

  BN_CTX_end(ctx);

  return result;
}

void DSA_genkeys(BIGNUM **x, BIGNUM **y) {
  const char *p_str = "800000000000000089e1855218a0e7dac38136ffafa72eda7"
    "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
    "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
    "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
    "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
    "1a584471bb1";
 
  const char *q_str = "f4f47f05794b256174bba6e9b396a7707e563c5b";
 
  const char *g_str = "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
    "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
    "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"
    "0f5b64c36b625a097f1651fe775323556fe00b3608c887892"
    "878480e99041be601a62166ca6894bdd41a7054ec89f756ba"
    "9fc95302291";
    
  BIGNUM *p = NULL;
  BIGNUM *q = NULL;
  BIGNUM *g = NULL;
  BN_CTX *ctx = NULL;

  if (!BN_hex2bn(&p, p_str))
    goto err;
  
  if (!BN_hex2bn(&q, q_str))
    goto err;
  
  if (!BN_hex2bn(&g, g_str))
    goto err;

  if (!(*x = BN_new()))
    goto err;

  if (!(*y = BN_new()))
    goto err;

  // Choose a secret key x by some random method, where 0 < x < q.
  if (!BN_rand_range(*x, q))
    goto err;
  
  // Calculate the public key y = g**x mod p.
  if (!(ctx = BN_CTX_new()))
      goto err;
      
  if (!BN_mod_exp(*y, g, *x, p, ctx))
    goto err;

 err:
  if (p) BN_free(p);
  if (q) BN_free(q);
  if (g) BN_free(g);
  if (ctx) BN_CTX_free(ctx);
}

DSASig *DSA_sign(const BIGNUM *x, const unsigned char *hash, const int hash_len, BIGNUM *k) {
  const char *p_str = "800000000000000089e1855218a0e7dac38136ffafa72eda7"
    "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
    "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
    "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
    "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
    "1a584471bb1";
 
  const char *q_str = "f4f47f05794b256174bba6e9b396a7707e563c5b";
 
  const char *g_str = "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
    "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
    "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"
    "0f5b64c36b625a097f1651fe775323556fe00b3608c887892"
    "878480e99041be601a62166ca6894bdd41a7054ec89f756ba"
    "9fc95302291";
    
  BIGNUM *p = NULL;
  BIGNUM *q = NULL;
  BIGNUM *g = NULL;
  BIGNUM *xr = NULL;
  BIGNUM *h = NULL;
  BIGNUM *hxr = NULL;
  BIGNUM *kmodinv = NULL;
  BN_CTX *ctx = NULL;
  DSASig *sig = new DSASig;
  bool k_set = false;

  if (!BN_hex2bn(&p, p_str))
    goto err;
  
  if (!BN_hex2bn(&q, q_str))
    goto err;
  
  if (!BN_hex2bn(&g, g_str))
    goto err;
  
  // Generate a random per-message value k where 0 < k < q
  if (!k) {
    if (!(k = BN_new()))
      goto err;

    if (!BN_rand_range(k, q))
      goto err;
  } else {
    k_set = true;
  }
  
  // Calculate r = (g**k mod p) mod q
  if (!(ctx = BN_CTX_new()))
    goto err;
  
  if (!BN_mod_exp(sig->r, g, k, p, ctx))
    goto err;

  if (!BN_mod(sig->r, sig->r, q, ctx))
    goto err;
  
  // In the unlikely case that r = 0, start again with a different random k
  if (BN_is_zero(sig->r))
    goto err;
  
  // Calculate s = k**−1(H(m) + xr) mod q
  if (!(kmodinv = modinv(k, q, ctx)))
    goto err;

  if (!(xr = BN_new()))
    goto err;

  if (!BN_mul(xr, x, sig->r, ctx))
    goto err;

  if (!(hxr = BN_new()))
    goto err;

  if (!(h = BN_new()))
    goto err;

  if (!BN_bin2bn(hash, hash_len, h))
    goto err;

  if (!BN_add(hxr, h, xr))
    goto err;

  if (!BN_mod_mul(sig->s, kmodinv, hxr, q, ctx))
    goto err;
  
  // In the unlikely case that s = 0, start again with a different random k
  if (BN_is_zero(sig->s))
    goto err;
  
  // The signature is (r, s)

 err:
  if (p) BN_free(p);
  if (q) BN_free(q);
  if (g) BN_free(g);
  if (!k_set && k) BN_free(k);
  if (xr) BN_free(xr);
  if (h) BN_free(h);
  if (hxr) BN_free(hxr);
  if (kmodinv) BN_free(kmodinv);
  if (ctx) BN_CTX_free(ctx);

  return sig;
}

bool DSA_verify(const BIGNUM *y, const DSASig *sig, const unsigned char *hash, const int hash_len) {
  bool ret = false;

  const char *p_str = "800000000000000089e1855218a0e7dac38136ffafa72eda7"
    "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
    "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
    "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
    "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
    "1a584471bb1";
 
  const char *q_str = "f4f47f05794b256174bba6e9b396a7707e563c5b";
 
  const char *g_str = "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
    "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
    "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"
    "0f5b64c36b625a097f1651fe775323556fe00b3608c887892"
    "878480e99041be601a62166ca6894bdd41a7054ec89f756ba"
    "9fc95302291";
    
  BIGNUM *p = NULL;
  BIGNUM *q = NULL;
  BIGNUM *g = NULL;
  BIGNUM *h = NULL;
  BIGNUM *w = NULL;
  BIGNUM *u1 = NULL;
  BIGNUM *u2 = NULL;
  BIGNUM *gu1 = NULL;
  BIGNUM *yu2 = NULL;
  BIGNUM *gu1yu2 = NULL;
  BIGNUM *v = NULL;
  BN_CTX *ctx = NULL;

  if (!BN_hex2bn(&p, p_str))
    goto err;
  
  if (!BN_hex2bn(&q, q_str))
    goto err;
  
  if (!BN_hex2bn(&g, g_str))
    goto err;
  
  // Reject the signature if 0 < r < q or 0 < s < q is not satisfied.
  if (BN_is_zero(sig->r))
    goto err;

  if (BN_cmp(q, sig->r) != 1)
    goto err;
  
  if (BN_is_zero(sig->s))
    goto err;

  if (BN_cmp(q, sig->s) != 1)
    goto err;
  
  // Calculate w = s**−1 mod q
  if (!(ctx = BN_CTX_new()))
    goto err;
  
  if (!(w = modinv(sig->s, q, ctx)))
    goto err;
  
  // Calculate u1 = H(m) * w mod q
  if (!(h = BN_new()))
    goto err;

  if (!BN_bin2bn(hash, hash_len, h))
    goto err;

  if (!(u1 = BN_new()))
    goto err;

  if (!BN_mod_mul(u1, h, w, q, ctx))
    goto err;

  // Calculate u2 = r * w mod q
  if (!(u2 = BN_new()))
    goto err;

  if (!BN_mod_mul(u2, sig->r, w, q, ctx))
    goto err;
  
  // Calculate v = ((g**u1)*(y**u2) mod p) mod q
  if (!(gu1 = BN_new()))
    goto err;

  if (!BN_mod_exp(gu1, g, u1, p, ctx))
    goto err;
  
  if (!(yu2 = BN_new()))
    goto err;

  if (!BN_mod_exp(yu2, y, u2, p, ctx))
    goto err;
  
  if (!(gu1yu2 = BN_new()))
    goto err;

  if (!BN_mod_mul(gu1yu2, gu1, yu2, p, ctx))
    goto err;
  
  if (!(v = BN_new()))
    goto err;

  if (!BN_mod(v, gu1yu2, q, ctx))
    goto err;
  
  // The signature is invalid unless v = r
  ret = (BN_cmp(v, sig->r) == 0);

 err:
  if (p) BN_free(p);
  if (q) BN_free(q);
  if (g) BN_free(g);
  if (h) BN_free(w);
  if (u1) BN_free(u1);
  if (u2) BN_free(u2);
  if (gu1) BN_free(gu1);
  if (yu2) BN_free(yu2);
  if (gu1yu2) BN_free(gu1yu2);
  if (v) BN_free(v);
  if (ctx) BN_CTX_free(ctx);

  return ret;
}

BIGNUM *find_x(const DSASig *sig, const BIGNUM *k, const unsigned char *hash, const int hash_len, BN_CTX *ctx) {
  //     (s * k) - H(msg)
  // x = ----------------  mod q
  //             r
  const char *q_str = "f4f47f05794b256174bba6e9b396a7707e563c5b";

  BIGNUM *q = NULL;
  BIGNUM *x = NULL;
  BIGNUM *h = NULL;
  BIGNUM *sk = NULL;
  BIGNUM *skh = NULL;

  BN_CTX_start(ctx);

  if (!BN_hex2bn(&q, q_str))
    goto err;

  if (!(h = BN_CTX_get(ctx)))
    goto err;

  if (!BN_bin2bn(hash, hash_len, h))
    goto err;

  if (!(sk = BN_CTX_get(ctx)))
    goto err;
  
  if (!BN_mod_mul(sk, sig->s, k, q, ctx))
    goto err;

  if (!(skh = BN_CTX_get(ctx)))
    goto err;

  if(!BN_mod_sub(skh, sk, h, q, ctx))
    goto err;

  if (!(x = modinv(sig->r, q, ctx)))
    goto err;

  if (!BN_mod_mul(x, x, skh, q, ctx))
    goto err;
  
 err:
  if (q) BN_free(q);
  BN_CTX_end(ctx);
  
  return x;
}

void md_internal(const char *M, const int M_len, const void *H, const int H_size, const bool pad, unsigned char *md) {
  // Pad M to multiple of 16 - let's use PKCS7
  int blockSize = 16;
  int noBlocks = 0;
  if (pad)
    noBlocks = M_len/blockSize + 1;
  else
    noBlocks = M_len/blockSize + (M_len%blockSize ? 1 : 0);
  unsigned char **blocks = new unsigned char*[noBlocks];
  for (int i = 0; i < noBlocks; i++) {
    blocks[i] = new unsigned char[blockSize];
  }
  breakIntoBlocks(blocks, (unsigned char *)M, M_len, noBlocks, blockSize);

  // Add padding if required
  if (pad) {
    int padding = blockSize - (M_len%blockSize);
    for(int i = blockSize-padding; i < blockSize; i++) {
      blocks[noBlocks-1][i] = (unsigned char)padding;
    }
  }

  // Pad H to 16 bytes
  memcpy(md, H, H_size);
  int padding = blockSize - (H_size%blockSize);
  // Loop M in blocks
  for (int i = 0; i < noBlocks; i++) {
    for(int i = blockSize-padding; i < blockSize; i++) {
      md[i] = (unsigned char)padding;
    }
  
    encryptEcb(blocks[i], blockSize, md, md, true);
  }

  for (int i = 0; i < noBlocks; i++)
    delete [] blocks[i];
  delete [] blocks;
}

uint16_t md(const char *M, const int M_len, uint16_t H, const bool pad) {
  unsigned char H_pad[16];
  md_internal(M, M_len, &H, sizeof(H), pad, H_pad);
  
  // Strip H to 16 bits
  memcpy(&H, H_pad, sizeof(H));

  return H;
}

uint32_t md2(const char *M, const int M_len, uint32_t H, bool pad) {
  unsigned char H_pad[16];
  md_internal(M, M_len, &H, sizeof(H), pad, H_pad);
  
  // Strip H to 32 bits
  memcpy(&H, H_pad, sizeof(H));

  return H;
}
