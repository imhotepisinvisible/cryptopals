#include <iostream>

#include <openssl/bn.h>
#include <openssl/sha.h>

#include "crypto.h"

using namespace std;

bool RSA_terrible_verify(const RSAKey *pub, const BIGNUM *sig, const char *msg) {
  bool ret = false;

  unsigned char hash[SHA1_HASH_LEN];
  SHA1((unsigned char *)msg, strlen(msg), hash);

  BIGNUM *calculated_hash_BN = RSA_encrypt(pub, sig);

  int calculated_hash_len = BN_num_bytes(calculated_hash_BN);
  unsigned char *calculated_hash = new unsigned char[calculated_hash_len];
  BN_bn2bin(calculated_hash_BN, calculated_hash);

  // BN_bin2bn ignores leading 0s so for simplicity, assume
  // calculated_hash had a leading 0
  if (/*calculated_hash[0] == 0 &&*/ calculated_hash[0] == 1 && calculated_hash[1] == 0xff) {
    int i = 1;
    while (calculated_hash[i] == 0xff && i < (calculated_hash_len - 1 - 5 - SHA1_HASH_LEN)) {
      i++;
    }
    if (calculated_hash[i] == 0
	&& (memcmp(&calculated_hash[i+1], "ASN.1", 5) == 0)
	&& (memcmp(&calculated_hash[i+1+5], hash, SHA1_HASH_LEN) == 0)) {
      ret = true;
    }
  }

  if (calculated_hash_BN) BN_free(calculated_hash_BN);
  if (calculated_hash) delete [] calculated_hash;

  return ret;
}

int main() {
  RSAKey *priv = NULL;
  RSAKey *pub = NULL;

  const char *msg = "Hello, World!";

  unsigned char hash[SHA1_HASH_LEN];
  SHA1((unsigned char *)msg, strlen(msg), hash);

  RSA_genkeys(&priv, &pub, 1024);

  // Construct valid padding
  int sig_block_len = BN_num_bytes(priv->n);
  unsigned char *sig_block = new unsigned char[sig_block_len];
  int padding_len = sig_block_len - SHA1_HASH_LEN - 5 - 1 - 2;

  sig_block[0] = 0;
  sig_block[1] = 1;
  memset(sig_block+2, 0xff, padding_len);
  sig_block[padding_len+2] = 0;
  memcpy(sig_block+2+padding_len+1, "ASN.1", 5);
  memcpy(sig_block+2+padding_len+1+5, hash, SHA1_HASH_LEN);
  
  BIGNUM *sig = RSA_sign(priv, sig_block, sig_block_len);

  // Normal verification
  if (RSA_verify(pub, sig, sig_block, sig_block_len)) {
    cout << "Signature valid" << endl;
  } else {
    cout << "Signature invalid" << endl;
  }

  // Terrible verification
  if (RSA_terrible_verify(pub, sig, msg)) {
    cout << "Signature valid" << endl;
  } else {
    cout << "Signature invalid" << endl;
  }

  // Attack
  const char *evil_msg = "hi mom";
  unsigned char evil_hash[SHA1_HASH_LEN];
  SHA1((unsigned char *)evil_msg, strlen(evil_msg), evil_hash);

  // Let's try method 2...
  unsigned char *evil_sig_block = new unsigned char[sig_block_len];

  evil_sig_block[0] = 0;
  evil_sig_block[1] = 1;
  evil_sig_block[2] = 0xff;
  evil_sig_block[3] = 0;
  memcpy(evil_sig_block+4, "ASN.1", 5);
  memcpy(evil_sig_block+4+5, evil_hash, SHA1_HASH_LEN);
  int zero_pad_len = sig_block_len - SHA1_HASH_LEN - 5 - 4;
  // Setting to 0xff seems to work better than setting to 0
  memset(evil_sig_block+4+5+SHA1_HASH_LEN, 0xff, zero_pad_len);

  BIGNUM *evil_sig_block_BN = BN_new();
  BN_bin2bn(evil_sig_block, sig_block_len, evil_sig_block_BN);
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *evil_sig = nearest_cuberoot(evil_sig_block_BN, ctx);
  
  if (RSA_terrible_verify(pub, evil_sig, evil_msg)) {
    cout << "Signature valid" << endl;
  } else {
    cout << "Signature invalid" << endl;
  }

  if (pub) delete pub;
  if (priv) delete priv;
  if (sig_block) delete [] sig_block;
  if (sig) BN_free(sig);
  if (evil_sig_block) delete [] evil_sig_block;
  if (evil_sig_block_BN) BN_free(evil_sig_block_BN);
  if (evil_sig) BN_free(evil_sig);
  if (ctx) BN_CTX_free(ctx);
  
  return 0;
}
