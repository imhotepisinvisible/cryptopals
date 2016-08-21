#include <iostream>

#include "crypto.h"
#include "conversions.h"

using namespace std;

bool parity_oracle(const RSAKey *priv, const BIGNUM *ciphertext) {
  bool ret = false;
  BIGNUM *plaintext = RSA_decrypt_toBN(priv, ciphertext);

  ret = !(BN_is_bit_set(plaintext, 0));
  
  if (plaintext) BN_free(plaintext);
  return ret;
}

int main() {
  RSAKey *priv = NULL;
  RSAKey *pub = NULL;

  const char *plaintext_b64 = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";
  char plaintext[128] = {0};
  b64ToBytes((unsigned char *)plaintext, plaintext_b64);

  RSA_genkeys(&priv, &pub, 1024);
  BIGNUM *ciphertext = RSA_encrypt(pub, plaintext);

  BIGNUM *UB = BN_dup(pub->n);
  BIGNUM *LB = BN_new();
  BN_zero(LB);

  BIGNUM *dbl = BN_new();
  BN_set_word(dbl, 2);
  BN_CTX *ctx = BN_CTX_new();
  BN_mod_exp(dbl, dbl, pub->e_or_d, pub->n, ctx);

  // lg(n) == number of bits in n
  for (int i = 0; i < BN_num_bits(pub->n); i++) {
    cout << "\r" << BN_bn2hex(UB) << flush;

    // Double ciphertext
    BN_mod_mul(ciphertext, ciphertext, dbl, pub->n, ctx);

    // Run against oracle and adjust bounds
    if (parity_oracle(priv, ciphertext)) {
      // UB = (UB + LB)/2;
      BN_add(UB, UB, LB);
      BN_rshift1(UB, UB);
    } else {
      // LB = (UB + LB)/2;
      BN_add(LB, UB, LB);
      BN_rshift1(LB, LB);
    }
  }

  unsigned char *calc_plaintext = new unsigned char[BN_num_bytes(UB)+1];
  BN_bn2bin(UB, calc_plaintext);

  calc_plaintext[BN_num_bytes(UB)] = '\0';
  cout << "\r" << calc_plaintext << endl;

  if (pub) delete pub;
  if (priv) delete priv;
  if (ciphertext) BN_free(ciphertext);
  if (UB) BN_free(UB);
  if (LB) BN_free(LB);
  if (dbl) BN_free(dbl);
  if (ctx) BN_CTX_free(ctx);
  if (calc_plaintext) delete [] calc_plaintext;
  
  return 0;
}
