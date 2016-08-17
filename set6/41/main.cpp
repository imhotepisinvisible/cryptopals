#include <iostream>

#include "crypto.h"

using namespace std;

int main() {
  RSAKey *priv = NULL;
  RSAKey *pub = NULL;
  BIGNUM *ciphertext = NULL;
  BIGNUM *ciphertext2 = NULL;
  BIGNUM *plaintext = NULL;
  BIGNUM *S = NULL;
  BIGNUM *Smodinv = NULL;
  BN_CTX *ctx = NULL;
  unsigned char *plaintext_str = NULL;

  RSA_genkeys(&priv, &pub, 512);
  if (!(ciphertext = RSA_encrypt(pub, "Hello, World!")))
    goto err;

  if (!(S = BN_new()))
      goto err;
      
  if (!BN_rand_range(S, pub->n))
    goto err;

  // C' = ((S**E mod N) C) mod N
  if (!(ctx = BN_CTX_new()))
    goto err;
  
  if (!(ciphertext2 = BN_new()))
    goto err;
  
  if (!BN_mod_exp(ciphertext2, S, pub->e_or_d, pub->n, ctx))
    goto err;
  
  if (!BN_mod_mul(ciphertext2, ciphertext2, ciphertext, pub->n, ctx))
    goto err;

  if (!(plaintext = RSA_decrypt_toBN(priv, ciphertext2)))
    goto err;

  //        P'
  //  P = -----  mod N
  //        S  
  if (!(Smodinv = modinv(S, pub->n, ctx)))
    goto err;
  
  if (!BN_mod_mul(plaintext, plaintext, Smodinv, pub->n, ctx))
    goto err;

  plaintext_str = new unsigned char[BN_num_bytes(plaintext)];
  BN_bn2bin(plaintext, plaintext_str);
      
  plaintext_str[BN_num_bytes(plaintext)] = '\0';

  cout << plaintext_str << endl;

 err:
  if (pub) delete pub;
  if (priv) delete priv;
  if (ciphertext) BN_free(ciphertext);
  if (ciphertext2) BN_free(ciphertext2);
  if (plaintext) BN_free(plaintext);
  if (S) BN_free(S);
  if (Smodinv) BN_free(Smodinv);
  if (ctx) BN_CTX_free(ctx);
  if (plaintext_str) delete [] plaintext_str;
  
  return 0;
}
