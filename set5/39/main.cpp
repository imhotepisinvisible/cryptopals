#include <iostream>

#include "crypto.h"

using namespace std;

int main() {
  RSAKey *priv = NULL;
  RSAKey *pub = NULL;

  RSA_genkeys(&priv, &pub, 512);
  BIGNUM *ciphertext = RSA_encrypt(pub, "Hello, World!");
  char *plaintext = RSA_decrypt(priv, ciphertext);

  cout << plaintext << endl;

  if (pub) delete pub;
  if (priv) delete priv;
  
  return 0;
}
