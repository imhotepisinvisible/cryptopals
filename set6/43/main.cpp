#include <iostream>
#include <sstream>

#include <openssl/bn.h>
#include <openssl/sha.h>

#include "crypto.h"

using namespace std;

int main() {
  BIGNUM *priv = NULL;
  BIGNUM *pub = NULL;

  const char *msg = "Hello, World!";

  unsigned char hash[SHA1_HASH_LEN];
  SHA1((unsigned char *)msg, strlen(msg), hash);

  DSA_genkeys(&priv, &pub);
  
  DSASig *sig = DSA_sign(priv, hash, SHA1_HASH_LEN);

  if (DSA_verify(pub, sig, hash, SHA1_HASH_LEN)) {
    cout << "Signature valid" << endl;
  } else {
    cout << "Signature invalid" << endl;
  }

  if (sig) {
    delete sig;
    sig = NULL;
  }

  const char *msg2 = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n";

  SHA1((unsigned char *)msg2, strlen(msg2), hash);

  const char *r_str = "548099063082341131477253921760299949438196259240";
  const char *s_str = "857042759984254168557880549501802188789837994940";
  const char *y_str = "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"
    "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"
    "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"
    "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"
    "bb283e6633451e535c45513b2d33c99ea17";
  
  sig = new DSASig;

  BN_dec2bn(&sig->r, r_str);
  BN_dec2bn(&sig->s, s_str);

  BIGNUM *y = NULL;
  BN_hex2bn(&y, y_str);

  if (DSA_verify(y, sig, hash, SHA1_HASH_LEN)) {
    cout << "Signature valid" << endl;
  } else {
    cout << "Signature invalid" << endl;
  }

  BN_CTX *ctx = BN_CTX_new();
  for (size_t i = 0; i < 0xffff; i++) {
    BIGNUM *k = NULL;
    stringstream ss;
    ss << i;
    BN_dec2bn(&k, ss.str().c_str());
    BIGNUM *x = find_x(sig, k, hash, SHA1_HASH_LEN, ctx);

    DSASig *test_sig = DSA_sign(x, hash, SHA1_HASH_LEN, k);

    if (((BN_cmp(test_sig->r, sig->r)) == 0) && ((BN_cmp(test_sig->s, sig->s)) == 0)) {
      cout << "Found it! k: " << i << " x: " << BN_bn2hex(x) << endl;
      if (x) BN_free(x);
      if (k) BN_free(k);
      if (test_sig) delete test_sig;
      break;
    }

    if (x) BN_free(x);
    if (k) BN_free(k);
    if (test_sig) delete test_sig;
  }

  if (priv) BN_free(priv);
  if (pub) BN_free(pub);
  if (y) BN_free(y);
  if (ctx) BN_CTX_free(ctx);
  if (sig) delete sig;
  
  return 0;
}
