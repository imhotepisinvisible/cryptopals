#include <iostream>

#include <openssl/bn.h>
#include <openssl/sha.h>

#include "crypto.h"

using namespace std;

// Bad version of DSA_sign that takes any generator, and doesn't perform the r and s !=0 safety checks
DSASig *DSA_bad_sign(const BIGNUM *x, const unsigned char *hash, const int hash_len, const char *g_str) {
  const char *p_str = "800000000000000089e1855218a0e7dac38136ffafa72eda7"
    "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
    "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
    "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
    "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
    "1a584471bb1";
 
  const char *q_str = "f4f47f05794b256174bba6e9b396a7707e563c5b";
    
  BIGNUM *p = NULL;
  BIGNUM *q = NULL;
  BIGNUM *g = NULL;
  BIGNUM *k = NULL;
  BIGNUM *xr = NULL;
  BIGNUM *h = NULL;
  BIGNUM *hxr = NULL;
  BIGNUM *kmodinv = NULL;
  BN_CTX *ctx = NULL;
  DSASig *sig = new DSASig;

  if (!BN_hex2bn(&p, p_str))
    goto err;
  
  if (!BN_hex2bn(&q, q_str))
    goto err;
  
  if (!BN_hex2bn(&g, g_str))
    goto err;
  
  // Generate a random per-message value k where 0 < k < q
  if (!(k = BN_new()))
    goto err;

  if (!BN_rand_range(k, q))
    goto err;
  
  // Calculate r = (g**k mod p) mod q
  if (!(ctx = BN_CTX_new()))
    goto err;
  
  if (!BN_mod_exp(sig->r, g, k, p, ctx))
    goto err;

  if (!BN_mod(sig->r, sig->r, q, ctx))
    goto err;
  
  // In the unlikely case that r = 0, start again with a different random k
  //if (BN_is_zero(sig->r))
  //  goto err;
  
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
  //if (BN_is_zero(sig->s))
  //  goto err;
  
  // The signature is (r, s)

 err:
  if (p) BN_free(p);
  if (q) BN_free(q);
  if (g) BN_free(g);
  if (k) BN_free(k);
  if (xr) BN_free(xr);
  if (h) BN_free(h);
  if (hxr) BN_free(hxr);
  if (kmodinv) BN_free(kmodinv);
  if (ctx) BN_CTX_free(ctx);

  return sig;
}

// Bad version of DSA_verify that takes any generator, and doesn't perform the r and s !=0 safety checks
bool DSA_bad_verify(const BIGNUM *y, const DSASig *sig, const unsigned char *hash, const int hash_len, const char *g_str) {
  bool ret = false;

  const char *p_str = "800000000000000089e1855218a0e7dac38136ffafa72eda7"
    "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
    "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
    "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
    "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
    "1a584471bb1";
 
  const char *q_str = "f4f47f05794b256174bba6e9b396a7707e563c5b";
    
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
  //if (BN_is_zero(sig->r))
  //  goto err;

  //if (BN_cmp(q, sig->r) != 1)
  //  goto err;
  
  //if (BN_is_zero(sig->s))
  //  goto err;

  //if (BN_cmp(q, sig->s) != 1)
  //  goto err;
  
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

DSASig *make_evil_sig(const BIGNUM *y, const BIGNUM *z) {
  // r = ((y**z) % p) % q
  //       r
  // s =  --- % q
  //       z
  DSASig *sig = new DSASig;

  const char *p_str = "800000000000000089e1855218a0e7dac38136ffafa72eda7"
    "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
    "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
    "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
    "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
    "1a584471bb1";
 
  const char *q_str = "f4f47f05794b256174bba6e9b396a7707e563c5b";

  BIGNUM *p = NULL;
  BIGNUM *q = NULL;
  BIGNUM *zmodinv = NULL;

  BN_CTX *ctx = NULL;
  
  if (!BN_hex2bn(&p, p_str))
    goto err;
  
  if (!BN_hex2bn(&q, q_str))
    goto err;

  if (!(ctx = BN_CTX_new()))
    goto err;
  
  if (!BN_mod_exp(sig->r, y, z, p, ctx))
    goto err;

  if (!BN_mod(sig->r, sig->r, q, ctx))
    goto err;

  if (!(zmodinv = modinv(z, q, ctx)))
    goto err;

  if (!BN_mod_mul(sig->s, sig->r, zmodinv, q, ctx))
    goto err;

 err:
  if (p) BN_free(p);
  if (q) BN_free(q);
  if (zmodinv) BN_free(zmodinv);
  if (ctx) BN_CTX_free(ctx);

  return sig;
}

int main() {
  BIGNUM *priv = NULL;
  BIGNUM *pub = NULL;

  const char *msg = "Hello, world";

  unsigned char hash1[SHA1_HASH_LEN];
  SHA1((unsigned char *)msg, strlen(msg), hash1);

  DSA_genkeys(&priv, &pub);
  
  DSASig *sig = DSA_bad_sign(priv, hash1, SHA1_HASH_LEN, "0");

  cout << BN_bn2hex(sig->r) << endl;
  cout << BN_bn2hex(sig->s) << endl << endl;

  // With g=0, r=0.  Signature verification checks v=r, so anything
  // can be signed with r=0, s=<literally-anything>
  if (DSA_bad_verify(pub, sig, hash1, SHA1_HASH_LEN, "0")) {
    cout << "Signature valid" << endl;
  } else {
    cout << "Signature invalid" << endl;
  }

  const char *msg2 = "Goodbye, world";
  unsigned char hash2[SHA1_HASH_LEN];
  SHA1((unsigned char *)msg2, strlen(msg2), hash2);

  if (DSA_bad_verify(pub, sig, hash2, SHA1_HASH_LEN, "0")) {
    cout << "Signature valid" << endl;
  } else {
    cout << "Signature invalid" << endl;
  }

  // g=p+1:
  const char *p_plus1 = "800000000000000089e1855218a0e7dac38136ffafa72eda7"
    "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
    "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
    "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
    "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
    "1a584471bb2";

  // Z can be literally anything - set it to 1
  BIGNUM *z = BN_new();
  BN_one(z);

  DSASig *evil_sig = make_evil_sig(pub, z);

  if (DSA_bad_verify(pub, evil_sig, hash1, SHA1_HASH_LEN, p_plus1)) {
    cout << "Signature valid" << endl;
  } else {
    cout << "Signature invalid" << endl;
  }

  if (DSA_bad_verify(pub, evil_sig, hash2, SHA1_HASH_LEN, p_plus1)) {
    cout << "Signature valid" << endl;
  } else {
    cout << "Signature invalid" << endl;
  }
  
  if (priv) BN_free(priv);
  if (pub) BN_free(pub);
  if (z) BN_free(z);
  if (sig) delete sig;
  
  return 0;
}
