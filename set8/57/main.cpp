#include <iostream>
#include <cmath>
#include <vector>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "crypto.h"
#include "conversions.h"

using namespace std;

int main() {
  init_openssl();

  unsigned char *K_bin = NULL;
  unsigned char *test_K_bin = NULL;
  unsigned char *hmac = NULL;
  unsigned char *found_hmac = NULL;
  const char *p_str = "719977399739191103060999931777394127432276433342869892173"
    "633964392834645370008535880297390048559291047548008972614070810247495742990"
    "3531369589969318716771";
  const char *g_str = "456535639709574065543685450348382683213610614163956348773"
    "243819534369043760611782831804241823818489621235232911860810008318753503340"
    "2010599512641674644143";
  const char *q_str = "236234353446506858198510045061214171961";
  const char *j_str = "304772523231776068117608821790589080388246407506105137716"
    "46768011063128035873508507547741559514324673960576895059570";
  BIGNUM *p = NULL;
  BIGNUM *g = NULL;
  BIGNUM *q = NULL;
  BIGNUM *b = NULL;
  BIGNUM *B = NULL;
  BIGNUM *j = NULL;
  BIGNUM *i_bn = NULL;
  BIGNUM *test_K = NULL;
  BIGNUM *rem = NULL;
  BIGNUM *h = NULL;
  BIGNUM *pminus1 = NULL;
  BIGNUM *pminus1overr = NULL;
  BIGNUM *K = NULL;
  BIGNUM *rn = NULL;
  BIGNUM *x = NULL;
  BIGNUM *xi = NULL;
  BIGNUM *rnoverr = NULL;
  BIGNUM *rnmodinv = NULL;
  BIGNUM *gcd = NULL;
  BIGNUM *xx = NULL;
  BIGNUM *yy = NULL;
  BN_CTX *ctx = NULL;
  vector<BIGNUM*> factors;
  vector<pair< BIGNUM*, BIGNUM*> > xs;
  uint32_t md_len = 0;
  int factor = -1;
  int r = 0;
  const char *msg = "crazy flamboyant for the rap enjoyment";

  if (!BN_dec2bn(&p, p_str))
    goto err;
 
  if (!BN_dec2bn(&g, g_str))
    goto err;

  if (!BN_dec2bn(&q, q_str))
    goto err;
  
  if (!(ctx = BN_CTX_new()))
    goto err;
  
  // Generate Bob's keys
  if (!(b = BN_new()))
    goto err;
  
  if (!BN_rand_range(b, q))
    goto err;
  
  if (!(B = BN_new()))
    goto err;
  
  if (!BN_mod_exp(B, g, b, p, ctx))
    goto err;

  // Attack
  if (!(rn = BN_new()))
    goto err;
  
  if (!BN_one(rn))
    goto err;
  
  if (!BN_dec2bn(&j, j_str))
    goto err;
  
  // Factor j
  if (!(rem = BN_new()))
    goto err;
  
  for (int i = 2; i <= 0x10000; i++) {
    if (!(i_bn = BN_new()))
      goto err;
    
    if (!BN_set_word(i_bn, i))
      goto err;
    
    if (!BN_mod(rem, j, i_bn, ctx))
      goto err;
    
    if (BN_is_zero(rem)) {
      factors.push_back(i_bn);
    } else {
      if (i_bn) BN_free(i_bn);
      i_bn = NULL;
    }
  }

  // Remove non-pairwise coprime factors
  if (!(gcd = BN_new()))
    goto err;
  
  if (!(xx = BN_new()))
    goto err;
  
  if (!(yy = BN_new()))
    goto err;
  
  for (int i = factors.size()-1; i >=0; i--) {
    for (int j = i-1; j >= 0; j--) {
      if (!egcd(factors[i], factors[j], gcd, xx, yy, ctx))
	goto err;
  
      if (!BN_is_one(gcd)) {
	factors.erase(factors.begin()+i);
	break;
      }
    }
  }

  if (!(h = BN_new()))
    goto err;
  
  if (!(pminus1 = BN_new()))
    goto err;
  
  if (!BN_sub(pminus1, p, BN_value_one()))
    goto err;
  
  if (!(pminus1overr = BN_new()))
    goto err;

  if (!(K = BN_new()))
    goto err;

  if (!(test_K = BN_new()))
    goto err;

  do {
    factor++;
    
    do {
      // h := rand(1, p)^((p-1)/r) mod p
      if (!BN_rand_range(h, p))
	goto err;

      if (!BN_div(pminus1overr, NULL, pminus1, factors[factor], ctx))
	goto err;

      if (!BN_mod_exp(h, h, pminus1overr, p, ctx))
	goto err;

    } while (BN_is_one(h));

    // Bob calcs K
    if (!BN_mod_exp(K, h, b, p, ctx))
      goto err;

    K_bin = new unsigned char[BN_num_bytes(K)];
    BN_bn2bin(K, K_bin);

    hmac = new unsigned char[SHA256_HASH_LEN];
    hmac = HMAC(EVP_sha256(), K_bin, BN_num_bytes(K), (unsigned char *)msg, strlen(msg), hmac, &md_len);

    // Recover K
    r = BN_get_word(factors[factor]);
    found_hmac = new unsigned char[SHA256_HASH_LEN];
    for (int i = 1; i <= r; i++) {
      if (!(i_bn = BN_new()))
	goto err;
      
      if (!BN_set_word(i_bn, i))
	goto err;
      
      if (!BN_mod_exp(test_K, h, i_bn, p, ctx))
	goto err;

      test_K_bin = new unsigned char[BN_num_bytes(test_K)];
      BN_bn2bin(test_K, test_K_bin);

      found_hmac = HMAC(EVP_sha256(), test_K_bin, BN_num_bytes(test_K), (unsigned char *)msg, strlen(msg), found_hmac, &md_len);
    
      if (memcmp(hmac, found_hmac, md_len) == 0) {
	pair<BIGNUM*,BIGNUM*> br(i_bn, factors[factor]);
	xs.push_back(br);
	if (test_K_bin) delete [] test_K_bin;
	test_K_bin = NULL;
	break;
      }
      
      if (i_bn) BN_free(i_bn);
      i_bn = NULL;
      if (test_K_bin) delete [] test_K_bin;
      test_K_bin = NULL;
    }

    if (!BN_mul(rn, rn, factors[factor], ctx))
      goto err;
  } while (BN_cmp(rn, q) < 1 && factor < factors.size());

  // Use the Chinese Remainder Theorem to find x
  if (!(x = BN_new()))
    goto err;
  
  BN_zero(x);
  
  if (!(xi = BN_new()))
    goto err;
  
  if (!(rnoverr = BN_new()))
    goto err;
  
  for (int i = 0; i < xs.size(); i++) {
    if (!BN_div(rnoverr, NULL, rn, xs[i].second, ctx))
      goto err;

    rnmodinv = modinv(rnoverr, xs[i].second, ctx);

    if (rnmodinv) {
      if (!BN_mul(xi, xs[i].first, rnoverr, ctx))
	goto err;
      
      if (!BN_mul(xi, xi, rnmodinv, ctx))
	goto err;
      
      if (!BN_add(x, x, xi))
	goto err;
    }
  }
  
  if (!BN_mod(x, x, rn, ctx))
    goto err;

  if (BN_cmp(x, b) == 0) {
    cout << "Success! b = " << BN_bn2hex(x) << endl;
  } else {
    cout << "Error, x calculated as" << endl
	 << BN_bn2hex(x) << endl
	 << "but b was" << endl
	 << BN_bn2hex(b) << endl;
  }

 err:
  if (p) BN_free(p);
  if (g) BN_free(g);
  if (q) BN_free(q);
  if (b) BN_free(b);
  if (B) BN_free(B);
  if (j) BN_free(j);
  if (test_K) BN_free(test_K);
  if (rem) BN_free(rem);
  if (h) BN_free(h);
  if (pminus1) BN_free(pminus1);
  if (pminus1overr) BN_free(pminus1overr);
  if (K) BN_free(K);
  if (rn) BN_free(rn);
  if (x) BN_free(x);
  if (xi) BN_free(xi);
  if (rnoverr) BN_free(rnoverr);
  if (rnmodinv) BN_free(rnmodinv);
  if (gcd) BN_free(gcd);
  if (xx) BN_free(xx);
  if (xx) BN_free(yy);
  if (ctx) BN_CTX_free(ctx);
  if (K_bin) delete [] K_bin;
  if (test_K_bin) delete [] test_K_bin;
  if (hmac) delete [] hmac;
  if (found_hmac) delete [] found_hmac;
  for (int i = 0; i < factors.size(); i++) {
    if (factors[i]) BN_free(factors[i]);
  }
  for (int i = 0; i < xs.size(); i++) {
    if (xs[i].first) BN_free(xs[i].first);
  }

  close_openssl();

  return 0;
}
