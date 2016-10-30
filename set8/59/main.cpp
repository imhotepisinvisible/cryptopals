#include <iostream>
#include <cmath>
#include <vector>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "crypto.h"
#include "conversions.h"
#include "ec.h"

using namespace std;

int tonelli_shanks(ECPoint &h, const ECGroup &group, BN_CTX *ctx) {
  BN_CTX_start(ctx);
  int ret = 0;

  BIGNUM *y2 = BN_CTX_get(ctx);
  BIGNUM *x3 = BN_CTX_get(ctx);
  BIGNUM *ax = BN_CTX_get(ctx);
  BIGNUM *three = BN_CTX_get(ctx);
  BIGNUM *two = BN_CTX_get(ctx);
  BIGNUM *pminus1over2 = BN_CTX_get(ctx);
  BIGNUM *pminus1 = BN_CTX_get(ctx);
  BIGNUM *l = BN_CTX_get(ctx);
  BIGNUM *Q = BN_CTX_get(ctx);
  BIGNUM *S = BN_CTX_get(ctx);
  BIGNUM *z = BN_CTX_get(ctx);
  BIGNUM *c = BN_CTX_get(ctx);
  BIGNUM *R = BN_CTX_get(ctx);
  BIGNUM *t = BN_CTX_get(ctx);
  BIGNUM *M = BN_CTX_get(ctx);
  BIGNUM *i = BN_CTX_get(ctx);
  BIGNUM *t2i = BN_CTX_get(ctx);
  BIGNUM *b = BN_CTX_get(ctx);

  if (!b)
    goto err;

  // Calculate y^2
  if (!BN_set_word(three, 3))
    goto err;
  
  if (!BN_set_word(two, 2))
    goto err;
  
  if (!BN_mod_exp(x3, h.getx(), three, group.p, ctx))
    goto err;
  
  if (!BN_mod_mul(ax, h.getx(), group.a, group.p, ctx))
    goto err;

  if (!BN_add(y2, x3, ax))
    goto err;
  
  if (!BN_add(y2, y2, group.b))
    goto err;
  
  if (!BN_nnmod(y2, y2, group.p, ctx))
    goto err;

  // Verify y^2 is a quadratic residue (mod p), meaning that the Legendre symbol ( n/p )=1
  if (!BN_sub(pminus1, group.p, BN_value_one()))
    goto err;
  
  if (!BN_sub(pminus1over2, group.p, BN_value_one()))
    goto err;
  
  if (!BN_div(pminus1over2, NULL, pminus1over2, two, ctx))
    goto err;

  if (!BN_mod_exp(l, y2, pminus1over2, group.p, ctx))
    goto err;
  
  if (BN_cmp(l, BN_value_one()) != 0) {
    goto err;
  }
 
  // Factor out powers of 2 from p − 1, defining Q and S as: p-1=Q2^S with Q odd
  if (!BN_sub(Q, group.p, BN_value_one()))
    goto err;
  
  BN_zero(S);
  
  while (!BN_is_bit_set(Q, 0)) {
    if (!BN_add(S, S, BN_value_one()))
      goto err;
    
    if (!BN_rshift1(Q, Q))
      goto err;
  }
    
  // If S==1 then solutions are given directly by R=n^(p+1/4)
  if (BN_cmp(S, BN_value_one()) == 0) {
    if (!BN_add(R, group.p, BN_value_one()))
      goto err;

    if (!BN_rshift(R, R, 2))
      goto err;

    if (!BN_mod_exp(R, y2, R, group.p, ctx))
      goto err;
    
    h.sety(R);
    ret = 1;
    goto err;
  }

  // Select a z such that the Legendre symbol ( z/p )=−1, and set c=z^Q
  if (!BN_set_word(z, 1))
    goto err;

  do {
    if (!BN_add(z, z, BN_value_one()))
      goto err;
    
    if (!BN_mod_exp(l, z, pminus1over2, group.p, ctx))
      goto err;
  } while (BN_cmp(l, pminus1) != 0);

  if (!BN_mod_exp(c, z, Q, group.p, ctx))
    goto err;

  // Let R=n^((Q+1)/2), t=n^Q, M=S  
  if (!BN_add(R, Q, BN_value_one()))
    goto err;
  
  if (!BN_div(R, NULL, R, two, ctx))
    goto err;
  
  if (!BN_mod_exp(R, y2, R, group.p, ctx))
    goto err;

  if (!BN_mod_exp(t, y2, Q, group.p, ctx))
    goto err;
  
  if (!BN_copy(M, S))
    goto err;

  // Loop:
  // If t==1 return R.
  // Otherwise, find the lowest i, 0<i<M, such that t^2^i==1
  // Let b=c^2^(M−i−1), and set R=Rb, t=tb^2, c=b^2 and M=i
  while (!BN_is_one(t)) {
    BN_zero(i);
    do {
      if (!BN_add(i, i, BN_value_one()))
	goto err;
      
      if (!BN_mod_exp(t2i, two, i, group.p, ctx))
	goto err;
      
      if (!BN_mod_exp(t2i, t, t2i, group.p, ctx))
	goto err;
    } while (!BN_is_one(t2i) && BN_cmp(i, M) < 0);

    if (!BN_sub(b, M, i))
      goto err;
    
    if (!BN_sub(b, b, BN_value_one()))
      goto err;
    
    if (!BN_mod_exp(b, two, b, group.p, ctx))
      goto err;
    
    if (!BN_mod_exp(b, c, b, group.p, ctx))
      goto err;

    if (!BN_mod_mul(R, R, b, group.p, ctx))
      goto err;

    if (!BN_mod_exp(c, b, two, group.p, ctx))
      goto err;

    if (!BN_mod_mul(t, t, c, group.p, ctx))
      goto err;

    if (!BN_copy(M, i))
      goto err;
  }

  // Once you have solved the congruence with R the second solution is p − R.
  h.sety(R);
      
  ret = 1;

 err:
  BN_CTX_end(ctx);
  return ret;
}

int ecdh_subgroup_attack(vector<pair< BIGNUM*, BIGNUM*> > &xs, const BIGNUM *b, const ECPoint &B, const ECGroup &group, const ECGroup &badgroup, BN_CTX *ctx) {
  BN_CTX_start(ctx);
  unsigned char *K_bin = NULL;
  unsigned char *test_K_bin = NULL;
  unsigned char *hmac = NULL;
  unsigned char *found_hmac = NULL;
  ECPoint K;
  ECPoint test_K;
  ECPoint h;
  BIGNUM *i_bn = NULL;
  BIGNUM *rn = BN_CTX_get(ctx);
  BIGNUM *rem = BN_CTX_get(ctx);
  BIGNUM *qoverr = NULL;
  BIGNUM *pminus1 = BN_CTX_get(ctx);
  BIGNUM *gcd = BN_CTX_get(ctx);
  BIGNUM *xx = BN_CTX_get(ctx);
  BIGNUM *yy = BN_CTX_get(ctx);
  BIGNUM *randx = BN_CTX_get(ctx);
  vector<BIGNUM*> factors;
  uint32_t md_len = 0;
  int factor = -1;
  int r = 0;
  int ret = 0;
  const char *msg = "crazy flamboyant for the rap enjoyment";

  if (!yy)
    goto err;
  
  // Attack
  if (!BN_one(rn))
    goto err;
  
  // Factor q
  for (int i = 3; i <= 0x10000; i++) {
    if (!(i_bn = BN_new()))
      goto err;
    
    if (!BN_set_word(i_bn, i))
      goto err;
    
    if (!BN_mod(rem, badgroup.q, i_bn, ctx))
      goto err;
    
    if (BN_is_zero(rem) && BN_is_prime_ex(i_bn, BN_prime_checks, ctx, NULL)) {
      factors.push_back(i_bn);
    } else {
      if (i_bn) BN_free(i_bn);
      i_bn = NULL;
    }
  }

  // Remove non-pairwise coprime factors
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
  
  if (!BN_sub(pminus1, group.p, BN_value_one()))
    goto err;

  do {
    factor++;
    
    do {
      // h := random point from the bad curve
      do {
	if (!BN_rand_range(randx, group.p))
	  goto err;

	h.setx(randx);
      } while (!tonelli_shanks(h, badgroup, ctx));

      // Multiply by q/r
      qoverr = modinv(factors[factor], group.p, ctx);

      if (!BN_mod_mul(qoverr, badgroup.q, qoverr, group.p, ctx))
	goto err;

      if (!EC_scale(h, h, qoverr, group, ctx))
	goto err;
    } while (EC_is_infinity(h, group));

    // Bob calcs K
    if (!EC_scale(K, h, b, group, ctx))
      goto err;

    // Use x+y as the key to make this attack easier (avoids having
    // to differentiate between K and -K).
    K_bin = new unsigned char[BN_num_bytes(K.getx())+BN_num_bytes(K.gety())];
    BN_bn2bin(K.getx(), K_bin);
    BN_bn2bin(K.gety(), K_bin+BN_num_bytes(K.getx()));

    hmac = new unsigned char[SHA256_HASH_LEN];
    hmac = HMAC(EVP_sha256(), K_bin, BN_num_bytes(K.getx())+BN_num_bytes(K.gety()), (unsigned char *)msg, strlen(msg), hmac, &md_len);

    // Recover K
    r = BN_get_word(factors[factor]);
    found_hmac = new unsigned char[SHA256_HASH_LEN];
    for (int i = 1; i <= r; i++) {
      if (!(i_bn = BN_new()))
	goto err;
      
      if (!BN_set_word(i_bn, i))
	goto err;

      if (!EC_scale(test_K, h, i_bn, badgroup, ctx))
	goto err;

      test_K_bin = new unsigned char[BN_num_bytes(test_K.getx())+BN_num_bytes(test_K.gety())];
      BN_bn2bin(test_K.getx(), test_K_bin);
      BN_bn2bin(test_K.gety(), test_K_bin+BN_num_bytes(test_K.getx()));

      found_hmac = HMAC(EVP_sha256(), test_K_bin, BN_num_bytes(test_K.getx())+BN_num_bytes(test_K.gety()), (unsigned char *)msg, strlen(msg), found_hmac, &md_len);
    
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
  } while (BN_cmp(rn, group.q) < 1 && factor+1 < factors.size());
  ret = 1;

 err:
  if (K_bin) delete [] K_bin;
  if (test_K_bin) delete [] test_K_bin;
  if (hmac) delete [] hmac;
  if (found_hmac) delete [] found_hmac;

  BN_CTX_end(ctx);
  
  return ret;
}

void add_to_vector(vector<pair< BIGNUM*, BIGNUM*> > &dest, vector<pair< BIGNUM*, BIGNUM*> > &src, BIGNUM *rn, BN_CTX *ctx) {
  bool add = false;
  
  for (int i = 0; i < src.size(); i++) {
    add = true;
    for (int j = 0; j < dest.size(); j++) {
      if (BN_cmp(src[i].second, dest[j].second) == 0) {
	add = false;
	break;
      }
    }
    
    if (add) {
      dest.push_back(src[i]);
      BN_mul(rn, rn, src[i].second, ctx);
    } else {
      if (src[i].first) BN_free(src[i].first);
      if (src[i].second) BN_free(src[i].second);
    }
  }
}

int main() {
  ECPoint base("182", "85518893674295321206118380980485522083");
  ECGroup group("-95051", "11279326", "233970423115425145524320034830162017933", base, "29246302889428143187362802287225875743", "8", "233970423115425145498902418297807005944");

  ECGroup badgroup("-95051", "210", "233970423115425145524320034830162017933", base, "0", "0", "233970423115425145550826547352470124412");
  ECGroup badgroup2("-95051", "504", "233970423115425145524320034830162017933", base, "0", "0", "233970423115425145544350131142039591210");
  ECGroup badgroup3("-95051", "727", "233970423115425145524320034830162017933", base, "0", "0", "233970423115425145545378039958152057148");

  ECPoint test;

  BN_CTX *ctx = NULL;
  BIGNUM *a = NULL;
  ECPoint A;
  BIGNUM *b = NULL;
  ECPoint B;
  ECPoint k1;
  ECPoint k2;
  BIGNUM *x1 = NULL;
  BIGNUM *x2 = NULL;

  BIGNUM *rn = NULL;
  BIGNUM *xi = NULL;
  BIGNUM *xguess = NULL;
  BIGNUM *rnoverr = NULL;
  BIGNUM *rnmodinv = NULL;
  vector<pair< BIGNUM*, BIGNUM*> > xs;
  vector<pair< BIGNUM*, BIGNUM*> > partial_xs;

  if (!(ctx = BN_CTX_new()))
    goto err;

  // Verify G*n = 0
  if (!EC_scale(test, group.G, group.n, group, ctx))
    goto err;
  
  cout << test << endl;
 
  // Try ECDH
  // Generate Alice's keys
  if (!(a = BN_new()))
    goto err;
  
  if (!BN_rand_range(a, group.n))
    goto err;
  
  if (!EC_scale(A, group.G, a, group, ctx))
    goto err;

  // Generate Bob's keys
  if (!(b = BN_new()))
    goto err;

  if (!BN_rand_range(b, group.n))
    goto err;
  
  if (!EC_scale(B, group.G, b, group, ctx))
    goto err;

  if (!EC_scale(k1, B, a, group, ctx))
    goto err;

  if (!EC_scale(k2, A, b, group, ctx))
    goto err;

  if (!(x1 = BN_dup(k1.getx())))
    goto err;
  
  if (!(x2 = BN_dup(k2.getx())))
    goto err;

  if (BN_cmp(x1, x2) == 0) {
    cout << "Found shared secret" << endl;
  } else {
    cout << "Error finding shared secret" << endl;
  }

  // Try the subgroup attack
  if (!(rn = BN_new()))
    goto err;

  if (!BN_set_word(rn, 1))
    goto err;

  ecdh_subgroup_attack(partial_xs, b, B, group, badgroup, ctx);
  add_to_vector(xs, partial_xs, rn, ctx);

  partial_xs.clear();
  ecdh_subgroup_attack(partial_xs, b, B, group, badgroup2, ctx);
  add_to_vector(xs, partial_xs, rn, ctx);

  partial_xs.clear();
  ecdh_subgroup_attack(partial_xs, b, B, group, badgroup3, ctx);
  add_to_vector(xs, partial_xs, rn, ctx);

  // Use the Chinese Remainder Theorem to find x
  if (!(xguess = BN_new()))
    goto err;
  
  BN_zero(xguess);
  
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
      
      if (!BN_add(xguess, xguess, xi))
	goto err;

      BN_free(rnmodinv);
    }
  }

  if (!BN_mod(xguess, xguess, rn, ctx))
    goto err;

  if (BN_cmp(xguess, b) == 0) {
    cout << "Success! b = " << BN_bn2dec(xguess) << endl;
  } else {
    cout << "Fail! b != " << BN_bn2dec(xguess) << endl;
  }
  
 err:
  if (a) BN_free(a);
  if (b) BN_free(b);
  if (x1) BN_free(x1);
  if (x2) BN_free(x2);
  if (rn) BN_free(rn);
  if (xi) BN_free(xi);
  if (xguess) BN_free(xguess);
  if (rnoverr) BN_free(rnoverr);
  if (ctx) BN_CTX_free(ctx);
  for (int i = 0; i < xs.size(); i++) {
    if (xs[i].first) BN_free(xs[i].first);
    if (xs[i].second) BN_free(xs[i].second);
  }
  
  return 0;
}
