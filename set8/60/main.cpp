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

bool square_in_group(BIGNUM *u, const ECGroup &group, BN_CTX *ctx) {
  BN_CTX_start(ctx);
  bool ret = true;

  BIGNUM *v2 = BN_CTX_get(ctx);
  BIGNUM *u3 = BN_CTX_get(ctx);
  BIGNUM *au2 = BN_CTX_get(ctx);
  BIGNUM *three = BN_CTX_get(ctx);
  BIGNUM *two = BN_CTX_get(ctx);
  BIGNUM *pminus1over2 = BN_CTX_get(ctx);
  BIGNUM *pminus1 = BN_CTX_get(ctx);
  BIGNUM *l = BN_CTX_get(ctx);

  if (!l)
    goto err;

  // verify that u^3 + A*u^2 + u is a nonsquare in GF(p)
  // Calculate v^2
  if (!BN_set_word(three, 3))
    goto err;
  
  if (!BN_set_word(two, 2))
    goto err;

  if (!BN_mod_exp(u3, u, three, group.p, ctx))
    goto err;

  if (!BN_mod_exp(au2, u, two, group.p, ctx))
    goto err;

  if (!BN_mod_mul(au2, group.a, au2, group.p, ctx))
    goto err;

  if (!BN_add(v2, u3, au2))
    goto err;
  
  if (!BN_add(v2, v2, u))
    goto err;
  
  if (!BN_nnmod(v2, v2, group.p, ctx))
    goto err;

  // Return true if v^2 is a quadratic residue (mod p),
  // meaning that the Legendre symbol ( n/p )=1
  // else return false
  if (!BN_sub(pminus1, group.p, BN_value_one()))
    goto err;
  
  if (!BN_sub(pminus1over2, group.p, BN_value_one()))
    goto err;
  
  if (!BN_div(pminus1over2, NULL, pminus1over2, two, ctx))
    goto err;

  if (!BN_mod_exp(l, v2, pminus1over2, group.p, ctx))
    goto err;
  
  if (BN_cmp(l, BN_value_one()) != 0) {
    ret = false;
  }

 err:
  BN_CTX_end(ctx);
  return ret;
}

int ecdh_montgomery_subgroup_attack(vector< pair<pair<BIGNUM*, BIGNUM*>, BIGNUM*> > &xs, const BIGNUM *b, const ECGroup &group, const ECGroup &badgroup, BN_CTX *ctx) {
  BN_CTX_start(ctx);
  unsigned char *K_bin = NULL;
  unsigned char *test_K_bin = NULL;
  unsigned char *hmac = NULL;
  unsigned char *found_hmac = NULL;
  BIGNUM *K = BN_CTX_get(ctx);
  BIGNUM *test_K = BN_CTX_get(ctx);
  BIGNUM *h = BN_CTX_get(ctx);
  BIGNUM *i_bn = NULL;
  BIGNUM *negi_bn = NULL;
  BIGNUM *rn = BN_CTX_get(ctx);
  BIGNUM *rem = BN_CTX_get(ctx);
  BIGNUM *qoverr = NULL;
  BIGNUM *pminus1 = BN_CTX_get(ctx);
  BIGNUM *gcd = BN_CTX_get(ctx);
  BIGNUM *xx = BN_CTX_get(ctx);
  BIGNUM *yy = BN_CTX_get(ctx);
  BIGNUM *element = BN_CTX_get(ctx);
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
  for (int i = 3; i <= 0x1000000; i++) {
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

  cout << "Factors: ";
  for (int i = 0; i < factors.size(); i++) {
    cout << BN_bn2dec(factors[i]) << " ";
  }
  cout << endl;
  
  if (!BN_sub(pminus1, group.p, BN_value_one()))
    goto err;

  do {
    factor++;

    cout << "Trying factor r: " << BN_bn2dec(factors[factor]) << endl;

    // h := random point from the bad curve
    do {
      if (!BN_rand_range(h, group.p))
	goto err;
	
      // verify that u^3 + A*u^2 + u is a nonsquare in GF(p)t

    } while (square_in_group(h, group, ctx));

    // Multiply by q/r
    qoverr = modinv(factors[factor], group.p, ctx);

    if (!BN_mod_mul(qoverr, badgroup.q, qoverr, group.p, ctx))
      goto err;

    if (!EC_mont_ladder(element, h, qoverr, group, ctx))
      goto err;

    // Bob calcs K
    if (!EC_mont_ladder(K, element, b, group, ctx))
      goto err;

    K_bin = new unsigned char[BN_num_bytes(K)];
    BN_bn2bin(K, K_bin);

    hmac = new unsigned char[SHA256_HASH_LEN];
    hmac = HMAC(EVP_sha256(), K_bin, BN_num_bytes(K), (unsigned char *)msg, strlen(msg), hmac, &md_len);

    // Recover K
    r = BN_get_word(factors[factor]);
    found_hmac = new unsigned char[SHA256_HASH_LEN];
    for (int i = 1; i <= r; i++) {
      if (i % 100000 == 0) {
	cout << i << endl;
      }
      if (!(i_bn = BN_new()))
	goto err;
      
      if (!BN_set_word(i_bn, i))
	goto err;

      if (!EC_mont_ladder(test_K, element, i_bn, badgroup, ctx))
	goto err;

      test_K_bin = new unsigned char[BN_num_bytes(test_K)];
      BN_bn2bin(test_K, test_K_bin);

      found_hmac = HMAC(EVP_sha256(), test_K_bin, BN_num_bytes(test_K), (unsigned char *)msg, strlen(msg), found_hmac, &md_len);
    
      if (memcmp(hmac, found_hmac, md_len) == 0) {
	negi_bn = BN_dup(i_bn);
	BN_set_negative(negi_bn, 1);
	BN_nnmod(negi_bn, negi_bn, factors[factor], ctx);

	pair<BIGNUM*,BIGNUM*> is(i_bn, negi_bn);
	pair<pair<BIGNUM*,BIGNUM*>,BIGNUM*> br(is, factors[factor]);
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

/*
 * Recursive function to turn our vector of pairs of possibilities into
 * the 2^n vectors of possibilities
 */
void combinatorial_explosion(vector< pair<pair<BIGNUM*,BIGNUM*>,BIGNUM*> >::const_iterator it, vector< pair<pair<BIGNUM*,BIGNUM*>,BIGNUM*> >::const_iterator end, vector< pair<BIGNUM*,BIGNUM*> > explosion, vector< vector< pair<BIGNUM*,BIGNUM*> > > &explosions, BN_CTX *ctx) {

  if (it == end) {
    explosions.push_back(explosion);
    return;
  }

  pair<BIGNUM*,BIGNUM*> one(it->first.first, it->second);
  explosion.push_back(one);
  combinatorial_explosion(++it, end, explosion, explosions, ctx);
  --it;

  pair<BIGNUM*,BIGNUM*> two(it->first.second, it->second);
  explosion.pop_back();
  explosion.push_back(two);
  combinatorial_explosion(++it, end, explosion, explosions, ctx);

  return;
}

/*
 * We narrow the combinatorial explosion by sending Bob an h
 * in the range of rn.  We then test which of our possible xs
 * could have produced it, narrowing the number of possibilities
 * to 2
 */
vector<BIGNUM *> narrow_range(const vector<BIGNUM *> &xs, const BIGNUM *rn, const BIGNUM *b, const ECGroup &group, const ECGroup &badgroup, BN_CTX *ctx) {
  BN_CTX_start(ctx);
  unsigned char *K_bin = NULL;
  unsigned char *test_K_bin = NULL;
  unsigned char *hmac = NULL;
  unsigned char *found_hmac = NULL;
  BIGNUM *K = BN_CTX_get(ctx);
  BIGNUM *test_K = BN_CTX_get(ctx);
  BIGNUM *h = BN_CTX_get(ctx);
  BIGNUM *qoverr = NULL;
  BIGNUM *element = BN_CTX_get(ctx);
  uint32_t md_len = 0;
  vector<BIGNUM *> ret;
  const char *msg = "crazy flamboyant for the rap enjoyment";
  
  // h := random point from the bad curve
  do {
    if (!BN_rand_range(h, group.p))
      goto err;
	
    // verify that u^3 + A*u^2 + u is a nonsquare in GF(p)t

  } while (square_in_group(h, group, ctx));

  // Multiply by q/r
  qoverr = modinv(rn, group.p, ctx);

  if (!BN_mod_mul(qoverr, badgroup.q, qoverr, group.p, ctx))
    goto err;

  if (!EC_mont_ladder(element, h, qoverr, group, ctx))
    goto err;

  // Bob calcs K
  if (!EC_mont_ladder(K, element, b, group, ctx))
    goto err;

  K_bin = new unsigned char[BN_num_bytes(K)];
  BN_bn2bin(K, K_bin);

  hmac = new unsigned char[SHA256_HASH_LEN];
  hmac = HMAC(EVP_sha256(), K_bin, BN_num_bytes(K), (unsigned char *)msg, strlen(msg), hmac, &md_len);

  // Recover K
  found_hmac = new unsigned char[SHA256_HASH_LEN];
  for (int i = 0; i < xs.size(); i++) {
    if (!EC_mont_ladder(test_K, element, xs[i], badgroup, ctx))
      goto err;

    test_K_bin = new unsigned char[BN_num_bytes(test_K)];
    BN_bn2bin(test_K, test_K_bin);

    found_hmac = HMAC(EVP_sha256(), test_K_bin, BN_num_bytes(test_K), (unsigned char *)msg, strlen(msg), found_hmac, &md_len);
    
    if (memcmp(hmac, found_hmac, md_len) == 0) {
      ret.push_back(xs[i]);
    }
  }

 err:
  BN_CTX_end(ctx);
  
  return ret;
}

//f(y) = 2^(y mod k)
void f(BIGNUM *fy, const ECPoint y, const int _k, BN_CTX *ctx) {
  BN_CTX_start(ctx);
  
  BIGNUM *k = NULL;

  BIGNUM *two = NULL;

  if (!(k = BN_CTX_get(ctx)))
    goto err;

  if (!(two = BN_CTX_get(ctx)))
    goto err;
  
  if (!BN_set_word(k, _k))
    goto err;
  
  if (!BN_set_word(two, 2))
    goto err;
  
  if (!BN_mod(fy, y.getx(), k, ctx))
    goto err;
  
  if (!BN_exp(fy, two, fy, ctx))
    goto err;

 err:
  BN_CTX_end(ctx);
}

uint64_t fmean(const int k) {
  uint64_t total = 0;
  for (int i = 0; i < k; i++) {
    total += pow(2, i);
  }
  total /= k;
  total *= 4; // because cryptopals
  return total;
}

/*
 * NOTE: for the 2^40 ish range we have to calculate here, this is
 * *very* slow
 */
int ec_kangaroo(BIGNUM *index, const ECPoint &y, const BIGNUM *b, const ECPoint &g, const ECGroup &group, BN_CTX *ctx) {
  BN_CTX_start(ctx);
  int ret = 0;
  BIGNUM *xT = BN_CTX_get(ctx);
  ECPoint yT;
  BIGNUM *fyT = BN_CTX_get(ctx);
  ECPoint gfyT;
  BIGNUM *xW = BN_CTX_get(ctx);
  ECPoint yW;
  BIGNUM *fyW = BN_CTX_get(ctx);
  ECPoint gfyW;
  BIGNUM *bxT = BN_CTX_get(ctx);
  int k = BN_num_bits(b)/2;
  
  // xT := 0
  // yT := g*b
  //
  // for i in 1..N:
  //     xT := xT + f(yT)
  //     yT := yT + g*f(yT)
  BN_zero(xT);

  if (!EC_scale(yT, g, b, group, ctx))
    goto err;
  
  for (size_t i = 0; i < fmean(k); i++) {
    f(fyT, yT, k, ctx);
    
    if (!BN_add(xT, xT, fyT))
      goto err;

    if (!EC_scale(gfyT, g, fyT, group, ctx))
      goto err;

    if (!EC_add(yT, yT, gfyT, group, ctx))
      goto err;
  }

  // xW := 0
  // yW := y
  //
  // while xW < b - a + xT:
  //     xW := xW + f(yW)
  //     yW := yW + g*f(yW)
  //
  //     if yW = yT:
  //         return b + xT - xW
  BN_zero(xW);
  
  yW.setx(y.getx());
  yW.sety(y.gety());
  
  if (!BN_add(bxT, b, xT))
    goto err;

  while (BN_cmp(xW, bxT) < 0) {
    f(fyW, yW, k, ctx);
    
    if (!BN_add(xW, xW, fyW))
      goto err;

    if (!EC_scale(gfyW, g, fyW, group, ctx))
      goto err;

    if (!EC_add(yW, yW, gfyW, group, ctx))
      goto err;
    
    if (EC_equals(yW, yT)) {
      if (!BN_sub(index, bxT, xW))
	goto err;
      
      ret = 1;
      break;
    }
  }

 err:
  BN_CTX_end(ctx);

  return ret;
}

int main() {
  ECPoint base("4", "85518893674295321206118380980485522083");
  ECGroup group("534", "1", "233970423115425145524320034830162017933", base, "29246302889428143187362802287225875743", "8", "233970423115425145498902418297807005944");
  ECGroup badgroup("534", "1", "233970423115425145524320034830162017933", base, "29246302889428143187362802287225875743", "8", "1");

  // The same curve in Weierstrass form
  ECPoint wbase("182", "85518893674295321206118380980485522083");
  ECGroup wgroup("-95051", "11279326", "233970423115425145524320034830162017933", wbase, "29246302889428143187362802287225875743", "8", "233970423115425145498902418297807005944");

  BN_CTX *ctx = NULL;
  BIGNUM *test = NULL;
  BIGNUM *weird1 = NULL;
  BIGNUM *weird2 = NULL;
  BIGNUM *twistq = NULL;
  BIGNUM *two = NULL;

  BIGNUM *b = NULL;
  BIGNUM *B = NULL;
  ECPoint Bw;
  BIGNUM *rn = NULL;
  BIGNUM *xi = NULL;
  BIGNUM *xguess = NULL;
  BIGNUM *rnoverr = NULL;
  BIGNUM *rnmodinv = NULL;
  vector< pair<pair<BIGNUM*, BIGNUM*>, BIGNUM*> > xs;

  vector< vector< pair<BIGNUM*,BIGNUM*> > > explosions; // todo free
  vector< pair<BIGNUM*,BIGNUM*> > e;
  vector<BIGNUM *> xguesses;
  vector<BIGNUM *> narrowxguesses;

  BIGNUM *index = NULL;
  ECPoint yprime;
  ECPoint gprime;
  BIGNUM *bound = NULL;
  BIGNUM *x = NULL;

  if (!(test = BN_new()))
    goto err;

  if (!(ctx = BN_CTX_new()))
    goto err;

  // Verify G*n = 0
  if (!EC_mont_ladder(test, group.G.getx(), group.n, group, ctx))
    goto err;

  cout << "G*n: " << BN_bn2dec(test) << endl;

  // ladder(76600469441198017145391791613091732004, 11)
  if (!(weird1 = BN_new()))
    goto err;

  if (!(weird2 = BN_new()))
    goto err;
  
  if (!BN_dec2bn(&weird1, "76600469441198017145391791613091732004"))
    goto err;
  
  if (!BN_dec2bn(&weird2, "11"))
    goto err;
  
  if (!EC_mont_ladder(test, weird1, weird2, group, ctx))
    goto err;

  cout << "ladder(76600469441198017145391791613091732004, 11): " << BN_bn2dec(test) << endl;

  // twistq = (2*p + 2) - q
  if (!(twistq = BN_new()))
    goto err;

  if (!(two = BN_new()))
    goto err;

  if (!BN_set_word(two, 2))
    goto err;

  if (!BN_mul(twistq, two, group.p, ctx))
    goto err;
  
  if (!BN_add(twistq, twistq, two))
    goto err;
  
  if (!BN_sub(twistq, twistq, group.q))
    goto err;
  
  if (!BN_copy(badgroup.q, twistq))
    goto err;

  cout << "twistq " << BN_bn2dec(twistq) << endl;

  // Generate Bob's keys
  if (!(b = BN_new()))
    goto err;

  if (!BN_rand_range(b, group.n))
    goto err;

  if (!(B = BN_new()))
    goto err;
  
  if (!EC_mont_ladder(B, group.G.getx(), b, group, ctx))
    goto err;

  // NOTE: normally we would not have B in Weierstrass form, but calculate it
  // here for ease, and to avoid having to kangaroo for the +/- y options
  // after converting the Montgomery u
  if (!EC_scale(Bw, wgroup.G, b, wgroup, ctx))
    goto err;

  ecdh_montgomery_subgroup_attack(xs, b, group, badgroup, ctx);

  combinatorial_explosion(xs.begin(), xs.end(), e, explosions, ctx);
  
  cout << explosions.size() << " possibilities for x found" << endl;

  for (int i = 0; i < explosions.size(); i++) {
    // Use the Chinese Remainder Theorem to find x
    if (!(rn = BN_new()))
      goto err;

    if (!BN_set_word(rn, 1))
      goto err;
  
    for (int j = 0; j < explosions[i].size(); j++) {
      BN_mul(rn, rn, explosions[i][j].second, ctx);
    }
  
    if (!(xguess = BN_new()))
      goto err;
  
    BN_zero(xguess);
  
    if (!(xi = BN_new()))
      goto err;
  
    if (!(rnoverr = BN_new()))
      goto err;
  
    for (int j = 0; j < explosions[i].size(); j++) {
      if (!BN_div(rnoverr, NULL, rn, explosions[i][j].second, ctx))
	goto err;

      rnmodinv = modinv(rnoverr, explosions[i][j].second, ctx);

      if (rnmodinv) {
	if (!BN_mul(xi, explosions[i][j].first, rnoverr, ctx))
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

    xguesses.push_back(xguess);
  }

  narrowxguesses = narrow_range(xguesses, rn, b, group, badgroup, ctx);
  
  cout << "After narrowing, " << narrowxguesses.size() << " possibilities for x found" << endl;

  for (int i = 0; i < narrowxguesses.size(); i++) {
    if (BN_cmp(narrowxguesses[i], b) == 0) {
      cout << "Success! b = " << BN_bn2dec(narrowxguesses[i]) << endl;
      break;
    } else {
      cout << "b (" << BN_bn2dec(narrowxguesses[i]) << ") is too small, trying kangaroo" << endl;

      // Begin kangaroo: note we have to use the Weierstrass operations
      // as addition is required.

      // y' = y + g*-n = g*(m+r)
      if (!(index = BN_new()))
	  goto err;
    
      if (!EC_invert(yprime, wgroup.G, wgroup))
	goto err;
    
      if (!EC_scale(yprime, yprime, narrowxguesses[i], wgroup, ctx))
	goto err;

      if (!EC_add(yprime, Bw, yprime, wgroup, ctx))
	goto err;

      // g' = g*r
      if (!EC_scale(gprime, wgroup.G, rn, wgroup, ctx))
	goto err;

      // bound = (q-1)/r
      if (!(bound = BN_new()))
	goto err;

      if (!BN_sub(bound, wgroup.q, BN_value_one()))
	goto err;
    
      if (!BN_div(bound, NULL, bound, rn, ctx))
	goto err;

      if (ec_kangaroo(index, yprime, bound, gprime, wgroup, ctx)) {
	cout << "Index found: " << BN_bn2dec(index) << endl;

	if (!(x = BN_new()))
	  goto err;
      
	// x = n + m*r
	if (!BN_mod_mul(x, index, rn, wgroup.p, ctx))
	  goto err;
      
	if(!BN_mod_add(x, narrowxguesses[i], x, wgroup.p, ctx))
	  goto err;
      
	if (BN_cmp(x, b) == 0) {
	  cout << "Success! b = " << BN_bn2hex(x) << endl;
	  break;
	} else {
	  cout << "Error, x calculated as" << endl
	       << BN_bn2hex(x) << endl
	       << "but b was" << endl
	       << BN_bn2hex(b) << endl;
	}
      } else {
	cout << "Error finding index" << endl;
      }
    }
  }
  
 err:
  if (test) BN_free(test);
  if (weird1) BN_free(weird1);
  if (weird2) BN_free(weird2);
  if (twistq) BN_free(twistq);
  if (two) BN_free(two);
  if (b) BN_free(b);
  if (B) BN_free(B);
  if (rn) BN_free(rn);
  if (xi) BN_free(xi);
  if (xguess) BN_free(xguess);
  if (rnoverr) BN_free(rnoverr);
  if (rnmodinv) BN_free(rnmodinv);
  if (index) BN_free(index);
  if (bound) BN_free(bound);
  if (x) BN_free(x);
  for (int i = 0; i < xs.size(); i++) {
    if (xs[i].first.first) BN_free(xs[i].first.first);
    if (xs[i].first.second) BN_free(xs[i].first.second);
    if (xs[i].second) BN_free(xs[i].second);
  }
  for (int i = 0; i < xguesses.size(); i++) {
    if (xguesses[i]) BN_free(xguesses[i]);
  }
  if (ctx) BN_CTX_free(ctx);
  return 0;
}
