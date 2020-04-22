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

int EC_faulty_add(ECPoint &ret, const ECPoint &a, const ECPoint &b, const ECGroup &group, BN_CTX *ctx) {
  int rc = 0;
  BN_CTX_start(ctx);
  BIGNUM *r = BN_CTX_get(ctx);
  BIGNUM *m = BN_CTX_get(ctx);

  // fault probability
  if (!BN_dec2bn(&m, "10000000000"))
    goto err;

  if (!BN_is_zero(a.getx()) && !BN_is_zero(b.getx())) {
    if (!BN_mod_mul(r, a.getx(), b.getx(), m, ctx))
      goto err;

    // fault
    if (BN_is_zero(r)) {
      cout << "fault" << endl;
      goto err;
    }
  }

  rc = EC_add(ret, a, b, group, ctx);

  err:
    BN_CTX_end(ctx);
    return rc;
}

int EC_faulty_scale(ECPoint &ret, const ECPoint &x, const BIGNUM *k, const ECGroup &group, BN_CTX *ctx) {
  int rc = 0;
  BN_CTX_start(ctx);
  ret = x;

  for (int i = BN_num_bits(k)-2; i >= 0; i--) {
    if (!EC_faulty_add(ret, ret, ret, group, ctx))
	    goto err;

    if (BN_is_bit_set(k, i)) {
      if (!EC_faulty_add(ret, ret, x, group, ctx))
	      goto err;
    }
  }

  rc = 1;

 err:
  BN_CTX_end(ctx);
  return rc;
}

int recover_y(BIGNUM *y, const BIGNUM *x, const ECGroup &group, BN_CTX *ctx) {
  int rc = 0;
  BN_CTX_start(ctx);
  BIGNUM *y2 = BN_CTX_get(ctx);
  BIGNUM *e = BN_CTX_get(ctx);
  BIGNUM *three = BN_CTX_get(ctx);
  BIGNUM *four = BN_CTX_get(ctx);
  BIGNUM *rem = BN_CTX_get(ctx);

  if (!BN_set_word(three, 3))
    goto err;

  if (!BN_set_word(four, 4))
    goto err;

  if (!BN_mod_exp(y2, x, three, group.p, ctx))
    goto err;

  if (!BN_mod_mul(y2, y2, group.a, group.p, ctx))
    goto err;

  if (!BN_mod_add(y2, y2, group.b, group.p, ctx))
    goto err;

  if (!BN_add(e, group.p, BN_value_one()))
    goto err;

  if (!BN_div(e, rem, e, four, ctx))
    goto err;

  if (!BN_mod_exp(y, y2, e, group.p, ctx))
    goto err;

  rc = 1;

  err:
    BN_CTX_end(ctx);
    return rc;
}

int main() {
  ECPoint base("273770915446981874685590330989765981402", "244285256346570949856991741957354058269");
  ECGroup group("1", "5", "325480743399686552582045909638450429411", base, "65096148679937310511785088836221088090", "5", "325480743399686552558925444181105440450");

  ECPoint test;

  BN_CTX *ctx = NULL;
  BIGNUM *a = NULL;
  ECPoint A;
  BIGNUM *randomx = NULL;
  BIGNUM *randomy = NULL;
  ECPoint randomp;
  ECPoint randomadd;
  ECPoint randomscale;
  BIGNUM *flag = NULL;

  if (!(ctx = BN_CTX_new()))
    goto err;

  // Verify G*n = 0
  if (!EC_faulty_scale(test, group.G, group.n, group, ctx))
    goto err;

  cout << test << endl;

  // Generate Alice's keys
  if (!(a = BN_new()))
    goto err;

  if (!BN_rand_range(a, group.n))
   goto err;

  if (!EC_faulty_scale(A, group.G, a, group, ctx))
    goto err;

  // Generate random point
  if (!(randomx = BN_new()))
    goto err;

  if (!(randomy = BN_new()))
    goto err;

  if (!(flag = BN_new()))
    goto err;

  BN_one(flag);

  for (int i = 1; i < BN_num_bits(a); i++) {
    cout << "i " << i << endl;

    bool right = false;
    bool left = false;
    while (!right && !left) {
      if (!BN_rand_range(randomx, group.n))
        goto err;

      if (!recover_y(randomy, randomx, group, ctx))
        goto err;

      randomp.setx(randomx);
      randomp.sety(randomy);

      // Try addition
      if (!EC_faulty_add(randomadd, randomp, randomp, group, ctx))
        continue;

      // Don't even ask about coming up with this logic
      bool fault = false;
      for (int j = BN_num_bits(flag)-2; j >= 0; j--) {
        if (BN_is_bit_set(flag, j)) {
          if (!EC_faulty_add(randomadd, randomadd, randomp, group, ctx)) {
            fault = true;
            break;
          }
        }

        if (!EC_faulty_add(randomadd, randomadd, randomadd, group, ctx)) {
          fault = true;
          break;
        }
      }
      if (fault) continue;

      right = false;
      left = false;
      // now we try the fault - first left half
      if (!EC_faulty_add(randomscale, randomadd, randomadd, group, ctx)) {
        cout << "left" << endl;
        left = true;
      }

      // then right half
      if (!EC_faulty_add(randomscale, randomadd, randomp, group, ctx)) {
        cout << "right1" << endl;
        right = true;
      }

      // this one is probably overkill but increases our chance of getting a fault
      if (!EC_faulty_add(randomscale, randomscale, randomscale, group, ctx)) {
        cout << "right2" << endl;
        right = true;
      }
    }

    BN_lshift1(flag, flag);
    // query the oracle
    if (left) {
      if (!EC_faulty_scale(randomscale, randomp, a, group, ctx)) {
        cout << "fail, k[" << i << "] = 0 (probably)" << endl;
      } else {
        cout << "success, k[" << i << "] = 1" << endl;
        BN_set_bit(flag, 0);
      }
    } else if (right) {
      if (!EC_faulty_scale(randomscale, randomp, a, group, ctx)) {
        cout << "fail, k[" << i << "] = 1 (probably)" << endl;
        BN_set_bit(flag, 0);
      } else {
        cout << "success, k[" << i << "] = 0" << endl;
      }
    }
  }

  cout << "d " << BN_bn2hex(a) << endl;
  cout << "flag " << BN_bn2hex(flag) << endl;

 err:
  if (a) BN_free(a);
  if (randomx) BN_free(randomx);
  if (randomy) BN_free(randomy);
  if (flag) BN_free(flag);

  return 0;
}
