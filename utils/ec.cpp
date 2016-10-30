#include <iostream>

#include "ec.h"
#include "crypto.h"

/*    invert((x, y)) = (x, -y) = (x, p-y)
 */
int EC_invert(ECPoint &ret, const ECPoint &point, const ECGroup &group) {
  ret.setx(point.getx());
  BIGNUM *y = BN_new();
  BN_sub(y, group.p, point.gety());
  ret.sety(y);
  
  return 1;
}

bool EC_equals(const ECPoint &a, const ECPoint &b) {
  return (BN_cmp(a.getx(), b.getx()) == 0 && BN_cmp(a.gety(), b.gety()) == 0);
}

bool EC_is_infinity(const ECPoint &point, const ECGroup &group) {
  return EC_equals(point, group.infinity);
}

/*    function add(P1, P2):
 *        if P1 = O:
 *            return P2
 *
 *        if P2 = O:
 *            return P1
 *
 *        if P1 = invert(P2):
 *            return O
 *
 *        x1, y1 := P1
 *        x2, y2 := P2
 *
 *        if P1 = P2:
 *            m := (3*x1^2 + a) / 2*y1
 *        else:
 *            m := (y2 - y1) / (x2 - x1)
 *
 *        x3 := m^2 - x1 - x2
 *        y3 := m*(x1 - x3) - y1
 *
 *       return (x3, y3)
 */
int EC_add(ECPoint &ret, const ECPoint &a, const ECPoint &b, const ECGroup &group, BN_CTX *ctx) {
  int rc = 0;
  BN_CTX_start(ctx);

  BIGNUM *m = NULL;
  BIGNUM *two = NULL;
  BIGNUM *three = NULL;
  BIGNUM *x3 = NULL;
  BIGNUM *y3 = NULL;
  BIGNUM *x123a = NULL;
  BIGNUM *y12 = NULL;
  BIGNUM *y2y1 = NULL;
  BIGNUM *x2x1 = NULL;
  ECPoint invert_b;
  EC_invert(invert_b, b, group);
  
  if (EC_is_infinity(a, group)) {
    ret = b;
  } else if (EC_is_infinity(b, group)) {
    ret = a;
  } else if (EC_equals(a, invert_b)) {
    ret = group.infinity;
  } else {
    m = BN_CTX_get(ctx);
    two = BN_CTX_get(ctx);
    three = BN_CTX_get(ctx);
    x3 = BN_CTX_get(ctx);
    y3 = BN_CTX_get(ctx);
    
    if (!BN_set_word(two, 2))
      goto err;
    
    if (!BN_set_word(three, 3))
      goto err;
    
    if (EC_equals(a, b)) {
      x123a = BN_CTX_get(ctx);
      y12 = BN_CTX_get(ctx);

      if (!BN_exp(x123a, a.getx(), two, ctx))
	goto err;
      
      if (!BN_mul(x123a, three, x123a, ctx))
	goto err;
      
      if (!BN_add(x123a, x123a, group.a))
	goto err;

      if (!BN_mul(y12, two, a.gety(), ctx))
	goto err;

      if (!(y12 = modinv(y12, group.p, ctx)))
	goto err;
      
      if (!BN_mul(m, x123a, y12, ctx))
	goto err;
    } else {
      y2y1 = BN_CTX_get(ctx);
      x2x1 = BN_CTX_get(ctx);
      
      if (!BN_mod_sub(y2y1, b.gety(), a.gety(), group.p, ctx))
	goto err;
      
      if (!BN_mod_sub(x2x1, b.getx(), a.getx(), group.p, ctx))
	goto err;
      
      if (!(x2x1 = modinv(x2x1, group.p, ctx)))
	goto err;
      if (!BN_mul(m, y2y1, x2x1, ctx))
	goto err;
    }

    if (!BN_exp(x3, m, two, ctx))
      goto err;
    
    if (!BN_sub(x3, x3, a.getx()))
      goto err;
    
    if (!BN_sub(x3, x3, b.getx()))
      goto err;

    if (!BN_sub(y3, a.getx(), x3))
      goto err;
    
    if (!BN_mul(y3, m, y3, ctx))
      goto err;
    
    if (!BN_sub(y3, y3, a.gety()))
      goto err;

    // todo review this
    if (!BN_nnmod(x3, x3, group.p, ctx))
      goto err;
    
    if (!BN_nnmod(y3, y3, group.p, ctx))
      goto err;

    ret.setx(x3);
    ret.sety(y3);
  }
  rc = 1;

 err:
  if (y12) BN_free(y12);
  BN_CTX_end(ctx);
  return rc;
}

/*   function scale(x, k):
 *       result := identity
 *       while k > 0:
 *           if odd(k):
 *               result := combine(result, x)
 *           x := combine(x, x)
 *           k := k >> 1
 *       return result
 */
int EC_scale(ECPoint &ret, const ECPoint &x, const BIGNUM *k, const ECGroup &group, BN_CTX *ctx) {
  int rc = 0;
  BN_CTX_start(ctx);
  BIGNUM *kk = BN_CTX_get(ctx);
  ECPoint xx = x;

  if (!BN_copy(kk, k))
    goto err;  
  
  ret = group.infinity;
  while (!BN_is_zero(kk)) {
    BIGNUM *rem = BN_CTX_get(ctx);
    BIGNUM *two = BN_CTX_get(ctx);

    if (!BN_set_word(two, 2))
      goto err;
    
    if (!BN_mod(rem, kk, two, ctx))
      goto err;
    
    if (!BN_is_zero(rem)) {
      if (!EC_add(ret, ret, xx, group, ctx))
	goto err;
    }
    
    if (!EC_add(xx, xx, xx, group, ctx))
      goto err;
    
    if (!BN_rshift1(kk, kk))
      goto err;
  }
  rc = 1;

 err:
  BN_CTX_end(ctx);
  return rc;
}

std::ostream& operator<<(std::ostream &out, const ECPoint &point)
{
  out << "(" << BN_bn2dec(point.x) << ", " << BN_bn2dec(point.y) << ")";
 
  return out;
}
