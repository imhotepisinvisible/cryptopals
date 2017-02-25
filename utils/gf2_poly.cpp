#include <gmp.h>
#include <gmpxx.h>

#include "gf2_poly.h"
#include "utils.h"

using namespace std;

mpz_class block2fieldel(const unsigned char *block) {
  mpz_class ret(0);
  for (int i = 15; i >= 0; i--) {
    ret <<= 8;
    ret |= reverse(block[i]);
  }

  return ret;
}

unsigned char *fieldel2block(mpz_class el) {
  unsigned char *ret = new unsigned char[16];
  mpz_class tmp(0);

  for (int i = 0; i < 16; i++) {
    tmp = el & 0xff;
    ret[i] = reverse(tmp.get_ui());
    el >>= 8;
  }
  
  return ret;
}

vector<uint8_t> fieldel2vector(const mpz_class &el) {
  vector<uint8_t> ret(128);
  
  for (int i = 0; i < 128; i++) {
    ret[i] = mpz_tstbit(el.get_mpz_t(), i);
  }

  return ret;
}

mpz_class vector2fieldel(const vector<uint8_t> &vec) {
  mpz_class ret;

  for (int i = 0; i < vec.size(); i++) {
    if (vec[i]) {
      mpz_setbit(ret.get_mpz_t(), i);
    }
  }
  
  return ret;
}

mpz_class gf2_add(const mpz_class &a, const mpz_class &b) {
  return a ^ b;
}

mpz_class gf2_sub(const mpz_class &a, const mpz_class &b) {
  return gf2_add(a, b);
}

/*
 * function mul(a, b):
 *       p := 0
 *
 *       while a > 0:
 *           if a & 1:
 *               p := p ^ b
 *
 *           a := a >> 1
 *           b := b << 1
 *
 *       return p
 */
mpz_class gf2_mul(mpz_class a, mpz_class b) {
  mpz_class p(0);

  while (a > 0) {
    if ((a & 1) != 0) {
      p ^= b;
    }

    a = a >> 1;
    b = b << 1;
  }

  return p;
}

/*
 * deg(a) is a function returning the degree of a polynomial. For the
 * polynomial x^4 + x + 1, it should return 4. For 1, it should return
 * 0. For 0, it should return some negative value.
 */
int gf2_deg(const mpz_class &a) {
  if (a == 0) {
    return -1;
  } else {
    return mpz_sizeinbase(a.get_mpz_t(), 2) - 1;
  }
}

/*
 * function divmod(a, b):
 *     q, r := 0, a
 *
 *     while deg(r) >= deg(b):
 *         d := deg(r) - deg(b)
 *         q := q ^ (1 << d)
 *         r := r ^ (b << d)
 *
 *     return q, r
 */
pair<mpz_class, mpz_class> gf2_divmod(const mpz_class &a, const mpz_class &b) {
  mpz_class q(0);
  mpz_class r(a);

  int d;
  mpz_class one(1);

  while (gf2_deg(r) >= gf2_deg(b)) {
    d = gf2_deg(r) - gf2_deg(b);
    q = q ^ (one << d);
    r = r ^ (b << d);
  }

  pair<mpz_class, mpz_class> ret(q, r);
  return ret;
}

/*
 *  function modmul(a, b, m):
 *      p := mul(a, b)
 *      q, r := divmod(p, m)
 *      return r
 */
mpz_class gf2_naive_modmul(const mpz_class &a, const mpz_class &b, const mpz_class &m) {
  mpz_class p = gf2_mul(a, b);
  pair<mpz_class, mpz_class> divmod = gf2_divmod(p, m);
  return divmod.second;
}

/*
 *  function modmul(a, b, m):
 *      p := 0
 *
 *      while a > 0:
 *          if a & 1:
 *              p := p ^ b
 *
 *          a := a >> 1
 *          b := b << 1
 *
 *          if deg(b) = deg(m):
 *              b := b ^ m
 *
 *      return p
 */
mpz_class gf2_modmul(mpz_class a, mpz_class b, const mpz_class &m) {
  mpz_class p(0);

  while (a > 0) {
    if ((a & 1) != 0) {
      p = p ^ b;
    }

    a = a >> 1;
    b = b << 1;

    if (gf2_deg(b) == gf2_deg(m)) {
      b = b ^ m;
    }
  }

  return p;
}

pair<mpz_class, mpz_class> gf2_egcd(const mpz_class &a, const mpz_class &b) {
  mpz_class s(0);
  mpz_class sprev(1);
  
  mpz_class r(b);
  mpz_class rprev(a);
  
  mpz_class tmp;
  pair<mpz_class, mpz_class> divmod;
  while (gf2_deg(r) != -1) {
    divmod = gf2_divmod(rprev, r);

    tmp = r;
    r = gf2_mul(divmod.first, r);
    r = gf2_sub(rprev, r);
    rprev = tmp;

    tmp = s;
    s = gf2_mul(divmod.first, s);
    s = gf2_sub(sprev, s);
    sprev = tmp;
  }

  pair<mpz_class, mpz_class> ret(rprev, sprev);
  return ret;
}

mpz_class gf2_modinv(const mpz_class &a, const mpz_class &m) {
  pair<mpz_class, mpz_class> egcd = gf2_egcd(a, m);
  if (egcd.first == 1) {
    return egcd.second;
  } else {
    return -1;
  }
}

mpz_class gf2_modexp(mpz_class a, mpz_class p, const mpz_class &m) {
  mpz_class ret(1);
  while (p > 0) {
    if ((p % 2) == 1) {
      ret = gf2_modmul(ret, a, m);
    }

    a = gf2_modmul(a, a, m);

    p = p >> 1;
  }

  pair<mpz_class, mpz_class> divmod;
  divmod = gf2_divmod(ret, m);

  return divmod.second;
}
