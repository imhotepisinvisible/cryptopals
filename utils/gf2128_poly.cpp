#include <set>
#include <cstdlib>

#include <gmp.h>
#include <gmpxx.h>

#include "gf2128_poly.h"
#include "gf2_poly.h"

using namespace std;

mappoly gf2128_makemonic(const mappoly &a) {
  mappoly ret;
  mpz_class m("0x100000000000000000000000000000087");

  mpz_class highest = a.rbegin()->second;
  mpz_class highestmodinv = gf2_modinv(highest, m);

  for (mappoly::const_iterator it=a.begin(); it!=a.end(); ++it) {
    ret[it->first] = gf2_modmul(it->second, highestmodinv, m);
  }

  return ret;
}

mappoly gf2128_add(const mappoly &a, const mappoly &b) {
  mappoly ret;
  mpz_class zero(0);

  set<int> bkeys;
  for (mappoly::const_iterator it=b.begin(); it!=b.end(); ++it) {
    bkeys.insert(it->first);
  }

  for (mappoly::const_iterator it=a.begin(); it!=a.end(); ++it) {
    if (bkeys.find(it->first) == bkeys.end()) {
      ret[it->first] = gf2_add(it->second, zero);
    } else {
      ret[it->first] = gf2_add(it->second, b.at(it->first));
      bkeys.erase(it->first);
    }
  }

  for (set<int>::iterator it=bkeys.begin(); it!=bkeys.end(); ++it) {
    ret[*it] = gf2_add(zero, b.at(*it));
  }

  // Remove zero coefficients
  for (mappoly::const_iterator it=ret.begin(); it!=ret.end(); /**/) {
    if (it->second == zero) {
      ret.erase(it++);
    } else {
      ++it;
    }
  }

  return ret;
}

mappoly gf2128_sub(const mappoly &a, const mappoly &b) {
  return gf2128_add(a, b);
}

mappoly gf2128_mul(const mappoly &a, const mappoly &b) {
  mappoly ret;
  mpz_class zero(0);
  mpz_class m("0x100000000000000000000000000000087");

  for (mappoly::const_iterator ait=a.begin(); ait!=a.end(); ++ait) {
    for (mappoly::const_iterator bit=b.begin(); bit!=b.end(); ++bit) {
      mpz_class ab = gf2_modmul(ait->second, bit->second, m);
      int idx = ait->first + bit->first;
      ret[idx] = gf2_add(ret[idx], ab); 
    }
  }

  // Remove zero coefficients
  for (mappoly::const_iterator it=ret.begin(); it!=ret.end(); /**/) {
    if (it->second == zero) {
      ret.erase(it++);
    } else {
      ++it;
    }
  }
  
  return ret;  
}

int gf2128_deg(const mappoly &a) {
  if (a.empty()) {
    return -1;
  } else {
    return a.rbegin()->first;
  }
}

pair<mappoly, mappoly> gf2128_divmod(const mappoly &a, const mappoly &b) {
  mappoly q;
  mappoly r = a;
  mpz_class m("0x100000000000000000000000000000087");

  int d;

  mappoly sb;

  while (gf2128_deg(r) >= gf2128_deg(b)) {
    d = gf2128_deg(r) - gf2128_deg(b);
    mpz_class bmodinv = gf2_modinv(b.rbegin()->second, m);
    mappoly s;
    s[d] = gf2_modmul(r.rbegin()->second, bmodinv, m);
    q = gf2128_add(q, s);
    sb = gf2128_mul(s, b);
    r = gf2128_sub(r, sb);
  }

  pair<mappoly, mappoly> ret(q, r);
  return ret;
}

mappoly gf2128_div(const mappoly &a, const mappoly &b) {
  mappoly ret;
  
  pair<mappoly, mappoly> divmod = gf2128_divmod(a, b);
  if (!divmod.second.empty()) {
    return ret;
  } else {
    return divmod.first;
  }
}

// Interleaved modmul feels fairly complicated, and using the naive
// modmul does not seem to affect performance too much
mappoly gf2128_modmul(const mappoly &a, const mappoly &b, const mappoly &m) {
  mappoly p = gf2128_mul(a, b);
  pair<mappoly, mappoly> divmod = gf2128_divmod(p, m);
  return divmod.second;
}

pair<mappoly, mappoly> gf2128_egcd(const mappoly &a, const mappoly &b) {
  mpz_class one(1);
  
  mappoly s;
  mappoly sprev;
  sprev[0] = one;
  mappoly r = b;
  mappoly rprev = a;

  mappoly tmp;
  pair<mappoly, mappoly> divmod;
  while (gf2128_deg(r) != -1) {
    divmod = gf2128_divmod(rprev, r);

    tmp = r;
    r = gf2128_mul(divmod.first, r);
    r = gf2128_sub(rprev, r);
    rprev = tmp;

    tmp = s;
    s = gf2128_mul(divmod.first, s);
    s = gf2128_sub(sprev, s);
    sprev = tmp;
  }

  pair<mappoly, mappoly> ret(rprev, sprev);
  return ret;
}

mappoly gf2128_modinv(const mappoly &a, const mappoly &m) {
  mpz_class gf2_one(1);
  mappoly one;
  one[0] = gf2_one;
  
  pair<mappoly, mappoly> egcd = gf2128_egcd(a, m);
  if (egcd.first == one) {
    return egcd.second;
  } else {
    return mappoly();
  }
}

mappoly gf2128_gcd(const mappoly &a, const mappoly &b) {
  pair<mappoly, mappoly> egcd = gf2128_egcd(a, b);
  return gf2128_makemonic(egcd.first);
}

mappoly gf2128_modexp(mappoly a, mpz_class p, const mappoly &m) {
  mappoly ret;
  mpz_class one(1);
  ret[0] = one;

  while (p > 0) {
    if ((p % 2) == 1) {
      ret = gf2128_modmul(ret, a, m);
    }

    a = gf2128_modmul(a, a, m);

    p = p >> 1;
  }

  pair<mappoly, mappoly> divmod = gf2128_divmod(ret, m);
  return divmod.second;
}

/*
 * if f(x) = x^r
 * then f'(x) = rx^(r-1)
 * When r = 0, this rule implies that f'(x) is zero for x != 0
 */
mappoly gf2128_derivative(const mappoly &a) {
  mappoly ret;

  for (mappoly::const_iterator it=a.begin(); it!=a.end(); ++it) {
    // scalar multiplication (hack for gf2 field...)
    if (it->first % 2 != 0) {
      ret[it->first-1] = it->second;
    }
  }
  
 return ret;
}

mappoly gf2128_divexp(const mappoly &a, const int p) {
  mappoly ret;

  for (mappoly::const_iterator it=a.begin(); it!=a.end(); ++it) {
    if (it->first % p != 0) {
      // error: clear and abort
      ret.clear();
      break;
    }
    ret[it->first/p] = it->second;
  }

  return ret;
}

mappoly gf2128_rand(const int d) {
  mappoly ret;

  gmp_randstate_t state;
  gmp_randinit_default(state);

  unsigned char randbuf[16];
  
  for (int i = 0; i < d; i++) {
    arc4random_buf(randbuf, 16);
    mpz_class rand = block2fieldel(randbuf);
    ret[i] = rand;
  }

  return ret;
}
