#ifndef EC_H
#define EC_H

#include <openssl/bn.h>

class ECPoint {
  BIGNUM *x;
  BIGNUM *y;

 public:
  ECPoint(const BIGNUM *_x, const BIGNUM *_y) {
    x = BN_dup(_x);
    y = BN_dup(_y);
  }
  ECPoint() {
    x = NULL;
    y = NULL;
  }
  ECPoint(const char *_x, const char *_y) {
    x = BN_new();
    y = BN_new();
    BN_dec2bn(&x, _x);
    BN_dec2bn(&y, _y);
  }
  ECPoint(const ECPoint &obj) {
    x = BN_dup(obj.x);
    y = BN_dup(obj.y);
  }
  ECPoint& operator=(const ECPoint &other) {
    if (this == &other)
      return *this;

    if (x) BN_free(x);
    if (y) BN_free(y);
    x = BN_dup(other.x);
    y = BN_dup(other.y);
 
    return *this;
  }
  ~ECPoint() {
    if (x) BN_free(x);
    if (y) BN_free(y);
  }
  friend std::ostream& operator<<(std::ostream &out, const ECPoint &point);
  void setx(const BIGNUM *_x) {
    if (x) BN_free(x);
    x = BN_dup(_x);
  }
  BIGNUM *getx() const {
    return x;
  }
  void sety(const BIGNUM *_y) {
    if (y) BN_free(y);
    y = BN_dup(_y);
  }
  BIGNUM *gety() const {
    return y;
  }
};

struct ECGroup {
  BIGNUM *a;
  BIGNUM *b;
  BIGNUM *p;
  ECPoint infinity;
  ECPoint G;
  BIGNUM *n;
  BIGNUM *h;
  BIGNUM *q;

  ECGroup(const char *_a, const char *_b, const char *_p, const ECPoint &_G, const char *_n, const char *_h, const char *_q) {
    a = BN_new();
    b = BN_new();
    p = BN_new();
    BN_dec2bn(&a, _a);
    BN_dec2bn(&b, _b);
    BN_dec2bn(&p, _p);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BN_zero(x);
    BN_one(y);
    infinity.setx(x);
    infinity.sety(y);
    G = _G;
    n = BN_new();
    h = BN_new();
    BN_dec2bn(&n, _n);
    BN_dec2bn(&h, _h);
    BN_dec2bn(&q, _q);
  }
  ~ECGroup() {
    if (a) BN_free(a);
    if (b) BN_free(b);
    if (p) BN_free(p);
    if (n) BN_free(n);
    if (h) BN_free(h);
    if (q) BN_free(q);
  }
};

int EC_add(ECPoint &ret, const ECPoint &a, const ECPoint &b, const ECGroup &group, BN_CTX *ctx);

int EC_scale(ECPoint &ret, const ECPoint &x, const BIGNUM *k, const ECGroup &group, BN_CTX *ctx);

bool EC_is_infinity(const ECPoint &point, const ECGroup &group);

#endif
