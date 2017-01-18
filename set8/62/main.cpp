#include <iostream>
#include <vector>

#include <gmp.h>
#include <gmpxx.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "ec.h"

using namespace std;

vector<mpq_class> add_vectors(const vector<mpq_class> &a, const vector<mpq_class> &b) {
  vector<mpq_class> ret;

  for (int i = 0; i < a.size(); i++) {
    mpq_class c = a[i] + b[i];
    ret.push_back(c);
  }

  return ret;
}

vector<mpq_class> sub_vectors(const vector<mpq_class> &a, const vector<mpq_class> &b) {
  vector<mpq_class> ret;

  for (int i = 0; i < a.size(); i++) {
    mpq_class c = a[i] - b[i];
    ret.push_back(c);
  }

  return ret;
}

mpq_class mult_vectors(const vector<mpq_class> &a, const vector<mpq_class> &b) {
  mpq_class ret;
  mpq_class c;

  for (int i = 0; i < a.size(); i++) {
    c = a[i] * b[i];
    ret += c;
  }

  return ret;
}

vector<mpq_class> scale_vector(const vector<mpq_class> &a, const mpq_class &b) {
  vector<mpq_class> ret;

  for (int i = 0; i < a.size(); i++) {
    mpq_class c = a[i] * b;
    ret.push_back(c);
  }

  return ret;
}

bool iszero(const vector<mpq_class> &u) {
  bool ret = true;
  
  for (int i = 0; i < u.size(); i++) {
    if (u[i] != 0) {
      ret = false;
      break;
    }
  }

  return ret;
}

vector<mpq_class> copy(const vector<mpq_class> &u) {
  vector<mpq_class> ret;
  
  for (int i = 0; i < u.size(); i++) {
    mpq_class a(u[i]);
    ret.push_back(a);
  }
  
  return ret;
}

vector< vector<mpq_class> > copycopy(const vector< vector<mpq_class> > &B) {
  vector< vector<mpq_class> > ret;
  
  for (int i = 0; i < B.size(); i++) {
    vector<mpq_class> a = copy(B[i]);
    ret.push_back(a);
  }
  
  return ret;
}

/* 
    function proj(u, v):
        if u = 0:
            return 0
        return ((v*u) / (u*u)) * u
*/
vector<mpq_class> proj(const vector<mpq_class> &u, const vector<mpq_class> &v) {
  if (iszero(u)) {
    return copy(u);
  }
  
  vector<mpq_class> ret;
  mpq_class scalar = mult_vectors(v, u) / mult_vectors(u, u);
  ret = scale_vector(u, scalar);

  return ret;
}

/*
    function gramschmidt(B):
        Q := []
        for i, v in enumerate(B):
            Q[i] := v - sum(proj(u, v) for u in Q[:i])
        return Q
*/
vector< vector<mpq_class> > gramschmidt(const vector< vector<mpq_class> > &B) {
  vector< vector<mpq_class> > Q;

  for (int i = 0; i < B.size(); i++) {
    vector<mpq_class> sumu;
    for (int j = 0; j < B[i].size(); j++) {
      mpq_class a(0);
      sumu.push_back(a);
    }
    
    for (int j = 0; j < i; j++) {
      vector<mpq_class> p;
      p = proj(Q[j], B[i]);
      sumu = add_vectors(p, sumu);
    }
    vector<mpq_class> Qi;
    Qi = sub_vectors(B[i], sumu);
    Q.push_back(Qi);
  }

  return Q;
}

/*
    function mu(i, j):
        v := B[i]
        u := Q[j]
        return (v*u) / (u*u)
*/
mpq_class mu(const vector< vector<mpq_class> > &B, const int i,
	     const vector< vector<mpq_class> > &Q, const int j) {
  mpq_class ret;

  ret = mult_vectors(B[i], Q[j]) / mult_vectors(Q[j], Q[j]);

  return ret;
}

/*
    function LLL(B, delta):
        B := copy(B)
        Q := gramschmidt(B)

        n := len(B)
        k := 1

        while k < n:
            for j in reverse(range(k)):
                if abs(mu(k, j)) > 1/2:
                    B[k] := B[k] - round(mu(k, j))*B[j]
                    Q := gramschmidt(B)

            if (Q[k]*Q[k]) >= (delta - mu(k, k-1)^2) * (Q[k-1]*Q[k-1]):
                k := k + 1
            else:
                B[k], B[k-1] := B[k-1], B[k]
                Q := gramschmidt(B)
                k := max(k-1, 1)

        return B
*/
vector< vector<mpq_class> > LLL(const vector< vector<mpq_class> > &B, const mpq_class &delta) {
  vector< vector<mpq_class> > ret = copycopy(B);
  vector< vector<mpq_class> > Q = gramschmidt(B);

  int n = B.size();
  int k = 1;

  mpq_class half(1, 2);

  mpq_class QkQk;
  mpq_class Qk1Qk1;
  while (k < n) {
    for (int j = k-1; j >= 0; j--) {
      mpq_class mukj = mu(ret, k, Q, j);
      if (abs(mukj) > half) {
	mpz_class a = mukj.get_num()*2 + mukj.get_den();
	mpz_class d = mukj.get_den()*2;
	mpz_class roundmukj;
	mpz_fdiv_q(roundmukj.get_mpz_t(), a.get_mpz_t(), d.get_mpz_t());
	vector<mpq_class> scaled = scale_vector(ret[j], roundmukj);
	ret[k] = sub_vectors(ret[k], scaled);
	Q = gramschmidt(ret);
      }
    }

    QkQk = mult_vectors(Q[k], Q[k]);
    Qk1Qk1 = mult_vectors(Q[k-1], Q[k-1]);
    mpq_class mukk1 = mu(ret, k, Q, k-1);
    if (QkQk >= (delta - mukk1*mukk1) * Qk1Qk1) {
      k++;
    } else {
      ret[k].swap(ret[k-1]);
      Q = gramschmidt(ret);
      k-1 > 1 ? k = k-1 : k = 1;
    }
  }

  return ret;
}

ECDSASig *ECDSA_biased_sign(const char *m, const BIGNUM *d, const ECGroup &group, BN_CTX *ctx) {
  BN_CTX_start(ctx);

  BIGNUM *k = BN_CTX_get(ctx);
  BIGNUM *Hm = BN_CTX_get(ctx);
  BIGNUM *dr = BN_CTX_get(ctx);
  BIGNUM *Hmdr = BN_CTX_get(ctx);
  BIGNUM *kmodinv = NULL;
  ECPoint r_xy;
  ECDSASig *sig = new ECDSASig;
  unsigned char hash[SHA256_HASH_LEN];

  if (!Hmdr)
    goto err;
  
  // k := random_scalar(1, n)
  if (!BN_rand_range(k, group.n))
    goto err;

  // nonce bias here
  BN_rshift(k, k, 8);
  BN_lshift(k, k, 8);
  
  // r := (k * G).x
  if (!EC_scale(r_xy, group.G, k, group, ctx))
    goto err;

  BN_copy(sig->r, r_xy.getx());
  
  // s := (H(m) + d*r) * k^-1
  SHA256((unsigned char *)m, strlen(m), hash);

  if (!BN_bin2bn(hash, SHA256_HASH_LEN, Hm))
    goto err;

  if (!BN_mod_mul(dr, d, sig->r, group.n, ctx))
    goto err;

  if (!BN_mod_add(Hmdr, Hm, dr, group.n, ctx))
    goto err;

  if (!(kmodinv = modinv(k, group.n, ctx)))
    goto err;

  if (!BN_mod_mul(sig->s, Hmdr, kmodinv, group.n, ctx))
    goto err;

 err:
  BN_CTX_end(ctx);
  if (kmodinv) BN_free(kmodinv);
  // return (r, s)
  return sig;
}

int main() {
  int rc = -1;
  
  /* 
   * b1 = [  -2    0    2    0]
   * b2 = [ 1/2   -1    0    0]
   * b3 = [  -1    0   -2  1/2]
   * b4 = [  -1    1    1    2]
   */
  vector<mpq_class> b1;
  mpq_class aa(-2);
  b1.push_back(aa);
  mpq_class b(0);
  b1.push_back(b);
  mpq_class c(2);
  b1.push_back(c);
  mpq_class d(0);
  b1.push_back(d);

  vector<mpq_class> b2;
  mpq_class e(1, 2);
  b2.push_back(e);
  mpq_class f(-1);
  b2.push_back(f);
  mpq_class g(0);
  b2.push_back(g);
  mpq_class h(0);
  b2.push_back(h);

  vector<mpq_class> b3;
  mpq_class i(-1);
  b3.push_back(i);
  mpq_class j(0);
  b3.push_back(j);
  mpq_class k(-2);
  b3.push_back(k);
  mpq_class ll(1, 2);
  b3.push_back(ll);

  vector<mpq_class> b4;
  mpq_class m(-1);
  b4.push_back(m);
  mpq_class n(1);
  b4.push_back(n);
  mpq_class o(1);
  b4.push_back(o);
  mpq_class p(2);
  b4.push_back(p);

  mpq_class delta(0.99);

  vector< vector<mpq_class> > B;
  B.push_back(b1);
  B.push_back(b2);
  B.push_back(b3);
  B.push_back(b4);
  
  vector< vector<mpq_class> > ret = LLL(B, delta);

  for (int i = 0; i < ret.size(); i++) {
    for (int j = 0; j < ret[i].size(); j++) {
      cout << ret[i][j] << " ";
    }
    cout << endl;
  }

  // ECDSA...
  ECPoint base("182", "85518893674295321206118380980485522083");
  ECGroup group("-95051", "11279326", "233970423115425145524320034830162017933", base, "29246302889428143187362802287225875743", "8", "233970423115425145498902418297807005944");

  BN_CTX *ctx = NULL;
  BIGNUM *a = NULL;
  ECPoint A;
  ECDSASig *sig = NULL;

  const char *msg = "Hello, World!";

  unsigned char hash[SHA256_HASH_LEN];
  BIGNUM *Hm = NULL;
  BIGNUM *l = NULL;
  BIGNUM *twol = NULL;
  BIGNUM *stwol = NULL;
  BIGNUM *t = NULL;
  BIGNUM *u = NULL;

  mpz_class q(BN_bn2dec(group.n), 10);
  vector< vector<mpq_class> > BB;
  vector<mpq_class> bt;
  vector<mpq_class> bu;
  mpq_class ct;
  mpq_class cu;
  mpq_class zero(0);
  mpz_class mpztwol;

  if (!(ctx = BN_CTX_new()))
    goto err;

  if (!(l = BN_new()))
    goto err;
  
  if (!BN_set_word(l, 8))
    goto err;

  if (!(twol = BN_new()))
    goto err;
  
  if (!BN_set_word(twol, 2))
    goto err;
  
  if (!BN_exp(twol, twol, l, ctx))
    goto err;

  {
    mpz_class xx(BN_bn2dec(twol), 10);
    mpztwol = xx;
  }

  // Generate Alice's keys
  if (!(a = BN_new()))
    goto err;
  
  if (!BN_rand_range(a, group.n))
    goto err;
  
  if (!EC_scale(A, group.G, a, group, ctx))
    goto err;

  if (!(Hm = BN_new()))
    goto err;

  SHA256((unsigned char *)msg, strlen(msg), hash);

  if (!BN_bin2bn(hash, SHA256_HASH_LEN, Hm))
    goto err;

  if (!(stwol = BN_new()))
    goto err;
  
  // Try ECDSA
  for (int i = 0; i < 20; i++) {
    sig = ECDSA_biased_sign(msg, a, group, ctx);

    // t =    r / ( s*2^l)
    // u = H(m) / (-s*2^l)
    if (!BN_mod_mul(stwol, sig->s, twol, group.n, ctx))
      goto err;

    if (!(u = BN_new()))
      goto err;
	
    if (!(t = modinv(stwol, group.n, ctx)))
      goto err;
    
    if (!BN_mod_mul(u, Hm, t, group.n, ctx))
      goto err;
    
    BN_set_negative(u, 1);
    
    if (!BN_mod_mul(t, sig->r, t, group.n, ctx))
      goto err;

    vector<mpq_class> bi;
    for (int j = 0; j < 22; j++) {
      mpq_class c;
      if (j == i) {
	c = q;
      } else {
	c = 0;
      }
      bi.push_back(c);
    }
    mpz_class mpzt(BN_bn2dec(t), 10);
    mpq_class mpqt(mpzt);
    bt.push_back(mpqt);
    mpz_class mpzu(BN_bn2dec(u), 10);
    mpq_class mpqu(mpzu);
    bu.push_back(mpqu);
    BB.push_back(bi);

    if (u) BN_free(u);
    u = NULL;
    if (t) BN_free(t);
    t = NULL;
  }

  // ct = 1/2^l
  // cu = q/2^l
  {
    mpq_class yy(1, mpztwol);
    ct = yy;
    mpq_class zz(q, mpztwol);
    cu = zz;
  }
  cu.canonicalize();
  bt.push_back(ct);
  bt.push_back(zero);

  bu.push_back(zero);
  bu.push_back(cu);

  BB.push_back(bt);
  BB.push_back(bu);

  // NOTE: unoptimized - with supplied curve succeeds
  // after approx. 30 mins
  ret = LLL(BB, delta);

  for (int i = 0; i < ret.size(); i++) {
    if (ret[i][ret[i].size()-1] == cu) {
      mpq_class d = ret[i][ret[i].size()-2];
      d = d * mpztwol * -1;
      mpz_class mpzd(d);
      mpz_mod(mpzd.get_mpz_t(), mpzd.get_mpz_t(), q.get_mpz_t());
      mpz_class mpza(BN_bn2dec(a), 10);
      if (mpzd == mpza) {
	cout << "Found d! d = " << mpzd << endl;
      } else {
	cout << "Didn't find d.  Guess = " << mpzd << ", d = " << mpza << endl;
      }
    }
  }

  rc = 0;

 err:
  if (a) BN_free(a);
  if (Hm) BN_free(Hm);
  if (l) BN_free(l);
  if (twol) BN_free(twol);
  if (stwol) BN_free(stwol);
  if (t) BN_free(t);
  if (u) BN_free(u);
  if (ctx) BN_CTX_free(ctx);
  
  return rc;
}
