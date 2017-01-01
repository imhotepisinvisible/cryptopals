#include <iostream>
#include <cmath>
#include <vector>
#include <set>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "crypto.h"
#include "conversions.h"
#include "ec.h"
#include "primes.h"

using namespace std;

int generate_Qprime(ECPoint &Qprime, ECPoint &Gprime, const char *m, const BIGNUM *d, const ECDSASig *sig, const ECPoint &Q, const ECGroup &group, BN_CTX *ctx) {
  BN_CTX_start(ctx);
  int ret = 0;

  BIGNUM *u1 = BN_CTX_get(ctx);
  BIGNUM *u2 = BN_CTX_get(ctx);
  BIGNUM *Hm = BN_CTX_get(ctx);
  BIGNUM *u2d = BN_CTX_get(ctx);
  BIGNUM *t = BN_CTX_get(ctx);
  BIGNUM *smodinv = NULL;
  BIGNUM *tmodinv = NULL;
  ECPoint u1G;
  ECPoint u2Q;
  ECPoint R;
  unsigned char hash[SHA256_HASH_LEN];

  if (!t)
    goto err;

  // u1 := H(m) * s^-1
  SHA256((unsigned char *)m, strlen(m), hash);

  if (!(smodinv = modinv(sig->s, group.n, ctx)))
    goto err;

  if (!BN_bin2bn(hash, SHA256_HASH_LEN, Hm))
    goto err;

  if (!BN_mod_mul(u1, Hm, smodinv, group.n, ctx))
    goto err;
  
  // u2 := r * s^-1
  if (!BN_mod_mul(u2, sig->r, smodinv, group.n, ctx))
    goto err;

  // R := u1*G + u2*Q
  if (!EC_scale(u1G, group.G, u1, group, ctx))
    goto err;

  if (!EC_scale(u2Q, Q, u2, group, ctx))
    goto err;

  if (!EC_add(R, u1G, u2Q, group, ctx))
    goto err;

  // 2. Calculate t := u1 + u2*d'.
  if (!BN_mod_mul(u2d, u2, d, group.n, ctx))
    goto err;

  if (!BN_mod_add(t, u1, u2d, group.n, ctx))
    goto err;

  // 3. Calculate G' := t^-1 * R.
  if (!(tmodinv = modinv(t, group.n, ctx)))
    goto err;

  if (!EC_scale(Gprime, R, tmodinv, group, ctx))
    goto err;

  // 4. Calculate Q' := d' * G'.
  if (!EC_scale(Qprime, Gprime, d, group, ctx))
    goto err;

  ret = 1;
  
 err:
  BN_CTX_end(ctx);
  if (!smodinv) BN_free(smodinv);
  if (!tmodinv) BN_free(tmodinv);
  return ret;
}

int pick_prime(BIGNUM *p, set<int> &factors, set<int> &excluded, const int bits, BN_CTX *ctx) {
  int ret = 0;
  BN_CTX_start(ctx);
  
  BIGNUM *two = BN_CTX_get(ctx);
  BIGNUM *factor = BN_CTX_get(ctx);
  BIGNUM *pminus1 = BN_CTX_get(ctx);
  int factor_int = 0;

  if (!pminus1)
    goto err;
  
  if (!BN_set_word(two, 2))
    goto err;

  if (!BN_copy(pminus1, two))
    goto err;
  
  if (!BN_add(p, pminus1, BN_value_one()))
    goto err;
  
  factors.insert(2);
  
  while (BN_num_bits(p) < bits || !BN_is_prime_ex(p, BN_prime_checks, ctx, NULL)) {
    // BN_generate_prime_ex() cannot generate primes < 16 bits
    // use a lookup table intead
    do {
      factor_int = primes[arc4random_uniform(sizeof(primes)/sizeof(primes[0]))];
    } while (factors.find(factor_int) != factors.end() && excluded.find(factor_int) != factors.end());

    if (!BN_set_word(factor, factor_int))
      goto err;
    
    factors.insert(factor_int);
    
    if (!BN_mul(pminus1, pminus1, factor, ctx))
      goto err;
    
    if (!BN_add(p, pminus1, BN_value_one()))
      goto err;

    if (BN_num_bits(p) > bits+1) {
      if (!BN_copy(pminus1, two))
	goto err;
      
      if (!BN_add(p, pminus1, BN_value_one()))
	goto err;
      
      factors.clear();
      factors.insert(2);
    }
  }

  ret = 1;

 err:
  BN_CTX_end(ctx);
  return ret;
}

bool is_primitive_root(const BIGNUM *g, const BIGNUM *p, const set<int> factors, BN_CTX *ctx) {
  // To check if an element g
  // is a primitive root mod p, check that:
  //     g^((p-1)/q) != 1 mod p
  // For every factor q of p-1.
  bool ret = false;
  bool primitive = true;
  BN_CTX_start(ctx);

  BIGNUM *factor = BN_CTX_get(ctx);
  BIGNUM *pminus1 = BN_CTX_get(ctx);
  BIGNUM *pminus1overq = BN_CTX_get(ctx);
  BIGNUM *gpminus1overq = BN_CTX_get(ctx);

  if (!gpminus1overq)
    goto err;

  if (!BN_sub(pminus1, p, BN_value_one()))
    goto err;

  for(set<int>::iterator it = factors.begin(); it != factors.end(); ++it) {
    if (!BN_set_word(factor, *it))
      goto err;
    
    if (!BN_div(pminus1overq, NULL, pminus1, factor, ctx))
      goto err;
    
    if (!BN_mod_exp(gpminus1overq, g, pminus1overq, p, ctx))
      goto err;
    
    if (BN_cmp(gpminus1overq, BN_value_one()) == 0) {
      primitive = false;
      break;
    }
  }

  ret = primitive;

 err:
  BN_CTX_end(ctx);
  return ret;
}

int crt(BIGNUM *x, const BIGNUM *rn, const vector<pair< BIGNUM*, BIGNUM*> > &xs, BN_CTX *ctx) {
  int ret = 0;
  BN_CTX_start(ctx);
  
  BIGNUM *xi = BN_CTX_get(ctx);
  BIGNUM *rnoverr = BN_CTX_get(ctx);
  BIGNUM *rnmodinv = NULL;
  BN_zero(x);
  
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

      BN_free(rnmodinv);
      rnmodinv = NULL;
    }
  }
  
  if (!BN_mod(x, x, rn, ctx))
    goto err;
  
  ret = 1;

 err:
  BN_CTX_end(ctx);
  return ret;
}

int pohlig_hellman(BIGNUM *x, const BIGNUM *p, const set<int> factors, const BIGNUM *s, const BIGNUM *padm, BN_CTX *ctx) {
  int ret = 0;
  BN_CTX_start(ctx);
  
  BIGNUM *se = BN_CTX_get(ctx);
  BIGNUM *padm_adj = BN_CTX_get(ctx);
  BIGNUM *s_adj = BN_CTX_get(ctx);
  BIGNUM *pminus1 = BN_CTX_get(ctx);
  BIGNUM *pminus1overf = BN_CTX_get(ctx);
  BIGNUM *factor = NULL;
  BIGNUM *e = NULL;
  vector<pair< BIGNUM*, BIGNUM*> > xs;

  if (!pminus1overf)
    goto err;

  if (!BN_sub(pminus1, p, BN_value_one()))
    goto err;
  
  for(set<int>::iterator it = factors.begin(); it != factors.end(); ++it) {
    if (!(factor = BN_new()))
      goto err;
    
    if (!(e = BN_new()))
      goto err;

    if (!BN_set_word(factor, *it))
      goto err;
    
    if (!BN_div(pminus1overf, NULL, pminus1, factor, ctx))
      goto err;
    
    if (!BN_mod_exp(padm_adj, padm, pminus1overf, p, ctx))
      goto err;
    
    if (!BN_mod_exp(s_adj, s, pminus1overf, p, ctx))
      goto err;
    
    for (int i = 1; i <= *it; i++) {
      if (!BN_set_word(e, i))
	goto err;

      if (!BN_mod_exp(se, s_adj, e, p, ctx))
	goto err;

      if (BN_cmp(se, padm_adj) == 0) {
	pair<BIGNUM*,BIGNUM*> ef(e, factor);
	xs.push_back(ef);
	break;
      }
    }
  }

  // Use the Chinese Remainder Theorem to find e
  if (!crt(x, pminus1, xs, ctx))
    goto err;

  ret = 1;

 err:
  BN_CTX_end(ctx);
  for (int i = 0; i < xs.size(); i++) {
    if (xs[i].first) BN_free(xs[i].first);
    if (xs[i].second) BN_free(xs[i].second);
  }
  return ret;
}

int generate_eprime(BIGNUM *e, BIGNUM *d, BIGNUM *pq, const BIGNUM *sig, const BIGNUM *padm, const BIGNUM *n, BN_CTX *ctx) {
  int ret = 0;
  BN_CTX_start(ctx);
  
  BIGNUM *p = BN_CTX_get(ctx);
  BIGNUM *q = BN_CTX_get(ctx);
  BIGNUM *ep = BN_CTX_get(ctx);
  BIGNUM *eq = BN_CTX_get(ctx);
  BIGNUM *pminus1 = BN_CTX_get(ctx);
  BIGNUM *qminus1 = BN_CTX_get(ctx);
  BIGNUM *qminus1over2 = BN_CTX_get(ctx);
  BIGNUM *pminus1qminus1 = BN_CTX_get(ctx);
  BIGNUM *pminus1qminus1over2 = BN_CTX_get(ctx);
  BIGNUM *two = BN_CTX_get(ctx);
  set<int> pfactors;
  set<int> qfactors;
  vector<pair< BIGNUM*, BIGNUM*> > xs;

  if (!two)
    goto err;

  if (!BN_set_word(two, 2))
    goto err;

  while (1) {
    if (!pick_prime(p, pfactors, qfactors, 256, ctx))
      goto err;
    
    if (!is_primitive_root(sig, p, pfactors, ctx)
	|| !is_primitive_root(padm, p, pfactors, ctx)) {
      pfactors.clear();
    } else {
      break;
    }
  }
  
  while (1) {
    if (!pick_prime(q, qfactors, pfactors, 256, ctx))
      goto err;
    
    if (!is_primitive_root(sig, q, qfactors, ctx)
	|| !is_primitive_root(padm, q, qfactors, ctx)) {
      qfactors.clear();
      continue;
    }

    if (!BN_mul(pq, p, q, ctx))
      goto err;
    
    if (BN_cmp(pq, n) == 1) {
      break;
    }
  }

  // Pohlig-Hellman time
  // derive ep = e' mod p and eq = e' mod q.
  if (!pohlig_hellman(ep, p, pfactors, sig, padm, ctx))
    goto err;
  
  if (!pohlig_hellman(eq, q, qfactors, sig, padm, ctx))
    goto err;

  // Put ep and eq together:
  // e' = crt([ep, eq], [p-1, q-1])
  // NOTE: this actually does not work as p-1 and q-1 are not pairwise coprime
  // do crt([ep, eq], [p-1, (q-1)/2]) instead
  if (!BN_sub(pminus1, p, BN_value_one()))
    goto err;
  
  if (!BN_sub(qminus1, q, BN_value_one()))
    goto err;
  
  if (!BN_div(qminus1over2, NULL, qminus1, two, ctx))
    goto err;
  
  if (!BN_mul(pminus1qminus1, pminus1, qminus1, ctx))
    goto err;
  
  if (!BN_mul(pminus1qminus1over2, pminus1, qminus1over2, ctx))
    goto err;

  {
    pair<BIGNUM*,BIGNUM*> pr(ep, pminus1);
    xs.push_back(pr);
    pair<BIGNUM*,BIGNUM*> qr(eq, qminus1over2);
    xs.push_back(qr);
  }

  if (!crt(e, pminus1qminus1over2, xs, ctx))
    goto err;

  // Derive d' in the normal fashion
  // NOTE: this is not actually used in this attack
  d = modinv(pq, pminus1qminus1, ctx);

  ret = 1;

 err:
  BN_CTX_end(ctx);
  return ret;
}

int generate_dprime(BIGNUM *d, BIGNUM *pq, const BIGNUM *sig, const BIGNUM *padm, const BIGNUM *n, BN_CTX *ctx) {
  return generate_eprime(d, NULL, pq, sig, padm, n, ctx);
}

void rsa_crafting1(BN_CTX *ctx) {
  BN_CTX_start(ctx);
  
  // Generate s and pad(m)
  RSAKey *priv = NULL;
  RSAKey *pub = NULL;
  
  const char *msg = "Hello, World!";

  unsigned char hash[SHA256_HASH_LEN];
  SHA256((unsigned char *)msg, strlen(msg), hash);

  RSA_genkeys(&priv, &pub, 256);

  // Construct valid padding
  int sig_block_len = BN_num_bytes(priv->n);
  unsigned char *sig_block = new unsigned char[sig_block_len];
  int padding_len = sig_block_len - SHA256_HASH_LEN - 5 - 1 - 2;

  sig_block[0] = 0;
  sig_block[1] = 1;
  memset(sig_block+2, 0xff, padding_len);
  sig_block[padding_len+2] = 0;
  memcpy(sig_block+2+padding_len+1, "ASN.1", 5);
  memcpy(sig_block+2+padding_len+1+5, hash, SHA256_HASH_LEN);
  
  BIGNUM *sig = RSA_sign(priv, sig_block, sig_block_len);

  // Do the attack
  BIGNUM *padm = BN_CTX_get(ctx);
  BIGNUM *eprime = BN_CTX_get(ctx);
  BIGNUM *dprime = BN_CTX_get(ctx);
  BIGNUM *pq = BN_CTX_get(ctx);
  
  BN_bin2bn(sig_block, sig_block_len, padm);
  
  generate_eprime(eprime, dprime, pq, sig, padm, pub->n, ctx);

  cout << "e': " << BN_bn2dec(eprime) << endl;

  RSAKey evilpub(eprime, pq);
  if (RSA_verify(&evilpub, sig, sig_block, sig_block_len)) {
    cout << "Signature valid" << endl;
  } else {
    cout << "Signature invalid" << endl;
  }

  if (sig_block) delete [] sig_block;
  BN_CTX_end(ctx);
}

void rsa_crafting2(BN_CTX *ctx) {
  BN_CTX_start(ctx);
  
  // Generate c and pad(m)
  RSAKey *priv = NULL;
  RSAKey *pub = NULL;
  
  RSA_genkeys(&priv, &pub, 256);

  // Do the attack
  BIGNUM *padm = BN_CTX_get(ctx);
  BIGNUM *dprime = BN_CTX_get(ctx);
  BIGNUM *pq = BN_CTX_get(ctx);
  BIGNUM *c = BN_CTX_get(ctx);

  // Our arbitrary ciphertext
  const unsigned char ciphertext[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF };

  // What we'd like to decrypt to
  const char *plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do ";

  BN_bin2bn(ciphertext, sizeof(ciphertext), c);
  BN_bin2bn((unsigned char*)plaintext, strlen(plaintext), padm);
  
  generate_dprime(dprime, pq, c, padm, pub->n, ctx);

  cout << "d': " << BN_bn2dec(dprime) << endl;

  RSAKey evilpriv(dprime, pq);
  cout << BN_bn2hex(RSA_decrypt_toBN(priv, c)) << endl;
  cout << RSA_decrypt(&evilpriv, c) << endl;

  BN_CTX_end(ctx);
}

int main() {
  ECPoint base("182", "85518893674295321206118380980485522083");
  ECGroup group("-95051", "11279326", "233970423115425145524320034830162017933", base, "29246302889428143187362802287225875743", "8", "233970423115425145498902418297807005944");
  ECGroup evilgroup("-95051", "11279326", "233970423115425145524320034830162017933", base, "29246302889428143187362802287225875743", "8", "233970423115425145498902418297807005944");

  BN_CTX *ctx = NULL;
  BIGNUM *a = NULL;
  ECPoint A;
  BIGNUM *dprime = NULL;
  ECPoint Qprime;
  ECPoint Gprime;
  ECDSASig *sig = NULL;

  const char *msg = "Hello, World!";

  if (!(ctx = BN_CTX_new()))
    goto err;

  // Generate Alice's keys
  if (!(a = BN_new()))
    goto err;
  
  if (!BN_rand_range(a, group.n))
    goto err;
  
  if (!EC_scale(A, group.G, a, group, ctx))
    goto err;

  // Try ECDSA
  sig = ECDSA_sign(msg, a, group, ctx);

  if (ECDSA_verify(msg, sig, A, group, ctx)) {
    cout << "Signature valid" << endl;
  } else {
    cout << "Signature invalid" << endl;
  }
  
  // Generate Eve's keys and parameters
  
  //1. Choose a random d' mod n.
  if (!(dprime = BN_new()))
    goto err;

  if (!BN_rand_range(dprime, group.n))
    goto err;
  
  if (!generate_Qprime(Qprime, Gprime, msg, dprime, sig, A, evilgroup, ctx))
    goto err;

  evilgroup.G = Gprime;

  if (ECDSA_verify(msg, sig, Qprime, evilgroup, ctx)) {
    cout << "Signature valid" << endl;
  } else {
    cout << "Signature invalid" << endl;
  }

  // Do the RSA attacks
  // First, generating a key to verify a signature
  rsa_crafting1(ctx);

  // Second, decrypting arbitrary ciphertext to chosen plaintext
  rsa_crafting2(ctx);

 err:
  if (a) BN_free(a);
  if (dprime) BN_free(dprime);
  if (ctx) BN_CTX_free(ctx);
  
  return 0;
}
