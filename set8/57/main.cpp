#include <iostream>

#include <openssl/bn.h>

#include "crypto.h"
#include "conversions.h"

using namespace std;

int main() {
  init_openssl();

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
  BIGNUM *j = NULL;
  BIGNUM *b = NULL;
  BIGNUM *B = NULL;
  BIGNUM *x = NULL;
  BIGNUM *r = NULL;
  BN_CTX *ctx = NULL;

  if (!BN_dec2bn(&p, p_str))
    goto err;

  if (!BN_dec2bn(&g, g_str))
    goto err;

  if (!BN_dec2bn(&q, q_str))
    goto err;

  if (!BN_dec2bn(&j, j_str))
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

  if (!(x = BN_new()))
    goto err;

  if (!(r = BN_new()))
    goto err;

  if (!dh_subgroup_attack(x, r, b, B, p, g, q, j, ctx)) {
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
  if (x) BN_free(x);
  if (r) BN_free(r);
  if (ctx) BN_CTX_free(ctx);

  close_openssl();

  return 0;
}
