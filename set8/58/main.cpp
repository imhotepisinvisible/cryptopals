#include <iostream>
#include <cmath>

#include <openssl/bn.h>

#include "crypto.h"
#include "conversions.h"

using namespace std;

//f(y) = 2^(y mod k)
void f(BIGNUM *fy, const BIGNUM *y, const BIGNUM *p, BN_CTX *ctx) {
  BN_CTX_start(ctx);
  
  BIGNUM *k = NULL;

  BIGNUM *two = NULL;

  if (!(k = BN_CTX_get(ctx)))
    goto err;

  if (!(two = BN_CTX_get(ctx)))
    goto err;
  
  if (!BN_set_word(k, 20))
    goto err;
  
  if (!BN_set_word(two, 2))
    goto err;
  
  if (!BN_mod(fy, y, k, ctx))
    goto err;
  
  if (!BN_mod_exp(fy, two, fy, p, ctx))
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

int kangaroo(BIGNUM *index, const BIGNUM *y, const BIGNUM *b, const BIGNUM *g, const BIGNUM *p, BN_CTX *ctx) {
  BN_CTX_start(ctx);
  int ret = 0;
  BIGNUM *xT = NULL;
  BIGNUM *yT = NULL;
  BIGNUM *fyT = NULL;
  BIGNUM *gfyT = NULL;
  BIGNUM *xW = NULL;
  BIGNUM *yW = NULL;
  BIGNUM *fyW = NULL;
  BIGNUM *gfyW = NULL;
  BIGNUM *bxT = NULL;
  
  // xT := 0
  // yT := g^b
  //
  // for i in 1..N:
  //     xT := xT + f(yT)
  //     yT := yT * g^f(yT)
  if (!(xT = BN_CTX_get(ctx)))
    goto err;
  
  BN_zero(xT);

  if (!(yT = BN_CTX_get(ctx)))
    goto err;
  
  if (!BN_mod_exp(yT, g, b, p, ctx))
    goto err;

  if (!(fyT = BN_CTX_get(ctx)))
    goto err;
  
  if (!(gfyT = BN_CTX_get(ctx)))
      goto err;
      
  for (size_t i = 0; i < fmean(20); i++) {
    f(fyT, yT, p, ctx);
    
    if (!BN_mod_add(xT, xT, fyT, p, ctx))
      goto err;
    
    if (!BN_mod_exp(gfyT, g, fyT, p, ctx))
      goto err;
    
    if (!BN_mod_mul(yT, yT, gfyT, p, ctx))
      goto err;
  }

  // xW := 0
  // yW := y
  //
  // while xW < b - a + xT:
  //     xW := xW + f(yW)
  //     yW := yW * g^f(yW)
  //
  //     if yW = yT:
  //         return b + xT - xW
  if (!(xW = BN_CTX_get(ctx)))
    goto err;
  
  BN_zero(xW);
  
  if (!(yW = BN_CTX_get(ctx)))
    goto err;
  
  if (!BN_copy(yW, y))
    goto err;

  if (!(fyW = BN_CTX_get(ctx)))
    goto err;
  
  if (!(gfyW = BN_CTX_get(ctx)))
    goto err;
  
  if (!(bxT = BN_CTX_get(ctx)))
    goto err;
  
  if (!BN_add(bxT, b, xT))
    goto err;

  while (BN_cmp(xW, bxT) < 0) {
    f(fyW, yW, p, ctx);
    
    if (!BN_mod_add(xW, xW, fyW, p, ctx))
      goto err;
    
    if (!BN_mod_exp(gfyW, g, fyW, p, ctx))
      goto err;
    
    if (!BN_mod_mul(yW, yW, gfyW, p, ctx))
      goto err;

    if (BN_cmp(yW, yT) == 0) {
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
    init_openssl();

    const char *p_str = "1147037487492527565811666350723216140208665025845389627"
      "4534991676898999262641581519101074740642369848233294239851519212341844337"
      "347119899874391456329785623";
    const char *q_str = "335062023296420808191071248367701059461";
    const char *j_str = "3423358685080740462347504838132868621107119670137423049"
      "2615844865929237417097514638999377942356150481334217896204702";
    const char *g_str = "6229523353339612969781592660847410858898813587384599399"
      "7829017993606363556674025855516778300905856739796346610314008264748661165"
      "7350811560630587013183357";
    const char *y1_str = "776007384803268950539500570567736587665462918929805277"
      "5754597607446617558600394076764814236081991643094239886772481052254010323"
      "780165093955236429914607119";
    const char *y2_str = "938889747801339955069411461449879069103418745308935525"
      "9602614074132918843899833277397448144245883225611726912025846772975325932"
      "794909655215329941809013733";

    BIGNUM *b = NULL;
    BIGNUM *B = NULL;
    BIGNUM *p = NULL;
    BIGNUM *q = NULL;
    BIGNUM *j = NULL;
    BIGNUM *g = NULL;
    BIGNUM *y1 = NULL;
    BIGNUM *y2 = NULL;
    BIGNUM *b1 = NULL;
    BIGNUM *b2 = NULL;
    BIGNUM *b3 = NULL;
    BIGNUM *n = NULL;
    BIGNUM *r = NULL;
    BIGNUM *x = NULL;
    BIGNUM *yprime = NULL;
    BIGNUM *gprime = NULL;
    BIGNUM *index = NULL;
    BN_CTX *ctx = NULL;

    if (!BN_dec2bn(&p, p_str))
      goto err;

    if (!BN_dec2bn(&q, q_str))
      goto err;

    if (!BN_dec2bn(&j, j_str))
      goto err;

    if (!BN_dec2bn(&g, g_str))
      goto err;

    if (!BN_dec2bn(&y1, y1_str))
      goto err;
  
    if (!(ctx = BN_CTX_new()))
      goto err;
    
    if (!(b1 = BN_new()))
      goto err;
    
    if (!BN_set_word(b1, 0x100000)) //2^20
      goto err;

    if (!(index = BN_new()))
      goto err;

    if (kangaroo(index, y1, b1, g, p, ctx)) {
      cout << "Index found: " << BN_bn2dec(index) << endl;
    } else {
      cout << "Error finding index" << endl;
    }

    if (!BN_dec2bn(&y2, y2_str))
      goto err;
    
    if (!(b2 = BN_new()))
      goto err;
    
    if (!BN_set_word(b2, 0x10000000000)) //2^40
      goto err;

    if (kangaroo(index, y2, b2, g, p, ctx)) {
      cout << "Index found: " << BN_bn2dec(index) << endl;
    } else {
      cout << "Error finding index" << endl;
    }

    if (!(n = BN_new()))
      goto err;
    
    if (!(r = BN_new()))
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
    
    dh_subgroup_attack(n, r, b, B, p, g, q, j, ctx);

    // y' = y * g^-n = g^(m*r)
    yprime = modinv(g, p, ctx);

    if (!BN_mod_exp(yprime, yprime, n, p, ctx))
      goto err;
    
    if (!BN_mod_mul(yprime, B, yprime, p, ctx))
      goto err;
    
    // g' = g^r
    if (!(gprime = BN_new()))
      goto err;

    if (!BN_mod_exp(gprime, g, r, p, ctx))
      goto err;

    // b3 = (q-1)/r
    if (!(b3 = BN_new()))
      goto err;

    if (!BN_sub(b3, q, BN_value_one()))
      goto err;
    
    if (!BN_div(b3, NULL, b3, r, ctx))
      goto err;

    if (kangaroo(index, yprime, b3, gprime, p, ctx)) {
      cout << "Index found: " << BN_bn2dec(index) << endl;
      if (!(x = BN_new()))
	goto err;
      
      // x = n + m*r
      if (!BN_mod_mul(x, index, r, p, ctx))
	goto err;
      
      if(!BN_mod_add(x, n, x, p, ctx))
	goto err;
      
      if (BN_cmp(x, b) == 0) {
	cout << "Success! b = " << BN_bn2hex(x) << endl;
      } else {
	cout << "Error, x calculated as" << endl
	     << BN_bn2hex(x) << endl
	     << "but b was" << endl
	     << BN_bn2hex(b) << endl;
      }
    } else {
      cout << "Error finding index" << endl;
    }

 err:
    if (b) BN_free(b);
    if (B) BN_free(B);
    if (p) BN_free(p);
    if (q) BN_free(q);
    if (j) BN_free(j);
    if (g) BN_free(g);
    if (y1) BN_free(y1);
    if (y2) BN_free(y2);
    if (b1) BN_free(b1);
    if (b2) BN_free(b2);
    if (b3) BN_free(b3);
    if (n) BN_free(n);
    if (r) BN_free(r);
    if (x) BN_free(x);
    if (yprime) BN_free(yprime);
    if (gprime) BN_free(gprime);
    if (index) BN_free(index);
    if (ctx) BN_CTX_free(ctx);
    
    close_openssl();
    
    return 0;
}
