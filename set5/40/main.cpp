#include <iostream>

#include "crypto.h"

using namespace std;

// https://github.com/androidrbox/aftv-full-unlock/blob/master/jni/aftv-full-unlock.c
BIGNUM *nearest_cuberoot(BIGNUM *in, BN_CTX *ctx) {
    BN_CTX_start(ctx);

    BIGNUM *three = BN_CTX_get(ctx);
    BIGNUM *high = BN_CTX_get(ctx);
    BIGNUM *mid = BN_CTX_get(ctx);
    BIGNUM *low = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);

    BN_set_word(three, 3); // Create the constant 3
    BN_set_word(high, 1); // high = 1

    do
    {
        BN_lshift1(high, high); // high = high << 1 (high * 2)
        BN_exp(tmp, high, three, ctx); // tmp = high^3
    } while (BN_ucmp(tmp, in) <= -1); // while (tmp < in)

    BN_rshift1(low, high); // low = high >> 1 (high / 2)

    while (BN_ucmp(low, high) <= -1) // while (low < high)
    {
        BN_add(tmp, low, high); // tmp = low + high
        BN_rshift1(mid, tmp); // mid = tmp >> 1 (tmp / 2)
        BN_exp(tmp, mid, three, ctx); // tmp = mid^3
        if (BN_ucmp(low, mid) <= -1 && BN_ucmp(tmp, in) <= -1) // if (low < mid && tmp < in)
            BN_copy(low, mid); // low = mid
        else if (BN_ucmp(high, mid) >= 1 && BN_ucmp(tmp, in) >= 1) // else if (high > mid && tmp > in)
            BN_copy(high, mid); // high = mid
        else
        {
            // subtract 1 from mid because 1 will be added after the loop
            BN_sub_word(mid, 1); // mid -= 1
            break;
        }
    }

    BN_add_word(mid, 1); // mid += 1

    BIGNUM *result = BN_dup(mid);

    BN_CTX_end(ctx);

    return result;
}

int main() {
  RSAKey *priv0 = NULL;
  RSAKey *pub0 = NULL;
  RSAKey *priv1 = NULL;
  RSAKey *pub1 = NULL;
  RSAKey *priv2 = NULL;
  RSAKey *pub2 = NULL;

  RSA_genkeys(&priv0, &pub0);
  RSA_genkeys(&priv1, &pub1);
  RSA_genkeys(&priv2, &pub2);
  BIGNUM *ciphertext0 = RSA_encrypt(pub0, "Hello, World!");
  BIGNUM *ciphertext1 = RSA_encrypt(pub1, "Hello, World!");
  BIGNUM *ciphertext2 = RSA_encrypt(pub2, "Hello, World!");

  // result =
  // (c_0 * m_s_0 * invmod(m_s_0, n_0)) +
  // (c_1 * m_s_1 * invmod(m_s_1, n_1)) +
  // (c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012
  // where:
  // c_0, c_1, c_2 are the three respective residues mod
  // n_0, n_1, n_2
  // m_s_n (for n in 0, 1, 2) are the product of the moduli
  // EXCEPT n_n --- ie, m_s_1 is n_0 * n_2
  // N_012 is the product of all three moduli
  BIGNUM *m_s_0 = NULL;
  BIGNUM *invmod0 = NULL;
  BIGNUM *m_s_1 = NULL;
  BIGNUM *invmod1 = NULL;
  BIGNUM *m_s_2 = NULL;
  BIGNUM *invmod2 = NULL;
  BIGNUM *r0 = NULL;
  BIGNUM *r1 = NULL;
  BIGNUM *r2 = NULL;
  BIGNUM *result = NULL;
  BIGNUM *N_012 = NULL;
  BIGNUM *m = NULL;
  BN_CTX *ctx = NULL;
  unsigned char *plaintext = NULL;
  
  if (!(ctx = BN_CTX_new()))
    goto err;
  
  if (!(m_s_0 = BN_new()))
    goto err;
  
  if (!BN_mul(m_s_0, pub1->n, pub2->n, ctx))
    goto err;
  
  if (!(invmod0 = BN_new()))
    goto err;
  
  if (!BN_mod_inverse(invmod0, m_s_0, pub0->n, ctx))
    goto err;

  if (!(m_s_1 = BN_new()))
    goto err;
  
  if (!BN_mul(m_s_1, pub0->n, pub2->n, ctx))
    goto err;
  
  if (!(invmod1 = BN_new()))
    goto err;
  
  if (!BN_mod_inverse(invmod1, m_s_1, pub1->n, ctx))
    goto err;

  if (!(m_s_2 = BN_new()))
    goto err;
  
  if (!BN_mul(m_s_2, pub0->n, pub1->n, ctx))
    goto err;
  
  if (!(invmod2 = BN_new()))
    goto err;
  
  if (!BN_mod_inverse(invmod2, m_s_2, pub2->n, ctx))
    goto err;

  if (!(r0 = BN_new()))
    goto err;
  
  if (!BN_mul(r0, ciphertext0, m_s_0, ctx))
    goto err;
  
  if (!BN_mul(r0, r0, invmod0, ctx))
    goto err;
  
  if (!(r1 = BN_new()))
    goto err;
  
  if (!BN_mul(r1, ciphertext1, m_s_1, ctx))
    goto err;
  
  if (!BN_mul(r1, r1, invmod1, ctx))
    goto err;
  
  if (!(r2 = BN_new()))
    goto err;
  
  if (!BN_mul(r2, ciphertext2, m_s_2, ctx))
    goto err;
  
  if (!BN_mul(r2, r2, invmod2, ctx))
    goto err;

  if (!(result = BN_new()))
    goto err;
  
  if (!BN_add(result, r0, r1))
    goto err;
  
  if (!BN_add(result, result, r2))
    goto err;

  // NOTE: Despite the instructions saying there is no need to mod,
  // this attack did not seem to work without the mod
  if (!(N_012 = BN_new()))
    goto err;
  
  if (!BN_mul(N_012, pub0->n, pub1->n, ctx))
    goto err;
  
  if (!BN_mul(N_012, N_012, pub2->n, ctx))
    goto err;
  
  if (!BN_mod(result, result, N_012, ctx))
    goto err;

  // To decrypt RSA using a simple cube root, leave off the final modulus operation; just take the raw accumulated result and cube-root it.
  if (!(m = nearest_cuberoot(result, ctx)))
    goto err;

  plaintext = new unsigned char[BN_num_bytes(m)];
  if (!BN_bn2bin(m, plaintext))
    goto err;

  plaintext[BN_num_bytes(m)] = '\0';

  cout << plaintext << endl;

 err:
  if (pub0) delete pub0;
  if (priv0) delete priv0;
  if (pub1) delete pub1;
  if (priv1) delete priv1;
  if (pub2) delete pub2;
  if (priv2) delete priv2;
  if (ciphertext0) BN_free(ciphertext0);
  if (ciphertext1) BN_free(ciphertext1);
  if (ciphertext2) BN_free(ciphertext2);
  if (m_s_0) BN_free(m_s_0);
  if (invmod0) BN_free(invmod0);
  if (m_s_1) BN_free(m_s_1);
  if (invmod1) BN_free(invmod1);
  if (m_s_2) BN_free(m_s_2);
  if (invmod2) BN_free(invmod2);
  if (r0) BN_free(r0);
  if (r1) BN_free(r1);
  if (r2) BN_free(r2);
  if (result) BN_free(result);
  if (N_012) BN_free(N_012);
  if (m) BN_free(m);
  if (ctx) BN_CTX_free(ctx);
  
  return 0;
}
