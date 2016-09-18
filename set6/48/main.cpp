#include <iostream>

#include "crypto.h"
#include "conversions.h"
#include "interval_union.h"

using namespace std;

// Global constants
BIGNUM *B = NULL;
BIGNUM *two = NULL;
BIGNUM *three = NULL;
BIGNUM *B2 = NULL;
BIGNUM *B3 = NULL;
BIGNUM *B3minus1 = NULL;

bool pkcs1_oracle(const RSAKey *priv, const BIGNUM *ciphertext) {
  bool ret = false;

  BIGNUM *plaintext = RSA_decrypt_toBN(priv, ciphertext);

  int plaintext_len = BN_num_bytes(plaintext);
  unsigned char *plaintext_str = new unsigned char[plaintext_len];
  BN_bn2bin(plaintext, plaintext_str);

  ret = ((plaintext_len == (BN_num_bytes(priv->n) - 1)) && plaintext_str[0] == 2);

  if (plaintext) BN_free(plaintext);
  if (plaintext_str) delete [] plaintext_str;

  return ret;
}

void ceiling(BIGNUM *n, const BIGNUM *rem) {
  if (!BN_is_zero(rem)) {
    BN_add(n, n, BN_value_one());
  }
  return;
}

void BN_max(BIGNUM *max, const BIGNUM *a, const BIGNUM *b) {
  if (BN_cmp(a, b) == 1) {
    BN_copy(max, a);
  } else {
    BN_copy(max, b);
  }
  return;
}

void BN_min(BIGNUM *min, const BIGNUM *a, const BIGNUM *b) {
  if (BN_cmp(a, b) == -1) {
    BN_copy(min, a);
  } else {
    BN_copy(min, b);
  }
  return;
}

void find_s(const RSAKey *pub, const RSAKey *priv, const BIGNUM *ciphertext, BIGNUM *s, BN_CTX *ctx) {
  BN_CTX_start(ctx);

  BIGNUM *sexp = BN_CTX_get(ctx);
  BIGNUM *c = BN_CTX_get(ctx);
  while(true) {
    BN_mod_exp(sexp, s, pub->e_or_d, pub->n, ctx);
    BN_mod_mul(c, ciphertext, sexp, pub->n, ctx);
    if (pkcs1_oracle(priv, c)) {
      break;
    }
    BN_add(s, s, BN_value_one());
  }

  //cout << "s" << i << ": " << BN_bn2dec(s) << endl;
  BN_CTX_end(ctx);

  return;
}

// Step 2.c: Searching with one interval left.
// Otherwise, if M(i−1) contains exactly one
// interval (i.e., M(i−1)={[a, b]}), then choose
// small integer values ri,si such that
//
//        bs(i-1) - 2B
// ri >= 2------------
//              n
//
// and
//
// 2B + ri.n        3B + ri.n
// --------- <= s < ---------
//     b               a
//
// until the ciphertext c0(si)**e mod n is PKCS conforming.
void step2c(const RSAKey *pub, const RSAKey *priv, const BIGNUM *ciphertext, const BIGNUM *sminus1, const BIGNUM *a, const BIGNUM *b, BIGNUM *s, BN_CTX *ctx) {
  BN_CTX_start(ctx);

  BIGNUM *r = BN_CTX_get(ctx);
  BIGNUM *rem = BN_CTX_get(ctx);
  BIGNUM *LB = BN_CTX_get(ctx);
  BIGNUM *UB = BN_CTX_get(ctx);
  BIGNUM *sexp = BN_CTX_get(ctx);
  BIGNUM *c = BN_dup(ciphertext);
  
  BN_mul(r, b, sminus1, ctx);
  BN_sub(r, r, B2);
  BN_mul(r, r, two, ctx);
  BN_div(r, rem, r, pub->n, ctx);
  ceiling(r, rem);

  bool found = false;
  while (!found) {
    //cout << "r: " << BN_bn2dec(r) << endl;

    BN_mul(LB, r, pub->n, ctx);
    BN_add(LB, B2, LB);
    BN_div(LB, rem, LB, b, ctx);
    ceiling(LB, rem);

    BN_mul(UB, r, pub->n, ctx);
    BN_add(UB, B3, UB);
    BN_div(UB, rem, UB, a, ctx);
    ceiling(UB, rem);

    BN_copy(s, LB);
    // Stop when hit upper range of si and increase r
    if (BN_cmp(LB, UB) <= 0) {
      while(BN_cmp(s, UB) < 0) {
	BN_mod_exp(sexp, s, pub->e_or_d, pub->n, ctx);
	BN_mod_mul(c, ciphertext, sexp, pub->n, ctx);
	if (pkcs1_oracle(priv, c)) {
	  found = true;
	  break;
	}
	BN_add(s, s, BN_value_one());
      }
    }
    
    BN_add(r, r, BN_value_one());
  }

  //cout << "s: " << BN_bn2dec(s) << endl;

  if (c) BN_free(c);
  BN_CTX_end(ctx);
}

void find_interval(const BIGNUM *n, const BIGNUM *s, const BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BIGNUM *LB, BIGNUM *UB, BN_CTX *ctx) {
  BN_CTX_start(ctx);

  BIGNUM *a_alt = BN_CTX_get(ctx);
  BIGNUM *b_alt = BN_CTX_get(ctx);
  BIGNUM *rem = BN_CTX_get(ctx);
  
  BN_mul(a_alt, r, n, ctx);
  BN_add(a_alt, a_alt, B2);
  BN_div(a_alt, rem, a_alt, s, ctx);
  ceiling(a_alt, rem);

  BN_max(LB, a, a_alt);

  BN_mul(b_alt, r, n, ctx);
  BN_add(b_alt, B3minus1, b_alt);
  BN_div(b_alt, NULL, b_alt, s, ctx);

  BN_min(UB, b, b_alt);

  BN_CTX_end(ctx);
}

void step3(const BIGNUM *n, const BIGNUM *s, const IntervalUnion &Mminus1, const int interval_num, IntervalUnion &M, BN_CTX *ctx) {
  BN_CTX_start(ctx);
  
  // Calc upper and lower bounds for r
  Interval inter = Mminus1.get_interval(interval_num);
  BIGNUM *LBr = BN_CTX_get(ctx);
  BIGNUM *UBr = BN_CTX_get(ctx);
  BIGNUM *rem = BN_CTX_get(ctx);
  BN_mul(LBr, inter.first, s, ctx);
  BN_sub(LBr, LBr, B3);
  BN_add(LBr, LBr, BN_value_one());
  BN_div(LBr, rem, LBr, n, ctx);
  ceiling(LBr, rem);

  BN_mul(UBr, inter.second, s, ctx);
  BN_sub(UBr, UBr, B2);
  BN_div(UBr, NULL, UBr, n, ctx);

  BIGNUM *r = BN_CTX_get(ctx);
  BN_copy(r, LBr);
  BIGNUM *LBunion = BN_CTX_get(ctx);
  BIGNUM *UBunion = BN_CTX_get(ctx);
  if (BN_cmp(LBr, UBr) <= 0) {
    do {
      find_interval(n, s, r, inter.first, inter.second, LBunion, UBunion, ctx);
    
      Interval new_inter(LBunion, UBunion);
      M.add_interval(new_inter);
      
      BN_add(r, r, BN_value_one());
    } while (BN_cmp(r, UBr) <= 0);
  }

  BN_CTX_end(ctx);

  return;
}

int main() {
  RSAKey *priv = NULL;
  RSAKey *pub = NULL;

  const char *plaintext = "kick it, CC";

  RSA_genkeys(&priv, &pub, 384);

  // Construct valid padding
  int plaintext_block_len = BN_num_bytes(priv->n);
  unsigned char *plaintext_block = new unsigned char[plaintext_block_len];
  int padding_len = plaintext_block_len - strlen(plaintext) - 1 - 2;

  plaintext_block[0] = 0;
  plaintext_block[1] = 2;
  memset(plaintext_block+2, 0xff, padding_len);
  plaintext_block[padding_len+2] = 0;
  memcpy(plaintext_block+2+padding_len+1, plaintext, strlen(plaintext));

  BIGNUM *ciphertext = RSA_encrypt(pub, plaintext_block, plaintext_block_len);

  int Bint = BN_num_bits(pub->n) - 16;

  // Initialize constants
  BN_CTX *ctx = BN_CTX_new();
  B = BN_new();
  BN_set_word(B, Bint);
  two = BN_new();
  BN_set_word(two, 2);
  three = BN_new();
  BN_set_word(three, 3);
  BN_exp(B, two, B, ctx);
  B2 = BN_new();
  B3 = BN_new();
  B3minus1 = BN_new();
  BN_mul(B2, B, two, ctx);
  BN_mul(B3, B, three, ctx);
  BN_sub(B3minus1, B3, BN_value_one());
  
  // Step 1: init
  IntervalUnion M;
  IntervalUnion Mminus1;
  Interval start(B2, B3minus1);
  M.add_interval(start);
  int i = 1;
  BIGNUM *s = BN_dup(BN_value_one());
  BIGNUM *sminus1 = NULL;
  BIGNUM *s0 = BN_dup(s);
  BIGNUM *rem = BN_new();
  BIGNUM *m = NULL;
  Interval inter;
  unsigned char *padded_found_plaintext = NULL;

  // Begin the loop
  cout << "Finding plaintext";
  while (true) {
    cout << "." << flush;
    
    // Step 2.a: Starting the search. If i = 1, then search
    // for the smallest positive integer s1 >= n/(3B), such
    // that the ciphertext c0(s1)**e mod n is PKCS conforming.
    if (i == 1) {
      BN_div(s, rem, pub->n, B3, ctx);
      ceiling(s, rem);
      find_s(pub, priv, ciphertext, s, ctx);
    } else if (M.number_intervals() > 1) {
      // Step 2.b: Searching with more than one interval left.
      // Otherwise, if i > 1 and the number of intervals in
      // M[i−1] is at least 2, then search for the smallest
      // integer si > s[i−1], such that the ciphertext
      // c0(si)**e mod n is PKCS conforming.
      BN_add(s, s, BN_value_one());
      find_s(pub, priv, ciphertext, s, ctx);
    } else {
      // Step 2.c
      sminus1 = BN_dup(s);
      inter = M.get_interval(0);
      step2c(pub, priv, ciphertext, sminus1, inter.first, inter.second, s, ctx);
    }

    // Step 3
    Mminus1 = M;
    M.clear();
    // Loop the intervals in M[i-1]
    for (int j = 0; j < Mminus1.number_intervals(); j++) {
      step3(pub->n, s, Mminus1, j, M, ctx);
    }

    // Step 4: Computing the solution. If Mi contains
    // only one interval of length 1 (i.e., Mi = {[a, a]}),
    // then set m <- a(s0)**−1 mod n, and return m as
    // solution of m==c**d (mod n).
    // Otherwise, set i <- i + 1 and go to step 2.
    if (M.number_intervals() == 1) {
      inter = M.get_interval(0);
      if (BN_cmp(inter.first, inter.second) == 0) {
	cout << endl << "Plaintext found after " << i << " rounds:" << endl;
	m = modinv(s0, pub->n, ctx);
	BN_mod_mul(m, inter.first, m, pub->n, ctx);
	
	// Remove padding
	int padded_plaintext_len = BN_num_bytes(m);
	padded_found_plaintext = new unsigned char[padded_plaintext_len+1];
	BN_bn2bin(m, padded_found_plaintext);
	padded_found_plaintext[padded_plaintext_len] = '\0';
	unsigned char *found_plaintext = padded_found_plaintext;
	found_plaintext++;
	while (*(found_plaintext++) == 0xff);
	cout << found_plaintext << endl;
	break;
      }
    }

    i++;
  }

  if (pub) delete pub;
  if (priv) delete priv;
  if (B) BN_free(B);
  if (two) BN_free(two);
  if (three) BN_free(three);
  if (B2) BN_free(B2);
  if (B3) BN_free(B3);
  if (B3minus1) BN_free(B3minus1);
  if (ciphertext) BN_free(ciphertext);
  if (s) BN_free(s);
  if (sminus1) BN_free(sminus1);
  if (s0) BN_free(s0);
  if (rem) BN_free(rem);
  if (m) BN_free(m);
  if (ctx) BN_CTX_free(ctx);
  if (plaintext_block) delete [] plaintext_block;
  if (padded_found_plaintext) delete [] padded_found_plaintext;
  
  return 0;
}
