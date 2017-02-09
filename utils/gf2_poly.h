/*
 * Functions for manipulating polynomials with
 * coefficients in GF(2)
 */
#ifndef GF2_POLY_H
#define GF2_POLY_H

#include <gmp.h>
#include <gmpxx.h>

mpz_class block2fieldel(const unsigned char *block);

unsigned char *fieldel2block(mpz_class el);

mpz_class gf2_add(const mpz_class &a, const mpz_class &b);

mpz_class gf2_sub(const mpz_class &a, const mpz_class &b);

mpz_class gf2_mul(mpz_class a, mpz_class b);

int gf2_deg(const mpz_class &a);

std::pair<mpz_class, mpz_class> gf2_divmod(const mpz_class &a, const mpz_class &b);

mpz_class gf2_naive_modmul(const mpz_class &a, const mpz_class &b, const mpz_class &m);

mpz_class gf2_modmul(mpz_class a, mpz_class b, const mpz_class &m);

std::pair<mpz_class, mpz_class> gf2_egcd(const mpz_class &a, const mpz_class &b);

mpz_class gf2_modinv(const mpz_class &a, const mpz_class &m);

mpz_class gf2_modexp(mpz_class a, mpz_class p, const mpz_class &m);

#endif
