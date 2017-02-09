/*
 * Functions for manipulating polynomials with
 * coefficients in GF(2^128)
 */
#ifndef GF2128_POLY_H
#define GF2128_POLY_H

#include <map>

typedef std::map<int, mpz_class> mappoly;

mappoly gf2128_makemonic(const mappoly &a);

mappoly gf2128_add(const mappoly &a, const mappoly &b);

mappoly gf2128_sub(const mappoly &a, const mappoly &b);

mappoly gf2128_mul(const mappoly &a, const mappoly &b);

int gf2128_deg(const mappoly &a);

std::pair<mappoly, mappoly> gf2128_divmod(const mappoly &a, const mappoly &b);

mappoly gf2128_div(const mappoly &a, const mappoly &b);

mappoly gf2128_modmul(const mappoly &a, const mappoly &b, const mappoly &m);

std::pair<mappoly, mappoly> gf2128_egcd(const mappoly &a, const mappoly &b);

mappoly gf2128_modinv(const mappoly &a, const mappoly &m);

mappoly gf2128_gcd(const mappoly &a, const mappoly &b);

mappoly gf2128_modexp(mappoly a, mpz_class p, const mappoly &m);

mappoly gf2128_derivative(const mappoly &a);

mappoly gf2128_divexp(const mappoly &a, const int p);

mappoly gf2128_rand(const int d);

#endif
