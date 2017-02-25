#ifndef GF2MATRIX_H
#define GF2MATRIX_H

#include <vector>

#include <gmp.h>
#include <gmpxx.h>

#include <m4ri/m4ri.h>

class Gf2Matrix {
 public:
  Gf2Matrix(const size_t rows, const size_t cols);
  Gf2Matrix(const mpz_class &c);
  Gf2Matrix(const std::vector<uint8_t> &vec);
  Gf2Matrix(const mzd_t *m4ri);

  int height() const;
  int width() const;

  Gf2Matrix operator+(const Gf2Matrix &rhs) const;
  Gf2Matrix operator*(const Gf2Matrix &rhs) const;
  Gf2Matrix transpose() const;
  Gf2Matrix identity() const;
  Gf2Matrix gaussian_elim(Gf2Matrix &identity) const;
  Gf2Matrix basis(const Gf2Matrix &augment) const;

  mzd_t *to_m4ri() const;

  std::vector<uint8_t> &operator[](size_t index);

  std::vector<uint8_t> const &operator[](size_t index) const;

 private:
  std::vector< std::vector<uint8_t> > m;
  void swap_rows(const int i, const int j);
  void xor_rows(const int i, const int j);
};

#endif
