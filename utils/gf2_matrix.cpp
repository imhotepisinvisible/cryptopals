#include <iostream>

#include "gf2_matrix.h"
#include "gf2_poly.h"

using namespace std;

Gf2Matrix::Gf2Matrix(const size_t rows, const size_t cols) {
  m.resize(rows, std::vector<uint8_t>(cols, 0));
}

Gf2Matrix::Gf2Matrix(const mpz_class &c) {
  m.resize(128, std::vector<uint8_t>(128, 0));
  mpz_class mask(1);
  mpz_class tmp;
  mpz_class mod("0x100000000000000000000000000000087");
  vector<uint8_t> cvec;
  
  for (int i = 0; i < 128; i++) {
    tmp = gf2_modmul(c, mask, mod);
    mask <<= 1;
    cvec = fieldel2vector(tmp);
    for (int j = 0; j < cvec.size(); j++) {
      m[j][i] = cvec[j];
    }
  }
}

Gf2Matrix::Gf2Matrix(const vector<uint8_t> &vec) {
  m.resize(vec.size(), std::vector<uint8_t>(1, 0));
  for (int i = 0; i < vec.size(); i++) {
    m[i][0] = vec[i];
  }
}

Gf2Matrix::Gf2Matrix(const mzd_t *m4ri) {
  m.resize(m4ri->nrows, std::vector<uint8_t>(m4ri->ncols, 0));
  for (int i = 0; i < m4ri->nrows; i++) {
    for (int j = 0; j < m4ri->ncols; j++) {
      m[i][j] = mzd_read_bit(m4ri, i, j);
    }
  }
}

Gf2Matrix Gf2Matrix::operator+(const Gf2Matrix &rhs) const {
  Gf2Matrix ret(height(), width());

  if (height() != rhs.height() || width() != rhs.width()) {
    cout << "Error: Mismatched sizes in +" << endl;
  } else {
    for (int i = 0; i < ret.height(); i++) {
      for (int j = 0; j < ret.width(); j++) {
	ret[i][j] = (m[i][j] + rhs[i][j]) % 2;
      }
    }
  }

  return ret;
}

Gf2Matrix Gf2Matrix::operator*(const Gf2Matrix &rhs) const {
  Gf2Matrix ret(height(), rhs.width());

  if (width() != rhs.height()) {
    cout << "Error: Mismatched sizes in *" << endl;
  } else {
    for (int i = 0; i < ret.height(); i++) {
      for (int j = 0; j < ret.width(); j++) {
	for (int k = 0; k < width(); ++k) {
	  ret[i][j] = (m[i][k] * rhs[k][j] + ret[i][j]) % 2;
	}
      }
    }
  }

  return ret;
}

Gf2Matrix Gf2Matrix::transpose() const {
  Gf2Matrix ret(width(), height());

  for (int i = 0; i < height(); i++) {
    for (int j = 0; j < width(); j++) {
      ret[j][i] = m[i][j];
    }
  }

  return ret;
}

Gf2Matrix Gf2Matrix::identity() const {
  Gf2Matrix ret(height(), width());

  for (int i = 0, j = 0; i < height() && j < width(); i++, j++) {
    ret[i][j] = 1;
  }

  return ret;
}

void Gf2Matrix::swap_rows(const int i, const int j) {
  m[i].swap(m[j]);
}

void Gf2Matrix::xor_rows(const int i, const int j) {
  for (int c = 0; c < width(); c++) {
    m[i][c] ^= m[j][c];
  }
}

Gf2Matrix Gf2Matrix::gaussian_elim(Gf2Matrix &identity) const {
  Gf2Matrix ret = *this;

  int pivot_row = 0;
  for (int i = 0; i < ret.width(); i++) {
    if (pivot_row >= ret.height()) {
      break;
    }
    if (ret[pivot_row][i] == 0) {
      int first_nonzero = -1;
      for (int j = pivot_row; j < ret.height(); j++) {
	if (ret[j][i] != 0) {
	  first_nonzero = j;
	  break;
	}
      }
      if (first_nonzero == -1) {
	continue;
      } else {
	ret.swap_rows(pivot_row, first_nonzero);
	identity.swap_rows(pivot_row, first_nonzero);
      }
    }
    for (int j = 0; j < ret.height(); j++) {
      if (j != pivot_row && ret[j][i] == 1) {
	ret.xor_rows(j, pivot_row);
	identity.xor_rows(j, pivot_row);
      }
    }
    pivot_row++;
  }

  return ret;
}

Gf2Matrix Gf2Matrix::basis(const Gf2Matrix &augment) const {
  vector<int> zerorows;
  bool ones = false;
  for (int i = 0; i < height(); i++) {
    for (int j = 0; j < width(); j++) {
      if (m[i][j] != 0) {
	ones = true;
	break;
      }
    }
    if (!ones) {
      zerorows.push_back(i);
    }
    ones = false;
  }

  Gf2Matrix ret(augment.height(), zerorows.size());
  for (int i = 0; i < zerorows.size(); i++) {
    for (int j = 0; j < augment.width(); j++) {
      ret[j][i] = augment[zerorows[i]][j];
    }
  }

  return ret;
}

mzd_t *Gf2Matrix::to_m4ri() const {
  mzd_t *ret = mzd_init(height(), width());
  for (int i = 0; i < height(); i++) {
    for (int j = 0; j < width(); j++) {
      mzd_write_bit(ret, i, j, m[i][j]);
    }
  }

  return ret;
}

int Gf2Matrix::height() const {
  return m.size();
}

int Gf2Matrix::width() const {
  return m.size() > 0 ? m[0].size() : 0;
}

std::vector<uint8_t> &Gf2Matrix::operator[](size_t index) {
  return m[index];
}

std::vector<uint8_t> const &Gf2Matrix::operator[](size_t index) const {
  return m[index];
}
