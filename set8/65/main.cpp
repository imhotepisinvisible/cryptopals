#include <iostream>
#include <vector>

#include <openssl/evp.h>

#include <m4ri/m4ri.h>

#include "crypto.h"
#include "utils.h"
#include "gf2_poly.h"
#include "gf2_matrix.h"

using namespace std;

int encrypt(unsigned char *plaintext, int plaintext_len,
	    unsigned char *key, unsigned char *iv,
	    unsigned char *ciphertext, unsigned char *tag) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new()))
    return 0;

  /* Initialise the encryption operation. */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
    return 0;

  /* Initialise key and IV */
  if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) return 0;

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    return 0;
  ciphertext_len = len;

  /* Finalise the encryption. Normally ciphertext bytes may be written at
   * this stage, but this does not occur in GCM mode
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    return 0;
  ciphertext_len += len;

  /* Get the tag */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 4, tag))
    return 0;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len,
	    unsigned char *tag, unsigned char *key, unsigned char *iv,
	    unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  int ret;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new()))
    return 0;

  /* Initialise the decryption operation. */
  if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
    return 0;

  /* Initialise key and IV */
  if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    return 0;

  /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 4, tag))
    return 0;
  
  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    return 0;
  plaintext_len = len;

  /* Finalise the decryption. A positive return value indicates success,
   * anything else is a failure - the plaintext is not trustworthy.
   */
  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  if(ret > 0)
    {
      /* Success */
      plaintext_len += len;
      return plaintext_len;
    }
  else
    {
      /* Verify failed */
      return -1;
    }
}

int forgeGcmTag_4byte(const unsigned char *ciphertext, const int ciphertext_len, const unsigned char *orig_ciphertext, const int orig_ciphertext_len, const unsigned char *orig_tag, const mpz_class &h, unsigned char **tag) {
  const int tag_len = 4;

  mpz_class orig_g = calculate_g(orig_ciphertext, orig_ciphertext_len, NULL, 0, h);

  mpz_class orig_t = block2fieldel(orig_tag);

  mpz_class s = gf2_sub(orig_t, orig_g);

  mpz_class g = calculate_g(ciphertext, ciphertext_len, NULL, 0, h);

  mpz_class t = gf2_add(g, s);

  *tag = fieldel2block(t);

  return tag_len;
}

vector<mzd_t *> makeAds(const int len, const Gf2Matrix &_Ms, const Gf2Matrix &_d0) {
  vector<mzd_t *> Ads;

  int cutoff = __M4RI_STRASSEN_MUL_CUTOFF;
  mzd_t *Ms = _Ms.to_m4ri();
  mzd_t *Msi = mzd_copy(NULL, Ms);
  mzd_t *d0 = _d0.to_m4ri();

  mpz_class mask(1);
  mpz_class maskmax("0x100000000000000000000000000000000");
  for (int i = 0; i < len; i++) {
    if (mask == maskmax) {
      mask = 1;
    }
    Gf2Matrix _di(mask);
    mzd_t *di = _di.to_m4ri();
    if (i > 0 && i % 128 == 0) {
      Msi = mzd_mul(NULL, Msi, Ms, cutoff);
    }
    mzd_t *Ad_tmp = mzd_mul(NULL, di, Msi, cutoff);
    mzd_t *Ad = mzd_add(NULL, Ad_tmp, d0);
    Ads.push_back(Ad);
    mask <<= 1;

    mzd_free(Ad_tmp);
    mzd_free(di);
  }

  mzd_free(Ms);
  mzd_free(Msi);
  mzd_free(d0);

  return Ads;
}

mzd_t *makeT(const int height, const int width, const int num_rows, const vector<mzd_t *> &Ads, const Gf2Matrix &_X) {
  cout << "Making T " << height << "x" << width << " blanking " << num_rows << " rows" << endl;

  int cutoff = __M4RI_STRASSEN_MUL_CUTOFF;
  mzd_t *T = mzd_init(height, width);
  mzd_t *X = _X.to_m4ri();

  for (int i = 0; i < T->ncols; i++) {
    mzd_t *Ad = mzd_mul(NULL, Ads[i], X, cutoff);
    for (int row = 0; row < num_rows; row++) {
      for (int col = 0; col < Ad->ncols; col++) {
	uint8_t bit = mzd_read_bit(Ad, row, col);
	mzd_write_bit(T, row*Ad->ncols+col, i, bit);
      }
    }
    mzd_free(Ad);
  }

  mzd_free(X);

  return T;
}

int main() {
  mpz_class m("0x100000000000000000000000000000087");

  const int n = 17;
  const int blockcount = 3;
  const int forged_blockcount = 1 << n; // blockcount = 2^17
  const int taglen = 4;

  Gf2Matrix Ms(128, 128);
  mpz_class mask(1);
  mpz_class tmp;
  vector<uint8_t> svec;
  
  for (int i = 0; i < Ms.width(); i++) {
    tmp = gf2_modmul(mask, mask, m);
    mask <<= 1;
    svec = fieldel2vector(tmp);
    for (int j = 0; j < svec.size(); j++) {
      Ms[j][i] = svec[j];
    }
  }

  vector<Gf2Matrix> Msis;
  Msis.push_back(Ms);
  Gf2Matrix Msi = Ms;
  for (int i = 1; i < n; i++) {
    Msi = Msi * Ms;
    Msis.push_back(Msi);
  }

  unsigned char len_block[16] = {0};
  uint64_t ciphertext_len_bits = reverse_uint64_t(16 * blockcount * 8);
  memcpy(len_block+8, &ciphertext_len_bits, sizeof(uint64_t));
  mpz_class len_poly = block2fieldel(len_block);

  unsigned char forged_len_block[16] = {0};
  ciphertext_len_bits = reverse_uint64_t(16 * forged_blockcount * 8);
  memcpy(forged_len_block+8, &ciphertext_len_bits, sizeof(uint64_t));
  len_poly = gf2_sub(len_poly, block2fieldel(forged_len_block));
  Gf2Matrix d0(len_poly);

  vector<mzd_t *> Ads = makeAds(n*128, Ms, d0);

  unsigned char key[16];
  arc4random_buf(key, 16);
  unsigned char nonce[12];
  arc4random_buf(nonce, 12);

  unsigned char *ciphertext = new unsigned char[16*blockcount];
  unsigned char *plaintext = new unsigned char[16*blockcount];
  memset(plaintext, 2, 16*blockcount);
  
  unsigned char tag[4];
  int ciphertext_len = encrypt(plaintext, 16*blockcount, key, nonce, ciphertext, tag);
  int forged_ciphertext_len = 16*forged_blockcount;

  Gf2Matrix X(128, 128);
  X = X.identity();
  int num_rows = n-1;
  mzd_t *n128_identity = mzd_init(n*128, n*128);
  mzd_set_ui(n128_identity, 1);
  unsigned char *forged_ciphertext = new unsigned char[forged_ciphertext_len];
  unsigned char *forged_res = new unsigned char[forged_ciphertext_len];

  for (int c = 0; 1; c++) {
    cout << "Loop: " << c+1 << endl;

    // NOTE: self written methods are too slow here, so m4ri library used
    // to complete challenge in reasonable time
    mzd_t *T = makeT(num_rows*X.width(), n*128, num_rows, Ads, X);
    cout << "Finding N(T)" << endl;
    mzd_t *Ttranspose = mzd_transpose(NULL, T);
    mzd_t *Ttid = mzd_concat(NULL, Ttranspose, n128_identity);
    mzd_echelonize(Ttid, 0);
    mzd_t *_Ttge = mzd_submatrix(NULL, Ttid, 0, 0, Ttid->nrows, Ttranspose->ncols);
    mzd_t *_Ttaugment = mzd_submatrix(NULL, Ttid, 0, Ttranspose->ncols, Ttid->nrows, Ttid->ncols);

    Gf2Matrix Ttge(_Ttge);
    Gf2Matrix Ttaugment(_Ttaugment);
    mzd_free(T);
    mzd_free(Ttranspose);
    mzd_free(Ttid);
    mzd_free(_Ttge);
    mzd_free(_Ttaugment);

    Gf2Matrix Tbasis = Ttge.basis(Ttaugment);

    cout << "N(T) size: " << Tbasis.width() << endl;

    vector<int> numbers;
    for (int i = 0; i < Tbasis.width(); i++) {
      numbers.push_back(i);
    }

    cout << "Attempting forgery..." << endl;
    // try forging...
    vector<uint8_t> finalbasis;
    int forgeries = 0;
    while (1) {
      forgeries++;
      int no_vectors = arc4random_uniform(Tbasis.width())+1;
      random_shuffle(numbers.begin(), numbers.end());

      vector<uint8_t> basis(Tbasis.height(), 0);
      for (int i = 0; i < no_vectors; i++) {
	for (int j = 0; j < Tbasis.height(); j++) {
	  basis[j] ^= Tbasis[j][numbers[i]];
	}
      }

      memset(forged_ciphertext, 0, forged_ciphertext_len);
      memcpy(forged_ciphertext+forged_ciphertext_len-ciphertext_len, ciphertext, ciphertext_len);
      for (int i = 0, byte = 0, mask = 0; i < basis.size(); /**/) {
	int block = i/128 + 1;
	block = 1 << block;
	block -= 2;
      
	// read the bits into a byte (assumes width is a multiple of 8)
	for (int j = 7; j >= 0; j--, i++) {
	  mask |= basis[i] << j;
	}
      
	// xor it into the forged ciphertext      
	*(forged_ciphertext+(forged_blockcount-1-block)*16+byte) ^= mask;
	byte = ++byte % 16;
	mask = 0;
      }
    
      // NOTE: self written methods are too slow here, so openssl library used
      // to complete challenge in reasonable time
      int forgery_decrypt_len = decrypt(forged_ciphertext, forged_ciphertext_len, tag, key, nonce, forged_res);
      if (forgery_decrypt_len != -1) {
	cout << "Forgery found after " << forgeries << " attempts" << endl;
	finalbasis = basis;
	break;
      }

      if (forgeries % 10000 == 0) {
	cout << forgeries << endl;
      }
    }

    // Create Ad
    Gf2Matrix Ad = d0;
    Gf2Matrix Mdis(128, 128);
    for (int i = 0; i < n; i++) {
      // build di
      mpz_class di;
      for (int j = 0; j < 128; j++) {
	if (finalbasis[i*128+j] == 1) {
	  mpz_setbit(di.get_mpz_t(), j);
	}
      }
      Gf2Matrix Mdi(di);
    
      // Ad = sum(Mdi * Ms^i)
      Mdis = Mdi * Msis[i];
      Ad = Ad + Mdis;
    }
    Ad = Ad * X;

    vector<int> Ad_nonzero;
    bool ones = false;
    for (int i = 0; i < taglen*8; i++) {
      for (int j = 0; j < Ad.width(); j++) {
	if (Ad[i][j] != 0) {
	  ones = true;
	  break;
	}
      }
      if (ones) {
	Ad_nonzero.push_back(i);
      }
      ones = false;
    }

    Gf2Matrix K(Ad_nonzero.size(), Ad.width());
    for (int i = 0; i < Ad_nonzero.size(); i++) {
      for (int j = 0; j < Ad.width(); j++) {
	K[i][j] = Ad[Ad_nonzero[i]][j];
      }
    }

    cout << "K: " << K.height() << "x" << K.width() << endl;

    Gf2Matrix Ktranspose = K.transpose();
    Gf2Matrix identity(Ad.width(), Ad.width());
    Gf2Matrix augment = identity.identity();
    Gf2Matrix Kge = Ktranspose.gaussian_elim(augment);
    Gf2Matrix newX = Kge.basis(augment);
    X = X * newX;

    num_rows = (n*128)/X.width();
    if (num_rows > 25) {
      num_rows = 25;
    }

    cout << "X: " << X.height() << "x" << X.width() << endl;

    // NOTE: the challenge states 'the endgame comes when K
    // has 127 linearly independent rows' but it seems more
    // straightforward to keep multiplying X in and ending
    // when X has 1 column
    if (X.width() == 1) {
      mpz_class h;
      for (int i = 0; i < X.height(); i++) {
	if (X[i][0] == 1) {
	  mpz_setbit(h.get_mpz_t(), i);
	}
      }

      unsigned char *forged_tag = NULL;
      const char *test_ciphertext = "Hello, World!";
      unsigned char test_res[128] = {0};
      forgeGcmTag_4byte((unsigned char *)test_ciphertext, strlen(test_ciphertext), ciphertext, ciphertext_len, tag, h, &forged_tag);
      int forgery_decrypt_len = decrypt((unsigned char *)test_ciphertext, strlen(test_ciphertext), forged_tag, key, nonce, test_res);
      if (forgery_decrypt_len != -1) {
	cout << "Found h! h = " << h << endl;
      } else {
	cout << "Didn't find h. Tried " << h << endl;
      }
      delete [] forged_tag;
      
      break;
    }
  }

  delete [] plaintext;
  delete [] ciphertext;
  delete [] forged_ciphertext;
  delete [] forged_res;
  mzd_free(n128_identity);
  for (int i = 0; i < Ads.size(); i++) {
    mzd_free(Ads[i]);
  }
  
  return 0;
}
