#include <iostream>
#include <vector>
#include <set>

#include "crypto.h"
#include "utils.h"
#include "gf2_poly.h"
#include "gf2128_poly.h"

using namespace std;

map<mappoly, int> sff(const mappoly &f) {
  map<mappoly, int> R;
  mpz_class gf2_one(1);
  mappoly one;
  one[0] = gf2_one;
  mappoly zero;

  if (f.rbegin()->second != gf2_one) {
    cout << "Error, input to sff was not monic" << endl;
  } else {
    int i = 1;
    R[one] = 1;
    mappoly f2;
    mappoly g = gf2128_derivative(f);

    if (!g.empty()) {
      mappoly c = gf2128_gcd(f, g);
      mappoly w = gf2128_div(f, c);
      while (w != one) {
	mappoly y = gf2128_gcd(w, c);
	mappoly z = gf2128_div(w, y);
	R[z] = i++;
	w = y;
	c = gf2128_div(c, y);
      }
      if (c != one) {
	c = gf2128_divexp(c, 2);
	map<mappoly, int> sffc = sff(c);
	for (map<mappoly, int>::const_iterator it=sffc.begin(); it!=sffc.end(); ++it) {
	  R[it->first] = it->second * 2 + R[it->first];
	}
      }
    } else {
      f2 = gf2128_divexp(f, 2);
      R = sff(f2);
      for (map<mappoly, int>::const_iterator it=R.begin(); it!=R.end(); ++it) {
	R[it->first] = it->second * 2;
      }
    }
  }

  return R;
}

set< pair<mappoly, int> > ddf(const mappoly &f) {
  set< pair<mappoly, int> > ret;
  int i = 1;
  mappoly f2 = f;
  mpz_class gf2_one(1);
  mappoly one;
  one[0] = gf2_one;

  if (f.rbegin()->second != gf2_one) {
    cout << "Error, input to ddf was not monic" << endl;
  } else {
    mappoly x;
    x[1] = gf2_one;
    mappoly xx = x;

    mpz_class q("0x100000000000000000000000000000000");

    mappoly xqi;
    pair<mappoly, mappoly> gcd;
    mappoly g;

    while(gf2128_deg(f2) >= i*2) {
      xx = gf2128_modexp(xx, q, f2);
      xqi = gf2128_add(xx, x);
      g = gf2128_gcd(f2, xqi);
      if (g != one) {
	pair<mappoly, int> pairret(g, i);
	ret.insert(pairret);
	f2 = gf2128_div(f2, g);
      }
      i++;
    }

    if (f2 != one) {
      pair<mappoly, int> pairret(f2, gf2128_deg(f2));
      ret.insert(pairret);
    }

    if (ret.empty()) {
      pair<mappoly, int> pairret(f, 1);
      ret.insert(pairret);
    }
  }

  return ret;
}

/*
 *  function edf(f, d):
 *      n := deg(f)
 *      r := n / d
 *      S := {f}
 *
 *      while len(S) < r:
 *          h := random_polynomial(1, f)
 *          g := gcd(h, f)
 *
 *          if g = 1:
 *              g := h^((q^d - 1)/3) - 1 mod f
 *
 *          for u in S:
 *              if deg(u) = d:
 *                  continue
 *
 *              if gcd(g, u) =/= 1 and gcd(g, u) =/= u:
 *                  S := union(S - {u}, {gcd(g, u), u / gcd(g, u)})
 *
 *      return S
 */
set<mappoly> edf(const mappoly &f, const int d) {
  set<mappoly> ret;
  
  int n = gf2128_deg(f);
  int r = n / d;
  ret.insert(f);

  mpz_class gf2_one(1);
  mappoly one;
  one[0] = gf2_one;

  if (f.rbegin()->second != gf2_one) {
    cout << "Error, input to edf was not monic" << endl;
  } else {
    mpz_class q("0x100000000000000000000000000000000");

    while (ret.size() < r) {
      mappoly h = gf2128_rand(n);
      mappoly g = gf2128_gcd(h, f);

      if (g == one) {
	mpz_class qd;
	mpz_pow_ui(qd.get_mpz_t(), q.get_mpz_t(), d);
	qd = (qd - 1)/3;
	g = gf2128_modexp(h, qd, f);
	g = gf2128_sub(g, one);
      }

      for (set<mappoly>::iterator it=ret.begin(); it!=ret.end(); /**/) {
	if (gf2128_deg(*it) == d) {
	  ++it;
	  continue;
	}

	mappoly gcd = gf2128_gcd(g, *it);
	if (gcd != one && gcd != *it) {
	  mappoly div = gf2128_div(*it, gcd);
	  ret.erase(it++);
	  ret.insert(gcd);
	  ret.insert(div);
	} else {
	  ++it;
	}
      }
    }
  }

  return ret;
}

mappoly ciphertext2mappoly(const unsigned char *ciphertext, const int ciphertext_len, const unsigned char *aad, const int aad_len) {
  mappoly ret;

  const int blocksize = 16;

  // Pad AAD
  int aad_no_blocks = aad_len/blocksize + (aad_len % blocksize ? 1 : 0);
  unsigned char *aad_padded = new unsigned char[aad_no_blocks*blocksize];
  memcpy(aad_padded, aad, aad_len);
  memset(aad_padded+aad_len, 0, (aad_no_blocks*blocksize)-aad_len);

  // Pad ciphertext
  int ciphertext_no_blocks = ciphertext_len/blocksize + (ciphertext_len % blocksize ? 1 : 0);
  unsigned char *ciphertext_padded = new unsigned char[ciphertext_no_blocks*blocksize];
  memcpy(ciphertext_padded, ciphertext, ciphertext_len);
  memset(ciphertext_padded+ciphertext_len, 0, (ciphertext_no_blocks*blocksize)-ciphertext_len);

  unsigned char len_block[blocksize] = {0};
  uint64_t aad_len_bits = reverse_uint64_t(aad_len * 8);
  memcpy(len_block, &aad_len_bits, sizeof(uint64_t));
  uint64_t ciphertext_len_bits = reverse_uint64_t(ciphertext_len * 8);
  memcpy(len_block+8, &ciphertext_len_bits, sizeof(uint64_t));

  int i = 1;

  ret[i++] = block2fieldel(len_block);

  for (int j = ciphertext_no_blocks-1; j >= 0; j--) {
    ret[i++] = block2fieldel(ciphertext_padded+j*blocksize);
  }

  for (int j = aad_no_blocks-1; j >= 0; j--) {
    ret[i++] = block2fieldel(aad_padded+j*blocksize);
  }

  delete [] aad_padded;
  delete [] ciphertext_padded;
  return ret;
}

int forgeGcmTag(const unsigned char *ciphertext, const int ciphertext_len, const unsigned char *aad, const int aad_len, const unsigned char *orig_ciphertext, const int orig_ciphertext_len, const unsigned char *orig_aad, const int orig_aad_len, const mpz_class &h, unsigned char **tag) {
  const int tag_len = 16;

  mpz_class orig_g = calculate_g(orig_ciphertext, orig_ciphertext_len-16, orig_aad, orig_aad_len, h);

  mpz_class orig_t = block2fieldel(orig_ciphertext+orig_ciphertext_len-16);

  mpz_class s = gf2_sub(orig_t, orig_g);

  mpz_class g = calculate_g(ciphertext, ciphertext_len, aad, aad_len, h);

  mpz_class t = gf2_add(g, s);

  *tag = fieldel2block(t);

  return tag_len;
}

int main() {
  unsigned char key[16];
  arc4random_buf(key, 16);
  unsigned char nonce[12];
  arc4random_buf(nonce, 12);

  unsigned char test_ciphertext[128] = {0};
  unsigned char test_plaintext_res[128] = {0};
  const char *test_plaintext = "Hello, World!";
  const char *test_aad = "Goodbye, World!";

  int test_ciphertext_len = encryptGcm((unsigned char *)test_plaintext, strlen(test_plaintext), (unsigned char *)test_aad, strlen(test_aad), key, nonce, test_ciphertext);

  int test_plaintext_len = decryptGcm(test_ciphertext, test_ciphertext_len, (unsigned char *)test_aad, strlen(test_aad), key, nonce, test_plaintext_res);
  test_plaintext_res[test_plaintext_len] = '\0';
  
  if (test_plaintext_len == 0) {
    cout << "Error decrypting" << endl;
  } else {
    cout << test_plaintext_res << endl;
  }
  
  unsigned char ciphertext[128] = {0};
  unsigned char plaintext[64];
  memset(plaintext, 2, sizeof(plaintext));
  unsigned char aad[32];
  memset(aad, 3, sizeof(aad));
  
  int ciphertext_len = encryptGcm(plaintext, sizeof(plaintext), aad, sizeof(aad), key, nonce, ciphertext);

  mappoly first = ciphertext2mappoly(ciphertext, sizeof(plaintext), aad, sizeof(aad));
  mpz_class t0 = block2fieldel(ciphertext+sizeof(plaintext));
  first[0] = t0;

  unsigned char ciphertext2[128] = {0};
  unsigned char plaintext2[64];
  memset(plaintext2, 7, sizeof(plaintext2));
  unsigned char aad2[32];
  memset(aad2, 8, sizeof(aad2));
  
  encryptGcm(plaintext2, sizeof(plaintext2), aad2, sizeof(aad2), key, nonce, ciphertext2);
  
  mappoly second = ciphertext2mappoly(ciphertext2, sizeof(plaintext2), aad2, sizeof(aad2));
  mpz_class t1 = block2fieldel(ciphertext2+sizeof(plaintext2));
  second[0] = t1;

  mappoly a = gf2128_add(first, second);

  cout << "Factoring polynomial..." << endl;

  mappoly amonic = gf2128_makemonic(a);

  map<mappoly, int> mysff = sff(amonic);

  vector< set< pair<mappoly, int> > > ddfs;
  for (map<mappoly, int>::const_iterator it=mysff.begin(); it!=mysff.end(); ++it) {
    set< pair<mappoly, int> > myddf = ddf(it->first);
    ddfs.push_back(myddf);
  }

  vector< set<mappoly> > edfs;
  for (int i = 0; i < ddfs.size(); i++) {
    for (set< pair<mappoly, int> >::iterator it=ddfs[i].begin(); it!=ddfs[i].end(); ++it) {
      set<mappoly> myedf = edf(it->first, it->second);
      edfs.push_back(myedf);
    }
  }

  // Now attempt a forgery with each candidate
  for (int i = 0; i < edfs.size(); i++) {
    for (set<mappoly>::iterator it=edfs[i].begin(); it!=edfs[i].end(); ++it) {
      if (gf2128_deg(*it) == 1) {
	cout << "Candidate found, attempting forgery..." << endl;
	mpz_class candidate_h = (*it).at(0);
	unsigned char *tag = NULL;
	int tag_len = forgeGcmTag((unsigned char *)test_plaintext, strlen(test_plaintext), (unsigned char *)test_aad, strlen(test_aad), ciphertext, ciphertext_len, aad, sizeof(aad), candidate_h, &tag);
	unsigned char forged_ciphertext[strlen(test_plaintext)+tag_len];
	memcpy(forged_ciphertext, test_plaintext, strlen(test_plaintext));
	memcpy(forged_ciphertext+strlen(test_plaintext), tag, tag_len);
	int forgery_decrypt_len = decryptGcm(forged_ciphertext, strlen(test_plaintext)+tag_len, (unsigned char *)test_aad, strlen(test_aad), key, nonce, test_plaintext_res);
	if (forgery_decrypt_len != 0) {
	  cout << "Found h! h = " << hex << candidate_h << endl;
	  break;
	}
      }
    }
  }
  
  return 0;
}
