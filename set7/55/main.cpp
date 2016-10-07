#include <iostream>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"
#include "md4.h"

using namespace std;

/* Some sample collisions found:
 * 5617DB11C1B7AF9FDEB7FA300ED360D8652FA6EFC38863F83FEEE60B4B5EDA4EBE5E807705CE014896B3A9998A264BD25E4964127567D55FECD254775A429204
 * 5617DB11C1B7AF1FDEB7FAA00ED360D8652FA6EFC38863F83FEEE60B4B5EDA4EBE5E807705CE014896B3A9998A264BD25E4963127567D55FECD254775A429204
 *
 * A1A4823AC479C0755CDC31ACE0884F49
 *
 * 94C4307946F27042CD89B9B40DCE85D54095015C60E7EFFF459179F26914683D18C7DD7C8C93FBCAD882DE5D032CFBA260A099C8476CF24B0826FBF4F704E57B
 * 94C4307946F270C2CD89B9240DCE85D54095015C60E7EFFF459179F26914683D18C7DD7C8C93FBCAD882DE5D032CFBA260A098C8476CF24B0826FBF4F704E57B
 *
 * 75E1A875C278A13633591475AD2FCF5B
 *
 * 0782BD4CCE44A51F386E6759E36FC4BD4AC0BDA6523D631AB718245A609CC9F93462CD272DD823CC7B466AFEEFB2BCF1F23EC112D375534C43C2B337B628CFB1
 * 0782BD4CCE44A59F386E67C9E36FC4BD4AC0BDA6523D631AB718245A609CC9F93462CD272DD823CC7B466AFEEFB2BCF1F23EC012D375534C43C2B337B628CFB1
 *
 * 91A16E1D54312876C9DDB55FDC15367B
 *
 */

// Defines from RFC 1392 https://tools.ietf.org/html/rfc1320
/* F, G and H are basic MD4 functions. */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

/* ROTATE_LEFT rotates x left n bits. */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
#define ROTATE_RIGHT(x, n) (((x) >> (n)) | ((x) << (32-(n))))

/* FF, GG and HH are transformations for rounds 1, 2 and 3 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s) { \
    (a) += F ((b), (c), (d)) + (x); \
    (a) = ROTATE_LEFT ((a), (s)); \
  }
#define GG(a, b, c, d, x, s) { \
    (a) += G ((b), (c), (d)) + (x) + (uint32_t)0x5a827999;	\
    (a) = ROTATE_LEFT ((a), (s)); \
  }
#define HH(a, b, c, d, x, s) { \
    (a) += H ((b), (c), (d)) + (x) + (uint32_t)0x6ed9eba1;	\
    (a) = ROTATE_LEFT ((a), (s)); \
  }

int main() {

  // Verify Wang's collision works
  const char *wangm_hex = "4d7a9c8356cb927ab9d5a57857a7a5eede748a3cdcc366b3b683a0203b2a5d9f"
    "c69d71b3f9e99198d79f805ea63bb2e845dd8e3197e31fe52794bf08b9e8c3e9";
  const char *wangm2_hex = "4d7a9c83d6cb927a29d5a57857a7a5eede748a3cdcc366b3b683a0203b2a5d9f"
    "c69d71b3f9e99198d79f805ea63bb2e845dc8e3197e31fe52794bf08b9e8c3e9";

  unsigned char wangm_bigendian[64];
  unsigned char wangm2_bigendian[64];
  hexToBytes(wangm_bigendian, wangm_hex);
  hexToBytes(wangm2_bigendian, wangm2_hex);

  uint32_t wangm[16];
  uint32_t wangm2[16];
  for (int i = 0; i < 16; i++) {
    wangm[i] = ntohl(*((uint32_t*)wangm_bigendian+i));
    wangm2[i] = ntohl(*((uint32_t*)wangm2_bigendian+i));
  }

  unsigned char wangm_hash[MD4_HASH_LEN];
  unsigned char wangm2_hash[MD4_HASH_LEN];
  
  MD4_CTX md4;

  MD4_Init(&md4);
  MD4_Update(&md4, wangm, 64);
  MD4_Final(wangm_hash, &md4);

  MD4_Init(&md4);
  MD4_Update(&md4, wangm2, 64);
  MD4_Final(wangm2_hash, &md4);

  if (memcmp(wangm_hash, wangm2_hash, MD4_HASH_LEN) == 0) {
    char wangm_hash_hex[MD4_HASH_LEN*2+1];
    bytesToHex(wangm_hash_hex, wangm_hash, MD4_HASH_LEN);
    wangm_hash_hex[MD4_HASH_LEN*2] = '\0';
    cout << "Wang collision verified, hash " << wangm_hash_hex << endl;
  }

  // Now try and find our own...
  uint32_t m[16] = {0};
  uint32_t m2[16] = {0};
  unsigned char m_hash[MD4_HASH_LEN];
  unsigned char m2_hash[MD4_HASH_LEN];
  uint32_t a[16] = {0};
  uint32_t b[16] = {0};
  uint32_t c[16] = {0};
  uint32_t d[16] = {0};
  a[0] = 0x67452301;
  b[0] = 0xefcdab89;
  c[0] = 0x98badcfe;
  d[0] = 0x10325476;
  
  int iterations = 1;
  int i = 0;
  int j = 0;
  int k = 0;
  while(1) {
    arc4random_buf(m, 64);

    i = 1;
    j = 0;
    //a1,7=b0,7
    // calculate the new value for a[1] in the normal fashion
    a[i] = a[i-1];
    FF(a[i], b[i-1], c[i-1], d[i-1], m[j], 3);

    // correct the erroneous bit
    a[i] ^= ((a[i] ^ b[i-1]) & (1 << 6));

    // use algebra to correct the first message block
    m[j] = ROTATE_RIGHT(a[i], 3) - a[i-1] - F(b[i-1], c[i-1], d[i-1]);

    j++;
  
    //d1,7=0, d1,8=a1,8, d1,11=a1,11
    d[i] = d[i-1];
    FF(d[i], a[i], b[i-1], c[i-1], m[j], 7);

    d[i] &= ~(1 << 6);
    d[i] ^= ((d[i] ^ a[i]) & (1 << 7));
    d[i] ^= ((d[i] ^ a[i]) & (1 << 10));

    m[j] = ROTATE_RIGHT(d[i], 7) - d[i-1] - F(a[i], b[i-1], c[i-1]);

    j++;
  
    //c1,7=1, c1,8=1, c1,11=0, c1,26=d1,26
    c[i] = c[i-1];
    FF(c[i], d[i], a[i], b[i-1], m[j], 11);

    c[i] |= (1 << 6);
    c[i] |= (1 << 7);
    c[i] &= ~(1 << 10);
    c[i] ^= ((c[i] ^ d[i]) & (1 << 25));

    m[j] = ROTATE_RIGHT(c[i], 11) - c[i-1] - F(d[i], a[i], b[i-1]);

    j++;
  
    //b1,7=1, b1,8=0, b1,11=0, b1,26=0
    b[i] = b[i-1];
    FF(b[i], c[i], d[i], a[i], m[j], 19);

    b[i] |= (1 << 6);
    b[i] &= ~(1 << 7);
    b[i] &= ~(1 << 10);
    b[i] &= ~(1 << 25);

    m[j] = ROTATE_RIGHT(b[i], 19) - b[i-1] - F(c[i], d[i], a[i]);

    j++;
    i++;
  
    //a2,8=1, a2,11=1, a2,26=0, a2,14=b1,14
    a[i] = a[i-1];
    FF(a[i], b[i-1], c[i-1], d[i-1], m[j], 3);

    a[i] |= (1 << 7);
    a[i] |= (1 << 10);
    a[i] &= ~(1 << 25);
    a[i] ^= ((a[i] ^ b[i-1]) & (1 << 13));

    m[j] = ROTATE_RIGHT(a[i], 3) - a[i-1] - F(b[i-1], c[i-1], d[i-1]);

    j++;
  
    //d2,14=0, d2,19=a2,19, d2,20=a2,20, d2,21=a2,21, d2,22=a2,22, d2,26=1
    d[i] = d[i-1];
    FF(d[i], a[i], b[i-1], c[i-1], m[j], 7);

    d[i] &= ~(1 << 13);
    d[i] ^= ((d[i] ^ a[i]) & (1 << 18));
    d[i] ^= ((d[i] ^ a[i]) & (1 << 19));
    d[i] ^= ((d[i] ^ a[i]) & (1 << 20));
    d[i] ^= ((d[i] ^ a[i]) & (1 << 21));
    d[i] |= (1 << 25);

    m[j] = ROTATE_RIGHT(d[i], 7) - d[i-1] - F(a[i], b[i-1], c[i-1]);

    j++;

    //c2,13=d2,13, c2,14=0, c2,15=d2,15, c2,19=0, c2,20=0, c2,21=1, c2,22=0
    c[i] = c[i-1];
    FF(c[i], d[i], a[i], b[i-1], m[j], 11);

    c[i] ^= ((c[i] ^ d[i]) & (1 << 12));
    c[i] &= ~(1 << 13);
    c[i] ^= ((c[i] ^ d[i]) & (1 << 14));
    c[i] &= ~(1 << 18);
    c[i] &= ~(1 << 19);
    c[i] |= (1 << 20);
    c[i] &= ~(1 << 21);

    m[j] = ROTATE_RIGHT(c[i], 11) - c[i-1] - F(d[i], a[i], b[i-1]);

    j++;

    //b2,13=1, b2,14=1, b2,15=0, b2,17=c2,17, b2,19=0, b2,20=0, b2,21=0, b2,22=0
    b[i] = b[i-1];
    FF(b[i], c[i], d[i], a[i], m[j], 19);

    b[i] |= (1 << 12);
    b[i] |= (1 << 13);
    b[i] &= ~(1 << 14);
    b[i] ^= ((b[i] ^ c[i]) & (1 << 16));
    b[i] &= ~(1 << 18);
    b[i] &= ~(1 << 19);
    b[i] &= ~(1 << 20);
    b[i] &= ~(1 << 21);

    m[j] = ROTATE_RIGHT(b[i], 19) - b[i-1] - F(c[i], d[i], a[i]);

    j++;
    i++;
  
    //a3,13=1, a3,14=1, a3,15=1, a3,17=0, a3,19=0, a3,20=0, a3,21=0, a3,23=b2,23 a3,22=1, a3,26=b2,26
    a[i] = a[i-1];
    FF(a[i], b[i-1], c[i-1], d[i-1], m[j], 3);

    a[i] |= (1 << 12);
    a[i] |= (1 << 13);
    a[i] |= (1 << 14);
    a[i] &= ~(1 << 16);
    a[i] &= ~(1 << 18);
    a[i] &= ~(1 << 19);
    a[i] &= ~(1 << 20);
    a[i] ^= ((a[i] ^ b[i-1]) & (1 << 22));
    a[i] |= (1 << 21);
    a[i] ^= ((a[i] ^ b[i-1]) & (1 << 25));

    m[j] = ROTATE_RIGHT(a[i], 3) - a[i-1] - F(b[i-1], c[i-1], d[i-1]);

    j++;
  
    //d3,13=1, d3,14=1, d3,15=1, d3,17=0, d3,20=0, d3,21=1, d3,22=1, d3,23=0, d3,26=1, d3,30=a3,30
    d[i] = d[i-1];
    FF(d[i], a[i], b[i-1], c[i-1], m[j], 7);

    d[i] |= (1 << 12);
    d[i] |= (1 << 13);
    d[i] |= (1 << 14);
    d[i] &= ~(1 << 16);
    d[i] &= ~(1 << 19);
    d[i] |= (1 << 20);
    d[i] |= (1 << 21);
    d[i] &= ~(1 << 22);
    d[i] |= (1 << 25);
    d[i] ^= ((d[i] ^ a[i]) & (1 << 29));

    m[j] = ROTATE_RIGHT(d[i], 7) - d[i-1] - F(a[i], b[i-1], c[i-1]);

    j++;

    //c3,17=1, c3,20=0, c3,21=0, c3,22=0, c3,23=0, c3,26=0, c3,30=1, c3,32=d3,32
    c[i] = c[i-1];
    FF(c[i], d[i], a[i], b[i-1], m[j], 11);

    c[i] |= (1 << 16);
    c[i] &= ~(1 << 19);
    c[i] &= ~(1 << 20);
    c[i] &= ~(1 << 21);
    c[i] &= ~(1 << 22);
    c[i] &= ~(1 << 25);
    c[i] |= (1 << 29);
    c[i] ^= ((c[i] ^ d[i]) & (1 << 31));

    m[j] = ROTATE_RIGHT(c[i], 11) - c[i-1] - F(d[i], a[i], b[i-1]);

    j++;
  
    //b3,20=0, b3,21=1, b3,22=1, b3,23=c3,23, b3,26=1, b3,30=0, b3,32=0
    b[i] = b[i-1];
    FF(b[i], c[i], d[i], a[i], m[j], 19);

    b[i] &= ~(1 << 19);
    b[i] |= (1 << 20);
    b[i] |= (1 << 21);
    b[i] ^= ((b[i] ^ c[i]) & (1 << 22));
    b[i] |= (1 << 25);
    b[i] &= ~(1 << 29);
    b[i] &= ~(1 << 31);

    m[j] = ROTATE_RIGHT(b[i], 19) - b[i-1] - F(c[i], d[i], a[i]);

    j++;
    i++;

    //a4,23=0, a4,26=0, a4,27=b3,27, a4,29=b3,29, a4,30=1, a4,32=0
    a[i] = a[i-1];
    FF(a[i], b[i-1], c[i-1], d[i-1], m[j], 3);

    a[i] &= ~(1 << 22);
    a[i] &= ~(1 << 25);
    a[i] ^= ((a[i] ^ b[i-1]) & (1 << 26));
    a[i] ^= ((a[i] ^ b[i-1]) & (1 << 28));
    a[i] |= (1 << 29);
    a[i] &= ~(1 << 31);

    m[j] = ROTATE_RIGHT(a[i], 3) - a[i-1] - F(b[i-1], c[i-1], d[i-1]);

    j++;
  
    //d4,23=0, d4,26=0, d4,27=1, d4,29=1, d4,30=0, d4,32=1
    d[i] = d[i-1];
    FF(d[i], a[i], b[i-1], c[i-1], m[j], 7);

    d[i] &= ~(1 << 22);
    d[i] &= ~(1 << 25);
    d[i] |= (1 << 26);
    d[i] |= (1 << 28);
    d[i] &= ~(1 << 29);
    d[i] |= (1 << 31);

    m[j] = ROTATE_RIGHT(d[i], 7) - d[i-1] - F(a[i], b[i-1], c[i-1]);

    j++;
  
    //c4,19=d4,19, c4,23=1, c4,26=1, c4,27=0, c4,29=0, c4,30=0
    c[i] = c[i-1];
    FF(c[i], d[i], a[i], b[i-1], m[j], 11);

    c[i] ^= ((c[i] ^ d[i]) & (1 << 18));
    c[i] |= (1 << 22);
    c[i] |= (1 << 25);
    c[i] &= ~(1 << 26);
    c[i] &= ~(1 << 28);
    c[i] &= ~(1 << 29);

    m[j] = ROTATE_RIGHT(c[i], 11) - c[i-1] - F(d[i], a[i], b[i-1]);

    j++;
  
    //b4,19=0, b4,26=c4,26=1, b4,27=1, b4,29=1, b4,30=0
    b[i] = b[i-1];
    FF(b[i], c[i], d[i], a[i], m[j], 19);

    b[i] &= ~(1 << 18);
    b[i] ^= ((b[i] ^ c[i]) & (1 << 25));
    b[i] |= (1 << 26);
    b[i] |= (1 << 28);
    b[i] &= ~(1 << 29);

    m[j] = ROTATE_RIGHT(b[i], 19) - b[i-1] - F(c[i], d[i], a[i]);

    // Set a5 and d5
    j=0;
    i++;
    a[i] = a[i-1];
    GG(a[i], b[i-1], c[i-1], d[i-1], m[j], 3);
    
    j=4;
    d[i] = d[i-1];
    GG(d[i], a[i], b[i-1], c[i-1], m[j], 5);
    
    // Round 2: Table 1
    j = 0;
    i = 1;
    k = 19;
    if ((a[5] ^ c[4]) & (1 << (k-1))) {
      m[j] ^= (1 << (k-4));
      a[i] = a[i-1];
      FF(a[i], b[i-1], c[i-1], d[i-1], m[j], 3);
      j++;
      m[j] = ROTATE_RIGHT(d[i], 7) - d[i-1] - F(a[i], b[i-1], c[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(c[i], 11) - c[i-1] - F(d[i], a[i], b[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(b[i], 19) - b[i-1] - F(c[i], d[i], a[i]);
      j++;
      i++;
      m[j] = ROTATE_RIGHT(a[i], 3) - a[i-1] - F(b[i-1], c[i-1], d[i-1]);
    }

    j = 0;
    i = 1;
    k = 26;
    if (!(a[5] & (1 << (k-1)))) {
      m[j] ^= (1 << (k-4));
      a[i] = a[i-1];
      FF(a[i], b[i-1], c[i-1], d[i-1], m[j], 3);
      j++;
      m[j] = ROTATE_RIGHT(d[i], 7) - d[i-1] - F(a[i], b[i-1], c[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(c[i], 11) - c[i-1] - F(d[i], a[i], b[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(b[i], 19) - b[i-1] - F(c[i], d[i], a[i]);
      j++;
      i++;
      m[j] = ROTATE_RIGHT(a[i], 3) - a[i-1] - F(b[i-1], c[i-1], d[i-1]);
    }
  
    j = 0;
    i = 1;
    k = 27;
    if (a[5] & (1 << (k-1))) {
      m[j] ^= (1 << (k-4));
      a[i] = a[i-1];
      FF(a[i], b[i-1], c[i-1], d[i-1], m[j], 3);
      j++;
      m[j] = ROTATE_RIGHT(d[i], 7) - d[i-1] - F(a[i], b[i-1], c[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(c[i], 11) - c[i-1] - F(d[i], a[i], b[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(b[i], 19) - b[i-1] - F(c[i], d[i], a[i]);
      j++;
      i++;
      m[j] = ROTATE_RIGHT(a[i], 3) - a[i-1] - F(b[i-1], c[i-1], d[i-1]);
    }

    j = 0;
    i = 1;
    k = 29;
    if (!(a[5] & (1 << (k-1)))) {
      m[j] ^= (1 << (k-4));
      a[i] = a[i-1];
      FF(a[i], b[i-1], c[i-1], d[i-1], m[j], 3);
      j++;
      m[j] = ROTATE_RIGHT(d[i], 7) - d[i-1] - F(a[i], b[i-1], c[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(c[i], 11) - c[i-1] - F(d[i], a[i], b[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(b[i], 19) - b[i-1] - F(c[i], d[i], a[i]);
      j++;
      i++;
      m[j] = ROTATE_RIGHT(a[i], 3) - a[i-1] - F(b[i-1], c[i-1], d[i-1]);
    }
  
    j = 0;
    i = 1;
    k = 32;
    if (!(a[5] & (1 << (k-1)))) {
      m[j] ^= (1 << (k-4));
      a[i] = a[i-1];
      FF(a[i], b[i-1], c[i-1], d[i-1], m[j], 3);
      j++;
      m[j] = ROTATE_RIGHT(d[i], 7) - d[i-1] - F(a[i], b[i-1], c[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(c[i], 11) - c[i-1] - F(d[i], a[i], b[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(b[i], 19) - b[i-1] - F(c[i], d[i], a[i]);
      j++;
      i++;
      m[j] = ROTATE_RIGHT(a[i], 3) - a[i-1] - F(b[i-1], c[i-1], d[i-1]);
    }
  
    j = 4;
    i = 2;
    k = 19;
    if ((d[5] ^ a[5]) & (1 << (k-1))) {
      m[j] ^= (1 << (k-4));
      a[i] = a[i-1];
      FF(a[i], b[i-1], c[i-1], d[i-1], m[j], 3);
      j++;
      m[j] = ROTATE_RIGHT(d[i], 7) - d[i-1] - F(a[i], b[i-1], c[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(c[i], 11) - c[i-1] - F(d[i], a[i], b[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(b[i], 19) - b[i-1] - F(c[i], d[i], a[i]);
      j++;
      i++;
      m[j] = ROTATE_RIGHT(a[i], 3) - a[i-1] - F(b[i-1], c[i-1], d[i-1]);
    }

    j = 4;
    i = 2;
    k = 26;
    if ((d[5] ^ b[4]) & (1 << (k-1))) {
      m[j] ^= (1 << (k-4));
      a[i] = a[i-1];
      FF(a[i], b[i-1], c[i-1], d[i-1], m[j], 3);
      j++;
      m[j] = ROTATE_RIGHT(d[i], 7) - d[i-1] - F(a[i], b[i-1], c[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(c[i], 11) - c[i-1] - F(d[i], a[i], b[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(b[i], 19) - b[i-1] - F(c[i], d[i], a[i]);
      j++;
      i++;
      m[j] = ROTATE_RIGHT(a[i], 3) - a[i-1] - F(b[i-1], c[i-1], d[i-1]);
    }
  
    j = 4;
    i = 2;
    k = 27;
    if ((d[5] ^ b[4]) & (1 << (k-1))) {
      m[j] ^= (1 << (k-4));
      a[i] = a[i-1];
      FF(a[i], b[i-1], c[i-1], d[i-1], m[j], 3);
      j++;
      m[j] = ROTATE_RIGHT(d[i], 7) - d[i-1] - F(a[i], b[i-1], c[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(c[i], 11) - c[i-1] - F(d[i], a[i], b[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(b[i], 19) - b[i-1] - F(c[i], d[i], a[i]);
      j++;
      i++;
      m[j] = ROTATE_RIGHT(a[i], 3) - a[i-1] - F(b[i-1], c[i-1], d[i-1]);
    }
  
    j = 4;
    i = 2;
    k = 29;
    if ((d[5] ^ b[4]) & (1 << (k-1))) {
      m[j] ^= (1 << (k-4));
      a[i] = a[i-1];
      FF(a[i], b[i-1], c[i-1], d[i-1], m[j], 3);
      j++;
      m[j] = ROTATE_RIGHT(d[i], 7) - d[i-1] - F(a[i], b[i-1], c[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(c[i], 11) - c[i-1] - F(d[i], a[i], b[i-1]);
      j++;
      m[j] = ROTATE_RIGHT(b[i], 19) - b[i-1] - F(c[i], d[i], a[i]);
      j++;
      i++;
      m[j] = ROTATE_RIGHT(a[i], 3) - a[i-1] - F(b[i-1], c[i-1], d[i-1]);
    }
  
    for (int i = 0; i < 16; i++) {
      m2[i] = m[i];
    }

    // Not clear if this differential should be ^ or +/- - both work
    //m2[1] += 0x80000000;
    //m2[2] += 0x70000000;
    //m2[12] -= 0x10000;
    m2[1] ^= 0x80000000;
    m2[2] ^= 0x90000000;
    m2[12] ^= 0x10000;
    
    MD4_Init(&md4);
    MD4_Update(&md4, m, 64);
    MD4_Final(m_hash, &md4);

    MD4_Init(&md4);
    MD4_Update(&md4, m2, 64);
    MD4_Final(m2_hash, &md4);

    if (memcmp(m_hash, m2_hash, MD4_HASH_LEN) == 0) {
      cout << "Collision found after " << iterations << " iterations" << endl;
      break;
    }

    // Wang suggests if we don't find a collision to only
    // adjust m[14] and m[15], but clearing the whole thing
    // seems more effective
    //arc4random_buf(&m[14], 8);

    if ((iterations % 1000000) == 0)
      cout << iterations << endl;
    iterations++;
  }

  char m_hex[64*2+1];
  char m2_hex[64*2+1];

  bytesToHex(m_hex, (unsigned char *)m, 64);
  m_hex[64*2] = '\0';
  bytesToHex(m2_hex, (unsigned char *)m2, 64);
  m2_hex[64*2] = '\0';

  char m_hash_hex[MD4_HASH_LEN*2+1];
  char m2_hash_hex[MD4_HASH_LEN*2+1];
  
  bytesToHex(m_hash_hex, m_hash, MD4_HASH_LEN);
  m_hash_hex[MD4_HASH_LEN*2] = '\0';
  bytesToHex(m2_hash_hex, m2_hash, MD4_HASH_LEN);
  m2_hash_hex[MD4_HASH_LEN*2] = '\0';

  cout << m_hex << endl;
  cout << m2_hex << endl << endl;
  cout << m_hash_hex << endl;
  cout << m2_hash_hex << endl;
}
