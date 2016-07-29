#include <iostream>
#include <cstdlib>
#include <random>

#include "utils.h"
#include "conversions.h"

using namespace std;

//The constants w, n, m, r, a, u, d, s, b, t, c, l, and f
uint8_t  w = 32;
uint16_t n = 624;
uint16_t m = 397;
uint8_t  r = 31;
uint32_t a = 0x9908B0DF;
uint8_t  u = 11;
uint32_t d = 0xFFFFFFFF;
uint8_t  s = 7;
uint32_t b = 0x9D2C5680;
uint8_t  t = 15;
uint32_t c = 0xEFC60000;
uint8_t  l = 18;
uint32_t f = 1812433253;

// Create a length n array to store the state of the generator
uint32_t MT[624];//[n];
uint16_t idx = n+1;
const uint32_t lower_mask = (1 << r) - 1; // That is, the binary number of r 1's
const uint32_t upper_mask = 0xFFFFFFFF & ~lower_mask;

// Initialize the generator from a seed
void seed_mt(uint32_t seed) {
  idx = n;
  MT[0] = seed;
  for (size_t i = 1; i < n; i++) { // loop over each element
    MT[i] = 0xFFFFFFFF & (f * (MT[i-1] ^ (MT[i-1] >> (w-2))) + i);
  }
}

// Generate the next n values from the series x_i 
void twist() {
  for (size_t i = 0; i < n; i++) {
    uint32_t x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask);
    uint32_t xA = x >> 1;
    if ((x % 2) != 0) { // lowest bit of x is 1
      xA = xA ^ a;
    }
    MT[i] = MT[(i + m) % n] ^ xA;
  }
  idx = 0;
}

// Extract a tempered value based on MT[idx]
// calling twist() every n numbers
uint32_t extract_number() {
  if (idx >= n) {
    if (idx > n) {
      cout << "Generator was never seeded, seeding with constant value."
	   << " 5489 is used in reference C code" << endl;
      seed_mt(5489);
    }
    twist();
  }
 
  uint32_t y = MT[idx];
  y = y ^ ((y >> u) & d);
  y = y ^ ((y << s) & b);
  y = y ^ ((y << t) & c);
  y = y ^ (y >> l);
 
  idx = idx + 1;
  return 0xFFFFFFFF & y;
}

int encryptMersenne(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
  uint32_t num = 0;
  for (size_t i = 0; i < plaintext_len/4; i++) {
    num = extract_number();
    doXor(ciphertext, plaintext, (unsigned char *)&num, 4);
    ciphertext += 4;
    plaintext += 4;
  }

  num = extract_number();
  doXor(ciphertext, plaintext, (unsigned char *)&num, plaintext_len%4);

  return plaintext_len;
}

void getPasswordToken(char *token, int token_len) {
  std::time_t seed = std::time(0);
  seed_mt(seed);

  int tokenBytes_len = token_len/2;
  unsigned char *tokenBytes = new unsigned char[tokenBytes_len];
  unsigned char *tokenBytesStart = tokenBytes;
  uint32_t num = 0;
  for (size_t i = 0; i < tokenBytes_len/4; i++) {
    num = extract_number();
    memcpy(tokenBytes, &num, 4);
    tokenBytes += 4;
  }

  num = extract_number();
  memcpy(tokenBytes, &num, tokenBytes_len%4);

  bytesToHex(token, tokenBytesStart, tokenBytes_len);

  delete [] tokenBytesStart;

  return;
}

int checkPasswordToken(char *token) {
  int ret = 0;
  
  char testToken[32];
  getPasswordToken(testToken, 32);

  if (0 == strcmp(token, testToken)) {
    cout << "Tokens is the product of an MT19937 PRNG seeded with the current time" << endl;
    ret = 1;
  } else {
    cout << "Tokens is not is the product of an MT19937 PRNG seeded with the current time" << endl;
  }

  return ret;
}

int main() {
  uint16_t seed = 0;
  arc4random_buf(&seed, 2);
  const char *known_pt = "AAAAAAAAAAAAAA";

  int prefix_len = arc4random_uniform(50)+1;
  int plaintext_len = prefix_len + strlen(known_pt);
  unsigned char *randomprefix = new unsigned char[plaintext_len];
  arc4random_buf(randomprefix, prefix_len);
  memcpy(randomprefix+prefix_len, known_pt, strlen(known_pt));

  unsigned char *ciphertext = new unsigned char[plaintext_len];
  
  seed_mt(seed);
  cout << "Seed: " << seed << endl;
  encryptMersenne(randomprefix, plaintext_len, ciphertext);

  // Get the last 14 bytes of keystream
  unsigned char keystream[14];
  doXor(keystream, ciphertext+prefix_len, (unsigned char *)known_pt, 14);

  // Since we know the seed is 16 bits we can brute force it
  unsigned char potential_keystream[16];
  for (size_t i = 0; i < 0xffff; i++) {
    seed_mt(i);
    // skip random prefix
    for (size_t j = 0; j < prefix_len/4; j++) {
      extract_number();
    }
    uint32_t num = extract_number();
    memcpy(potential_keystream, ((char *)&num)+prefix_len%4, 4-prefix_len%4);
    int remaining = 14 - (4-prefix_len%4);
    while (remaining > 0) {
      num = extract_number();
      memcpy(potential_keystream+14-remaining, &num, 4);
      remaining -= 4;
    }

    if (0 == memcmp(keystream, potential_keystream, 14)) {
      cout << "Seed found! " << i << endl;
      break;
    }
  }

  delete [] randomprefix;
  delete [] ciphertext;

  // Password token
  char token[32];
  getPasswordToken(token, 32);
  cout << "Password token: " << token << endl;
  checkPasswordToken(token);
}
