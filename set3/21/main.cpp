#include <iostream>
#include <cstdlib>
#include <random>

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

int main() {
  seed_mt(0);
  cout << "Custom implementation: " << extract_number() << endl;

  mt19937 stl_mt(0);
  cout << "STL MT implementation: " << stl_mt() << endl;
}
