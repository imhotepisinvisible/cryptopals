#include <iostream>

#include <openssl/rc4.h>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

void rc4_oracle(unsigned char *ciphertext, const unsigned char *request, const int request_len) {
  const char *token_b64 = "QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F";
  unsigned char token[64] = {0};
  int token_len = b64ToBytes(token, token_b64);

  if (request_len < 128 - token_len) {
    unsigned char key[16];
    arc4random_buf(key, 16);
    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, 16, key);

    unsigned char plaintext[128] = {0};
    memcpy(plaintext, request, request_len);
    memcpy(plaintext+request_len, token, token_len);
    int plaintext_len = token_len+request_len;

    RC4(&rc4_key, plaintext_len, plaintext, ciphertext);
  }
}

int main() {
  const unsigned char *filler = (unsigned char *)"AAAAAAAAAAAAAAA";
  unsigned char ciphertext[128] = {0};
  unsigned char plaintext[128] = {0};

  uint32_t N1[256];
  uint32_t N2[256];
  uint32_t Nk1[256];
  uint32_t Nk2[256];
  char Pr1;
  char Pr2;
  uint32_t lambda16;
  uint32_t lambda32;

  for (int c = 0; c < 16; c++) {
    Pr1 = 0;
    Pr2 = 0;
    lambda16 = 0;
    lambda32 = 0;
    for (int i = 0; i < 256; i++) {
      N1[i] = 0;
      N2[i] = 0;
    }

    for (int i = 0; i < 0x1000000; i++) {
      rc4_oracle(ciphertext, filler, 15-c);

      N1[ciphertext[15]]++;
      N2[ciphertext[31]]++;
    }

    for (int mu = 0; mu < 256; mu++) {
      for (int i = 0 ; i < 256; i++) {
	Nk1[i] = 0;
	Nk2[i] = 0;
      }
      for (int k = 0; k < 256; k++) {
	Nk1[k] = N1[mu^k];
	Nk2[k] = N2[mu^k];
      }

      // In the paper a bias map for all bytes is built here
      // As recommended in the challenge, easier just to use the
      // heavy bias for bytes 16 and 32
      if (Nk1[240] > lambda16) {
	lambda16 = Nk1[240];
	Pr1 = mu;
      }
      if (Nk2[224] > lambda32) {
	lambda32 = Nk2[224];
	Pr2 = mu;
      }
    }

    plaintext[c] = Pr1;
    if (c+16 < 30) {
      plaintext[c+16] = Pr2;
    }
    cout << "." << flush;
  }
  cout << endl << plaintext << endl;
  
  return 0;
}
