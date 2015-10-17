#include <iostream>
#include <fstream>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

unsigned char key[] = "YELLOW SUBMARINE";
unsigned char nonce[8] = {0};

int main() {
  char input[1024];
  unsigned char plaintext[1024];
  unsigned char ciphertext[1024];
  int plaintext_len, ciphertext_len;

  init_openssl();

  cout << "Input pls" << endl;
  cin.getline(input, 10240);
  ciphertext_len = b64ToBytes(ciphertext, input);

  plaintext_len = decryptCtr(ciphertext, ciphertext_len, key, nonce, plaintext);

  plaintext[plaintext_len] = '\0';
  cout << plaintext << endl;

  close_openssl();
}
