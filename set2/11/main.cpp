#include <iostream>
#include <fstream>
#include <cstdlib>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

int encryption_oracle(unsigned char *ciphertext, const char *plaintext) {
  int blockSize = 16;
  unsigned char key[blockSize];
  unsigned char iv[blockSize];
  arc4random_buf(key, blockSize);
  arc4random_buf(iv, blockSize);
  unsigned char *newplaintext = new unsigned char[102420];
  int plaintext_len = strlen(plaintext);
  int append = arc4random_uniform(5)+5;
  int prepend = arc4random_uniform(5)+5;
  arc4random_buf(newplaintext, append);
  strcpy((char *) newplaintext+append, plaintext);
  arc4random_buf(newplaintext+append+plaintext_len, prepend);
  int ciphertext_len;
  
  if (arc4random_uniform(2) == 1) {
     ciphertext_len = encryptCbc(newplaintext, append+plaintext_len+prepend, key, iv, ciphertext);
  }
  else {
    ciphertext_len = encryptEcb(newplaintext, append+plaintext_len+prepend, key, ciphertext, false);
  }

  delete [] newplaintext;
  return ciphertext_len;
}

int main() {
  char input[1024];
  unsigned char output[1024];
  int output_len;
  //char outputHex[2048];

  init_openssl();

  cout << "input pls" << endl;
  cin.getline(input, 1024);

  output_len = encryption_oracle(output, input);

  //bytesToHex(outputHex, output, output_len);
  //cout << outputHex << endl;
  
  int blockSize = 16;
  int foundBlock = detect_cipher(output, output_len);

  if (foundBlock >= 0) {
    char foundStrHex[blockSize*2+1];
    bytesToHex(foundStrHex, output+(foundBlock*blockSize), blockSize);
    cout << "Probably ECB mode. Repeated string: " << foundStrHex << endl;
  }

  close_openssl();
}
