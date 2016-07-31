#include <iostream>
#include <fstream>
#include <cstdlib>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

unsigned char key[16];
unsigned char iv[16];

int encryption_oracle(unsigned char *ciphertext, const char *plaintext) {
  unsigned char prefix[1024];
  strcpy((char *)prefix, "comment1=cooking%20MCs;userdata=");
  int prefix_len = strlen((char *)prefix);
  unsigned char *newplaintext = new unsigned char[102420];
  memcpy(newplaintext, prefix, prefix_len);
  int plaintext_len = strlen(plaintext);
  strcpy ((char *)newplaintext+prefix_len, plaintext);
  unsigned char append[1024];
  strcpy((char *)append, ";comment2=%20like%20a%20pound%20of%20bacon");
  int append_len = strlen((char *)append);
  memcpy(newplaintext+prefix_len+plaintext_len, append, append_len);
  int ciphertext_len;
  
  ciphertext_len = encryptCbc(newplaintext, prefix_len+plaintext_len+append_len, key, iv, ciphertext);

  delete [] newplaintext;
  return ciphertext_len;
}

bool ascii_compliant(const char *plaintext) {
  bool ret = true;

  while (*plaintext) {
    if ((unsigned char)*plaintext > 127) {
      ret = false;
      break;
    }
    plaintext++;
  }
  
  return ret;
}

int main() {
  string input;
  char plaintext[1024];
  unsigned char ciphertext[1024];
  unsigned char modified_ciphertext[1024];
  //char *cipherHex = new char[2048];
  int plaintext_len, ciphertext_len;
  int blockSize = 16;

  arc4random_buf(key, 16);

  memcpy(iv, key, 16);

  init_openssl();

  cout << "Input pls" << endl;
  getline(cin, input);

  string sane_input = sanitize_input(input);
  strcpy(plaintext, sane_input.c_str());

  // Craft input: aaaaaaaaaaaaaaaa
  ciphertext_len = encryption_oracle(ciphertext, plaintext);
  //bytesToHex(cipherHex, ciphertext, ciphertext_len);
  //cout << cipherHex << endl;

  // Attacker: Modify ciphertext
  memcpy(modified_ciphertext, ciphertext, ciphertext_len);
  memset(modified_ciphertext+blockSize, 0, blockSize);
  memcpy(modified_ciphertext+blockSize*2, modified_ciphertext, blockSize);

  // Receiver: decrypt ciphertext
  plaintext_len = decryptCbc(modified_ciphertext, ciphertext_len, key, iv, (unsigned char *)plaintext);
  plaintext[plaintext_len] = '\0';

  unsigned char recovered_key[16];
  if (!ascii_compliant(plaintext)) {
    cout << "Error, plaintext is not ascii compliant!!" << endl << "<plaintext output>" << endl;
    // Attacker:
    doXor(recovered_key, (unsigned char *)plaintext, (unsigned char *)plaintext+blockSize*2, blockSize);
    cout << "Key recovered! Decrypted plaintext:" << endl;
    plaintext_len = decryptCbc(ciphertext, ciphertext_len, recovered_key, recovered_key, (unsigned char *)plaintext);
    plaintext[plaintext_len] = '\0';
    cout << plaintext << endl;
  } else {
    cout << plaintext << endl;
  }

  close_openssl();
}
