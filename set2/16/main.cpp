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

string sanitize_input(string input) {
  size_t found = input.find('=');
  while (found!=std::string::npos) {
    input.insert(found, "\'");
    found += 2;
    input.insert(found, "\'");
    found = input.find('=', found);
  }
  found = input.find(';');
  while (found!=std::string::npos) {
    input.insert(found, "\'");
    found += 2;
    input.insert(found, "\'");
    found = input.find(';', found);
  }
  return input;
}

int main() {
  string input;
  char plaintext[1024];
  unsigned char ciphertext[1024];
  //char * cipherHex = new char[2048];
  int plaintext_len, ciphertext_len;

  arc4random_buf(key, 16);

  arc4random_buf(iv, 16);

  init_openssl();

  cout << "Input pls" << endl;
  getline(cin, input);

  string sane_input = sanitize_input(input);
  strcpy(plaintext, sane_input.c_str());

  // Craft input: aaaaaaaaaaaaaaaaaaaaa:admin<true
  ciphertext_len = encryption_oracle(ciphertext, plaintext);
  //bytesToHex(ciphertext, ciphertext_len, cipherHex);
  //cout << cipherHex << endl;

  // Flip bits 48 and 96 in block 3 (out of 16*8 total)
  ciphertext[37] ^= 1;
  ciphertext[43] ^= 1;
  
  plaintext_len = decryptCbc(ciphertext, ciphertext_len, key, iv, (unsigned char *)plaintext);
  plaintext[plaintext_len] = '\0';

  //cout << plaintext << endl;
  cout << "Admin: " << (strstr(plaintext, ";admin=true;") ? "true" : "false") << endl;

  close_openssl();
}
