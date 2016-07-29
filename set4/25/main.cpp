#include <iostream>
#include <fstream>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

unsigned char key[16];
unsigned char nonce[8];

int edit(unsigned char *ciphertext, unsigned char *key, const int offset, const char *newtext) {
  // Generate keystream of required length
  int plaintext_len = strlen(newtext);
  int blockSize = 16;
  int required_blocks = plaintext_len/blockSize + (plaintext_len%blockSize ? 1 : 0);
  unsigned char *keystream = new unsigned char[blockSize*required_blocks];
  unsigned char keystream_block[blockSize];
  // Load in nonce
  memcpy(keystream_block, nonce, blockSize/2);
  int keystream_offset = offset/blockSize;
  for (uint64_t i = keystream_offset; i < required_blocks; i++) {
    *(uint64_t *)(keystream_block+(blockSize/2)) = i;
    encryptEcb(keystream_block, blockSize, key, keystream+i*blockSize, true);
  }

  // Encrypt plaintext
  unsigned char new_ciphertext[plaintext_len];
  int block_offset = offset%blockSize;
  doXor(new_ciphertext, keystream+block_offset, (unsigned char*)newtext, plaintext_len);

  // Splice in
  memcpy(ciphertext+offset, new_ciphertext, plaintext_len);

  delete [] keystream;
  
  return 0;
}

int main() {
  char* input = new char[10240];
  unsigned char *plaintext = new unsigned char[10240];
  unsigned char *ciphertext = new unsigned char[10240];
  unsigned char *known_plaintext = new unsigned char[10240];
  unsigned char *known_ciphertext = new unsigned char[10240];
  int plaintext_len, ciphertext_len;

  arc4random_buf(key, 16);
  
  arc4random_buf(nonce, 8);

  init_openssl();

  ifstream in_file("25-decrypted.txt");
  while (!in_file.eof())
    in_file.read(input, 102400);
  plaintext_len = strlen(input);b64ToBytes(plaintext, input);

  ciphertext_len = encryptCtr((unsigned char*)input, plaintext_len, key, nonce, ciphertext);

  memcpy(known_ciphertext, ciphertext, ciphertext_len);
  memset(known_plaintext, 'A', ciphertext_len);
  edit(ciphertext, key, 0, (char *)known_plaintext);

  doXor(plaintext, known_plaintext, ciphertext, ciphertext_len);
  doXor(plaintext, plaintext, known_ciphertext, ciphertext_len);
  plaintext[ciphertext_len] = '\0';

  cout << plaintext << endl;

  close_openssl();

  delete [] input;
  delete [] plaintext;
  delete [] ciphertext;
  delete [] known_plaintext;
  delete [] known_ciphertext;
}
