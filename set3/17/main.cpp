#include <iostream>
#include <fstream>
#include <cstdlib>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

unsigned char key[16];
unsigned char iv[16];

bool padding_oracle(unsigned char *ciphertext, int ciphertext_len) {
  unsigned char *plaintext = new unsigned char[10240];
  int plaintext_len;

  plaintext_len = decryptCbc(ciphertext, ciphertext_len, key, iv, plaintext);

  delete [] plaintext;
  return (plaintext_len > 0);
}

int main() {
  char* input = new char[10240];
  unsigned char *plaintext = new unsigned char[10240];
  unsigned char *ciphertext = new unsigned char[10240];
  char *revealed_plaintext = new char[10240];
  int plaintext_len, ciphertext_len;
  int blockSize = 16;

  arc4random_buf(key, 16);
  
  arc4random_buf(iv, 16);

  init_openssl();

  ifstream in_file("17.txt");
  int line = arc4random_uniform(10)+1;
  for (int i = 0; i < line; i++)
    in_file.getline(input, 10240);
  plaintext_len = b64ToBytes(plaintext, input);

  ciphertext_len = encryptCbc(plaintext, plaintext_len, key, iv, ciphertext);

  int noBlocks = ciphertext_len/blockSize;
  unsigned char intermediateBlock[blockSize];
  unsigned char attackingBlock[blockSize*2];
  // Begin the attack, starting from the last block
  for (int block = noBlocks-1; block >= 0; block--) {
    // The attacking block is two blocks long.
    // It contains the ciphertext we're attacking in the second block
    // And our crafted block in the first
    for (int i = 0; i < blockSize; i++)
      attackingBlock[blockSize+i] = ciphertext[block*blockSize+i];
    // This loop attacks byte by byte, starting at the end of the block
    for (int padding = 1; padding <= blockSize; padding++) {
      // Fill in the relevant portion of our attacking block
      for (int j = blockSize-1; j > blockSize-padding; j--) {
	attackingBlock[j] = (intermediateBlock[j] ^ padding);
      }
      // Now try every byte
      for (unsigned char c = 0; c <= 255; c++) {
	attackingBlock[blockSize-padding] = c;
	if (padding_oracle(attackingBlock, blockSize*2)) {
	  // Found something! Fill in our intermediate block
	  intermediateBlock[blockSize-padding] = (c ^ padding);
	  break;
	}
      }
    }
    // Fill in plaintext
    for (int i = 0; i < blockSize; i++) {
      if (block > 0)
	revealed_plaintext[block*blockSize+i] = (char)(ciphertext[block*blockSize+i-blockSize] ^ intermediateBlock[i]);
      else {
	// We need to use the IV to discover the first block
	revealed_plaintext[block*blockSize+i] = (char)(iv[i] ^ intermediateBlock[i]);
      }
    }
  }

  int padding = revealed_plaintext[ciphertext_len-1];
  if (padding <= blockSize)
    revealed_plaintext[ciphertext_len-padding] = '\0';
  else
    revealed_plaintext[ciphertext_len] = '\0';
  cout << revealed_plaintext << endl;

  close_openssl();

  delete [] input;
  delete [] plaintext;
  delete [] ciphertext;
  delete [] revealed_plaintext;
}
