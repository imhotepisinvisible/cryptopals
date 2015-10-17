#include <iostream>
#include <fstream>
#include <cstdlib>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

unsigned char key[16];
unsigned char *randomprefix;
int prefix_len;

int encryption_oracle(unsigned char * ciphertext, const char *plaintext) {
  //const char *key = "YELLOW SUBMARINE";
  unsigned char *newplaintext = new unsigned char[102420];
  memcpy(newplaintext, randomprefix, prefix_len);
  int plaintext_len = strlen(plaintext);
  strcpy ((char *)newplaintext+prefix_len,  plaintext);
  char append[1024];
  strcpy(append, "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
  unsigned char appendBytes[1024];
  int append_len = b64ToBytes(appendBytes, append);
  memcpy(newplaintext+prefix_len+plaintext_len, appendBytes, append_len);
  int ciphertext_len;
  
  ciphertext_len = encryptEcb(newplaintext, prefix_len+plaintext_len+append_len, (unsigned char *)key, ciphertext, false);

  delete [] newplaintext;
  return ciphertext_len;
}

int main() {
  char *input = new char[102400];
  unsigned char *output = new unsigned char[102400];
  int output_len;

  char answer[512];

  arc4random_buf(key, 16);

  prefix_len = arc4random_uniform(500)+1;
  randomprefix = new unsigned char[prefix_len];
  arc4random_buf(randomprefix, prefix_len);

  unsigned char attackBlock[16];

  init_openssl();

  /* Detect block size and encryption method */
  /*for (int i = 1; i < 33; i++) {
    for (int j = 0; j < i; j++)
      input[j] = 'A';
    output_len = encryption_oracle(input, output);
    cout << i << ": " << output_len << endl;
    detect_cipher(output, output_len);
  }*/
  int blockSize = 16;

  int prefixPad, prefixBlocks;
  bool found = false;
  /* Figure out prefix length */
  for (int i = 0; i < blockSize*3; i++) {
    for (int j = 0; j < i; j++)
      input[j] = 'A';
    output_len = encryption_oracle(output, input);
    //cout << i << ": " << output_len << endl;
    if ((prefixBlocks = detect_cipher(output, output_len)) > 0) {
      //prefixBlocks = detect_cipher(output, output_len);
      prefixPad = i-blockSize*2;
      found = true;
      break;
    }
    if (found)
      break;
  }
  if (!found)
    return -1;
  //cout << prefixPad << "::" << prefixBlocks << endl;
  
  for (int iteration = 0; iteration < 138; iteration++) {
    int blockNo = iteration/blockSize;

    // Zero input
    memset(input, 0, prefixPad+blockSize);
    // Pad input the right amount
    for (int i = 0; i < prefixPad+15-(iteration%blockSize); i++)
      input[i] = 'A';
    // Encrypt
    output_len = encryption_oracle(output, input);
    // Now craft our attack input
    if (blockNo == 0) {
      for (int i = prefixPad+(blockSize-1)-(iteration%blockSize), j=iteration-(iteration%blockSize); i < prefixPad+(blockSize-1); i++, j++)
	input[i] = answer[j];
    }
    else {
      for (int i=prefixPad, j=(iteration-blockSize)+1; i < prefixPad+(blockSize-1); i++, j++)
	input[i] = answer[j];
    }

    // Grab the block we're going to compare with
    // Add prefix blocks to avoid the prefix
    for (int i = (prefixBlocks+blockNo)*blockSize; i < ((prefixBlocks+blockNo)*blockSize)+blockSize; i++)
      attackBlock[i%blockSize] = output[i];

    // Now attack...
    for (unsigned char c = 1; c < 255; c++) {
      input[prefixPad+(blockSize-1)] = (char) c;

      output_len = encryption_oracle(output, input);

      // Compare
      bool match = false;
      for (int i = 0; i < blockSize; i++) {
	if (output[i+blockSize*prefixBlocks] != attackBlock[i])
	  break;
	if (i == blockSize-1)
	  match = true;
      }
      if (match) {
	answer[iteration] = c;
	cout << c << flush;
	break;
      }
    }
  }
  cout << endl;
  //cout << answer << endl;

  close_openssl();

  delete [] input;
  delete [] output;
  delete [] randomprefix;
}
