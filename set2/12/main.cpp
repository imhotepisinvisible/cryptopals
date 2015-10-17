#include <iostream>
#include <fstream>
#include <cstdlib>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

unsigned char key[16];

int encryption_oracle(char *plaintext, unsigned char *ciphertext) {
  //const char *key = "YELLOW SUBMARINE";
  unsigned char *newplaintext = new unsigned char[102420];
  int plaintext_len = strlen(plaintext);
  strcpy ((char *)newplaintext,  plaintext);
  char append[1024];
  strcpy(append, "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
  unsigned char appendBytes[1024];
  int append_len = b64ToBytes(appendBytes, append);
  memcpy(newplaintext+plaintext_len, appendBytes, append_len);
  int ciphertext_len;
  
  ciphertext_len = encryptEcb(newplaintext, plaintext_len+append_len, (unsigned char *)key, ciphertext, false);

  delete [] newplaintext;
  return ciphertext_len;
}

int main() {
  char input[1024];
  unsigned char output[1024];
  int output_len;

  char answer[512];

  arc4random_buf(key, 16);

  unsigned char attackBlock[16];

  init_openssl();

  /* Detect block size and encryption method */
  /*for (int i = 1; i < 33; i++) {
    for (int j = 0; j < i; j++)
      input[j] = 'A';
    output_len = encryption_oracle(input, output);
    cout << i << ": " << output_len << endl;
    int result = detect_cipher(output, output_len);
  }*/
  int blockSize = 16;

  for (int iteration = 0; iteration < 138; iteration++) {
    int blockNo = iteration/blockSize;

    // Zero input
    memset(input, 0, blockSize);
    // Pad input the right amount
    for (int i = 0; i < 15-(iteration%blockSize); i++)
      input[i] = 'A';
    // Encrypt
    output_len = encryption_oracle(input, output);
    // Now craft our attack input
    if (blockNo == 0) {
      for (int i = (blockSize-1)-(iteration%blockSize), j=iteration-(iteration%blockSize); i < (blockSize-1); i++, j++)
	input[i] = answer[j];
    }
    else {
      for (int i=0, j=(iteration-blockSize)+1; i < (blockSize-1); i++, j++)
	input[i] = answer[j];
    }

    // Grab the block we're going to compare with
    for (int i = blockNo*blockSize; i < (blockNo*blockSize)+blockSize; i++)
      attackBlock[i%blockSize] = output[i];

    // Now attack...
    for (unsigned char c = 1; c < 255; c++) {
      input[15] = (char) c;

      output_len = encryption_oracle(input, output);

      // Compare
      bool match = false;
      for (int i = 0; i < blockSize; i++) {
	if (output[i] != attackBlock[i])
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
}
