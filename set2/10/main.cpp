#include <iostream>
#include <fstream>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

int main() {
  char *input = new char[102400];
  unsigned char *inputBytes = new unsigned char[102400];

  unsigned char *key = (unsigned char *)"YELLOW SUBMARINE";
  unsigned char iv[16] = {0};

  unsigned char *decryptedtext = new unsigned char[102400];
  int inputBytes_len, decryptedtext_len = 0;

  ifstream in_file("10.txt");
  while (!in_file.eof())
    in_file.read(input, 102400);

  inputBytes_len = b64ToBytes(inputBytes, input);

  int blockSize = 16;
  int noBlocks = inputBytes_len/blockSize;
  unsigned char **blocks = new unsigned char*[noBlocks];
  for (int i = 0; i < noBlocks; i++) {
    blocks[i] = new unsigned char[blockSize];
  }
  breakIntoBlocks(blocks, inputBytes, inputBytes_len, noBlocks, blockSize);
  
  init_openssl();

  unsigned char *workingBlock = new unsigned char[blockSize];
  unsigned char *decrypted_start = decryptedtext;
  /* Decrypt the ciphertext */
  for (int i = 0; i < noBlocks; i++) {
    decryptedtext_len += decryptEcb(blocks[i], blockSize, key, workingBlock, true);
    if (i > 0) {
      memcpy(iv, blocks[i-1], blockSize);
    }
    doXor(decryptedtext, workingBlock, iv, blockSize);
    decryptedtext += blockSize;
  }

  /* Remove Padding */
  decryptedtext = decrypted_start;
  int padding = decryptedtext[decryptedtext_len-1];
  for (int i = decryptedtext_len-1; i >= decryptedtext_len-padding; i--)
    decryptedtext[i] = '\0';
  decryptedtext_len -= padding;

  /* Show the decrypted text */
  cout << decryptedtext << endl;

  close_openssl();

  delete [] input;
  delete [] inputBytes;
  delete [] decryptedtext;
  for (int i = 0; i < noBlocks; i++)
    delete [] blocks[i];
  delete [] blocks;
}
