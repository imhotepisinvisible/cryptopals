#include <iostream>
#include <fstream>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

unsigned char *key;
unsigned char *nonce;

int main() {
  char* input = new char[10240];
  unsigned char *plaintext = new unsigned char[10240];
  unsigned char *ciphertext = new unsigned char[10240];
  unsigned char *ciphertext_stream = new unsigned char[1024000];
  char *cipherHex = new char[10240];
  int plaintext_len, ciphertext_len;
  int blockSize = 16;

  unsigned char *possibleKey = new unsigned char[64];

  key = new unsigned char[16];
  strcpy((char *)key, "YELLOW SUBMARINE");
  
  nonce = new unsigned char[8];
  memset(nonce, 0, 8);

  init_openssl();

  // Encrypt plaintext
  /*ifstream in_file3("20.txt");
  while(in_file3.getline(input, 10240)) {

    plaintext_len = b64ToBytes(plaintext, input);
    ciphertext_len = encryptCtr(plaintext, plaintext_len, key, nonce, ciphertext);
    bytesToHex(cipherHex, ciphertext, ciphertext_len);
    cout << cipherHex << endl;
      
    }*/

  // Trim and load ciphertext
  ifstream in_file("20ciphers-trimmed.txt");
  int total_len = 0;
  while(in_file.getline(input, 10240)) {
    ciphertext_len = hexToBytes(ciphertext, input);
    memcpy(ciphertext_stream+total_len, ciphertext, ciphertext_len);
    total_len += ciphertext_len;
  }
  in_file.close();

  int keysize = 53;

  int noBlocks = total_len/keysize;
  unsigned char **blocks = new unsigned char*[noBlocks];
  for (int i = 0; i < noBlocks; i++) {
    blocks[i] = new unsigned char[keysize];
  }
  breakIntoBlocks(blocks, ciphertext_stream, noBlocks, keysize);

  unsigned char **transposedBlocks = new unsigned char*[keysize];
  unsigned char **transposedBlocksStart = transposedBlocks;
  for (int i = 0; i < keysize; i++) {
    transposedBlocks[i] = new unsigned char[noBlocks];
  }
  transposeBlocks(transposedBlocks, blocks, noBlocks, keysize);

  char c;
  unsigned char winner[noBlocks];
  //while (*transposedBlocks) {
  for (int i = 0; i < keysize; i++) {
    c = singleCharXor(winner, *transposedBlocks++, noBlocks);
    possibleKey[i] = c;
  }

  char *possible_plaintext = new char[1024];
  for (int i = 0; i < noBlocks; i++) {
    memset(possible_plaintext, 0, 1024);
    doXor((unsigned char *)possible_plaintext, ciphertext_stream+(i*keysize), possibleKey, keysize);
    cout << possible_plaintext << endl;
  }

  close_openssl();
}
