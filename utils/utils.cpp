#include <iostream>

#include "utils.h"
#include "conversions.h"

using namespace std;

void doXor(unsigned char *dest, const unsigned char *source1, const unsigned char *source2, int length) {
  for (int i = 0; i < length; i++) {
    *(dest++) = *(source1++) ^ *(source2++);
  }
}

int countSpaces(const unsigned char *source) {
  int result = 0;
  while (*source) {
    if (*source == ' ')
      result++;
    source++;
  }
  return result;
}

// Uses Wegner's algorithm
int calcHammingDistance(const unsigned char *source1, const unsigned char *source2, int length) {
  int result = 0;

  for (int i = 0; i < length; i++) {
    unsigned char val = *source1 ^ *source2;

    // Count the number of bits set
    while (val != 0) {
        // A bit is set, so increment the count and clear the bit
        result++;
        val &= val - 1;
    }

    source1++;
    source2++;
  }

  return result;
}

char singleCharXor(unsigned char *dest, unsigned char *source, int source_len) {
  unsigned char *charBytes = new unsigned char[10240];
  unsigned char *candidateBytes = new unsigned char[10240];
  char winningChar;

  int result;
  int topScore = 0;
  for (int c = 0; c <= 255; c++) {
    memset(charBytes, (char)c, source_len);
    doXor(candidateBytes, source, charBytes, source_len);
    result = countSpaces(candidateBytes);
    if (result > topScore) {
      topScore = result;
      memcpy(dest, candidateBytes, source_len);
      winningChar = (char)c;
    }
  }

  delete [] charBytes;
  delete [] candidateBytes;
  return winningChar;
}

void breakIntoBlocks(unsigned char **dest, const unsigned char *source, int no_blocks, int block_len) {
  for (int i = 0; i < no_blocks; i++) {
    for (int j = 0; j < block_len; j++)
      dest[i][j] = *(source++);
  }
}

void transposeBlocks(unsigned char **dest, unsigned char **source, int no_blocks, int keysize) {
  for (int i = 0; i < keysize; i++) {
    for (int j = 0; j < no_blocks; j++) {
      dest[i][j] = source[j][i];
    }
  }
}

int pkcs7padding(unsigned char *block, int blockSize) {
  char pad = blockSize - strlen((char *)block);
  for(int i = strlen((char *)block); i < blockSize; i++) {
    block[i] = pad;
  }
  return pad;
}

int detect_cipher(unsigned char *input, int input_len) {
  int blockSize = 16;
  int noBlocks = input_len/blockSize;
  unsigned char **blocks = new unsigned char*[noBlocks];
  for (int i = 0; i < noBlocks; i++) {
    blocks[i] = new unsigned char[blockSize];
  }
  breakIntoBlocks(blocks, input, noBlocks, blockSize);

  bool found = false;
  int firstBlock = -1;
  for (int i = 0; i < noBlocks; i++) {
    for (int j = i+1; j < noBlocks; j++) {
      for (int k = 0; k < blockSize; k++) {
	if (blocks[i][k] != blocks[j][k])
	  break;
	if (k == blockSize-1) {
	  if (!found)
	    firstBlock = i;
	  found = true;
	}
      }
    }
  }

  for (int i = 0; i < noBlocks; i++)
    delete [] blocks[i];
  delete [] blocks;
  return firstBlock;
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
