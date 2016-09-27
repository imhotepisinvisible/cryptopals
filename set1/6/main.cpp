#include <iostream>
#include <fstream>

#include "conversions.h"
#include "utils.h"

using namespace std;

int main() {
  char *input = new char[102400];
  unsigned char *inputBytes = new unsigned char[102400];

  ifstream in_file("6.txt");
  while (!in_file.eof())
    in_file.read(input, 102400);

  int length = b64ToBytes(inputBytes, input);

  float keysizeHammings[41] = {0};
  unsigned char testBlock1[1024];
  unsigned char testBlock2[1024];
  int avg;
  float hammings;
  float hamming;
  float norm;

  for (int i = 2; i < 41; i++) {
    avg = 0;
    hammings = 0;
    for (int j = 0; j < length-i; j+=i*2) {
      memcpy(testBlock1, inputBytes+j, i);
      memcpy(testBlock2, inputBytes+j+i, i);
    
      hamming = calcHammingDistance(testBlock1, testBlock2, i);
      norm = hamming/(float)i;
      hammings += norm;
      avg++;    
    }
    hamming = hammings/avg;

    keysizeHammings[i] = hamming;
    //cout << i << ": " << keysizeHammings[i] << endl;
  }

  int chosenKeysize = 0;
  float result = 0;
  float lowestHamming = 100;
  for (int i = 2; i < 41; i++) {
    result = keysizeHammings[i];
    if (result < lowestHamming) {
      lowestHamming = result;
      chosenKeysize = i;
    }
  }
  cout << "Chosen keysize: " << chosenKeysize << endl;
  
  int noBlocks = length/chosenKeysize;
  unsigned char **blocks = new unsigned char*[noBlocks];
  for (int i = 0; i < noBlocks; i++) {
    blocks[i] = new unsigned char[chosenKeysize];
  }
  breakIntoBlocks(blocks, inputBytes, length, noBlocks, chosenKeysize);

  unsigned char **transposedBlocks = new unsigned char*[chosenKeysize];
  unsigned char **transposedBlocksStart = transposedBlocks;
  for (int i = 0; i < chosenKeysize; i++) {
    transposedBlocks[i] = new unsigned char[noBlocks];
  }
  transposeBlocks(transposedBlocks, blocks, noBlocks, chosenKeysize);

  char c;
  unsigned char winner[noBlocks];
  while (*transposedBlocks) {
    c = singleCharXor(winner, *transposedBlocks++, noBlocks);
    cout << c;
  }
  cout << endl;

  delete [] input;
  delete [] inputBytes;
  for (int i = 0; i < noBlocks; i++)
    delete [] blocks[i];
  delete [] blocks;
  for (int i = 0; i < chosenKeysize; i++)
    delete [] transposedBlocksStart[i];
  delete [] transposedBlocksStart;
}
