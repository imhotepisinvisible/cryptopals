#include <iostream>
#include <fstream>

#include "conversions.h"
#include "utils.h"

using namespace std;

int main() {
  char *input = new char[10240];
  unsigned char *inputBytes = new unsigned char[10240];

  ifstream in_file("8.txt");
  while (!in_file.eof()) {
    in_file.getline(input, 10240);

    int length = hexToBytes(inputBytes, input);
    int blockSize = 16;
    int noBlocks = length/blockSize;
    unsigned char **blocks = new unsigned char*[noBlocks];
    for (int i = 0; i < noBlocks; i++) {
      blocks[i] = new unsigned char[blockSize];
    }
    breakIntoBlocks(blocks, inputBytes, length, noBlocks, blockSize);

    bool found = false;
    unsigned char foundBytes[blockSize];
    for (int i = 0; i < noBlocks; i++) {
      for (int j = i+1; j < noBlocks; j++) {
	for (int k = 0; k < blockSize; k++) {
	  if (blocks[i][k] != blocks[j][k])
	    break;
	  if (k == blockSize-1) {
	    found = true;
	    memcpy(foundBytes, blocks[i], blockSize);
	  }
	}
      }
    }

    if (found) {
      char foundStr[blockSize*2+1];
      bytesToHex(foundStr, foundBytes, blockSize);
      cout << "Found something?? input: " << input << endl
	   << "Repeated string: " << foundStr << endl;
    }

    for (int i = 0; i < noBlocks; i++)
      delete [] blocks[i];
    delete [] blocks;
  }

  delete [] input;
  delete [] inputBytes;
}
