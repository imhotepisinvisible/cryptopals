#include <iostream>

using namespace std;

int main() {
  char input[32];
  int blockSize = 16;
  
  /* Remove Padding */
  int padding = block[blockSize-1];
  if (padding <= 0 || padding > blockSize)
    return -1;
  for (int i = blockSize-1; i >= blockSize-padding; i--) {
    if (block[i] != padding)
      return -1;
    block[i] = '\0';
  }
  blockSize -= padding;

  return blockSize;
}
