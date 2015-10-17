#include <iostream>

#include "utils.h"

using namespace std;

int main() {
  char input[256];
  int blockSize;

  cout << "input pls" << endl;
  cin.getline(input, 256);

  cout << "blocksize pls" << endl;
  cin >> blockSize;

  if (strlen(input) > blockSize) {
    cout << "Error! String longer than block size!" << endl;
    return -1;
  }
  
  char *output = new char[blockSize];
  strcpy(output, input);

  pkcs7padding((unsigned char*)output, blockSize);

  cout << output << endl;
  
}
