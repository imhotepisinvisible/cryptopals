#include <iostream>

#include "conversions.h"

using namespace std;

int main() {
  char input[256];
  unsigned char inputBytes[1024];
  char output[256];

  cout << "Input pls" << endl;
  cin >> input;

  int length = hexToBytes(inputBytes, input);

  bytesToB64(output, inputBytes, length);

  cout << output << endl;
}
