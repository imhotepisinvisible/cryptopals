#include <iostream>

#include "conversions.h"
#include "utils.h"

using namespace std;

int main() {
  char input[256];
  unsigned char inputBytes[1024];
  unsigned char winner[256];

  cout << "Input pls" << endl;
  cin >> input;

  int length = hexToBytes(inputBytes, input);

  singleCharXor(winner, inputBytes, length);

  cout << (char*)winner << endl;
}
