#include <iostream>

#include "conversions.h"
#include "utils.h"

using namespace std;

int main() {
  char input1[256];
  char input2[256];
  unsigned char input1Bytes[1024];
  unsigned char input2Bytes[1024];
  unsigned char outputBytes[1024];
  char output[256];

  cout << "Input 1 pls" << endl;
  cin >> input1;
  cout << "Input 2 pls" << endl;
  cin >> input2;

  if (strlen(input1) != strlen(input2)) {
    cout << "Error, strings must be same length" << endl;
    return -1;
  }

  int length = hexToBytes(input1Bytes, input1);
  hexToBytes(input2Bytes, input2);

  doXor(outputBytes, input1Bytes, input2Bytes, length);

  bytesToHex(output, outputBytes, length);

  cout << output << endl;
}
