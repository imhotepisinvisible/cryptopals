#include <iostream>
#include <fstream>

#include "conversions.h"
#include "utils.h"

using namespace std;

int main() {
  char input[256];
  char key[256];
  unsigned char keyBytes[1024];
  unsigned char outputBytes[1024];
  char output[256];

  cout << "Input pls" << endl;
  cin.getline(input,256);
  cout << "Key pls" << endl;
  cin >> key;

  // Stretch key to the length of the input
  for (int i = 0; i < strlen(input); i++)
    keyBytes[i] = (unsigned char)key[i%strlen(key)];

  doXor(outputBytes, (unsigned char*)input, keyBytes, strlen(input));
  bytesToHex(output, outputBytes, strlen(input));
  
  cout << output << endl;
}
