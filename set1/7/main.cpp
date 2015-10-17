#include <iostream>
#include <fstream>

#include "conversions.h"
#include "crypto.h"

using namespace std;

int main() {
  char *input = new char[10240];
  unsigned char *inputBytes = new unsigned char[10240];

  unsigned char *key = (unsigned char *)"YELLOW SUBMARINE";

  unsigned char *decryptedtext = new unsigned char[10240];
  int inputBytes_len, decryptedtext_len;

  ifstream in_file("7.txt");
  while (!in_file.eof())
    in_file.read(input, 10240);

  inputBytes_len = b64ToBytes(inputBytes, input);
  
  init_openssl();

  /* Decrypt the ciphertext */
  decryptedtext_len = decryptEcb(inputBytes, inputBytes_len, key, decryptedtext, false);

  /* Add a NULL terminator. We are expecting printable text */
  decryptedtext[decryptedtext_len] = '\0';

  /* Show the decrypted text */
  cout << decryptedtext << endl;

  close_openssl();

  delete [] input;
  delete [] inputBytes;
  delete [] decryptedtext;
}
