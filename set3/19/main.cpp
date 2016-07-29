#include <iostream>
#include <fstream>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

unsigned char *key;
unsigned char *nonce;

int main() {
  char* input = new char[10240];
  unsigned char *plaintext = new unsigned char[10240];
  unsigned char *ciphertext = new unsigned char[10240];
  char *cipherHex = new char[10240];
  int plaintext_len, ciphertext_len;
  int blockSize = 16;

  key = new unsigned char[16];
  strcpy((char *)key, "YELLOW SUBMARINE");
  
  nonce = new unsigned char[8];
  memset(nonce, 0, 8);

  init_openssl();

  // Encrypt plaintext
  ifstream in_file3("19.txt");
  while(in_file3.getline(input, 10240)) {

    plaintext_len = b64ToBytes(plaintext, input);
    ciphertext_len = encryptCtr(plaintext, plaintext_len, key, nonce, ciphertext);
    bytesToHex(cipherHex, ciphertext, ciphertext_len);
    cout << cipherHex << endl;
      
  }

  // Generate attempted keystring
  ifstream in_file("19ciphers.txt");
  unsigned char **keystream = new unsigned char*[40];
  for (int i = 0; i < 40; i++)
    keystream[i] = new unsigned char[10240];
  unsigned char *spaces = new unsigned char[ciphertext_len];
  for (int i = 0; i < ciphertext_len; i++)
    spaces[i] = ' ';
  int count = 0;
  while(in_file.getline(input, 10240)) {

    ciphertext_len = hexToBytes(ciphertext, input);
    doXor(keystream[count], ciphertext, spaces, ciphertext_len);
    count++;
  }
  in_file.close();

  // Now try decrypting with our forged keystring
  ifstream in_file2("19ciphers.txt");
  while (in_file2.getline(input, 10240)) {
    ciphertext_len = hexToBytes(ciphertext, input);
    for (int i = 0; i < 40; i++) {
      cout << i << ": ";
      doXor(plaintext, ciphertext, keystream[i], ciphertext_len);
      //plaintext[ciphertext_len] = '\0';
      //cout << plaintext << endl;
      for (int j = 0; j < ciphertext_len; j++)
	if (isalnum(plaintext[j]) || ispunct(plaintext[j]))
	  cout << j << " ";
      cout << endl;
    }
    cout << endl;
  }

    /*plaintext_len = decryptCtr(ciphertext, ciphertext_len, key, nonce, plaintext);

  plaintext[plaintext_len] = '\0';
  cout << plaintext << endl;*/

  close_openssl();
}
