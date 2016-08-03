#include <iostream>
#include <fstream>
#include <cstdlib>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"
#include "sha1.h"

using namespace std;

int main() {
  unsigned char mac[SHA1_HASH_LEN];
  char macHex[SHA1_HASH_LEN*2+1];
  const char *key = "YELLOW SUBMARINE";
  const char *message = "Hello World!";

  if (!generate_secret_prefix_mac((unsigned char *)key, strlen(key), message, mac)) {
    cout << "Error generating MAC" << endl;
  }

  bytesToHex(macHex, mac, SHA1_HASH_LEN);
  if (!authenticate_secret_prefix_mac((unsigned char *)key, strlen(key), message, mac)) {
    cout << "MAC could not be verified" << endl << macHex << endl;
  } else {
    cout << "MAC verified" << endl << macHex << endl;
  }

  // Mess with the mac
  mac[10] = 0x41;
  bytesToHex(macHex, mac, SHA1_HASH_LEN);
  if (!authenticate_secret_prefix_mac((unsigned char *)key, strlen(key), message, mac)) {
    cout << "MAC could not be verified" << endl << macHex << endl;
  } else {
    cout << "MAC verified" << endl << macHex << endl;
  }

  return 0;
}
