#include <iostream>
#include <sstream>
#include <cstdlib>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

void generate_cbc_mac(const char *msg, const int msg_len, const unsigned char *key, const unsigned char *iv, unsigned char *mac) {
  unsigned char ciphertext[512];

  int ciphertext_len = encryptCbc((unsigned char *)msg, msg_len, key, iv, ciphertext);

  memcpy(mac,  &ciphertext[ciphertext_len-16], 16);
}

int main() {
  const char *key = "YELLOW SUBMARINE";
  const unsigned char iv[16] = {0};
  unsigned char mac[16];
  unsigned char victim_mac[16];
  char mac_hex[32+1] = {0};

  const char *snippet = "alert('MZA who was that?');\n";

  init_openssl();

  generate_cbc_mac(snippet, strlen(snippet), (unsigned char *)key, iv, mac);

  memcpy(victim_mac, mac, 16);
  bytesToHex(mac_hex, victim_mac, 16);
  cout << "Victim Mac: " << mac_hex << endl;

  const char *forged_snippet = "alert('Ayo, the Wu is back!'); //";
  int forged_snippet_len = strlen(forged_snippet);

  generate_cbc_mac(forged_snippet, strlen(forged_snippet), (unsigned char *)key, iv, mac);

  bytesToHex(mac_hex, mac, 16);
  cout << "Attack Mac: " << mac_hex << endl;

  // For this to work, this merely needs to finish with CBCing a
  // block that matches the snippet, i.e. forged_mac^snippet
  unsigned char attack_block[16];
  doXor(attack_block, mac, (unsigned char *)"alert('MZA who w", 16);
  const char *attack_suffix = "as that?');\n";

  char attack_snippet[128] = {0};
  memcpy(attack_snippet, forged_snippet, forged_snippet_len);
  memset(attack_snippet+forged_snippet_len, 0xf, 15);
  memcpy(attack_snippet+forged_snippet_len+15, attack_block, 16);
  memcpy(attack_snippet+forged_snippet_len+15+16, attack_suffix, strlen(attack_suffix));

  int msg_len = forged_snippet_len+15+16+strlen(attack_suffix);
  generate_cbc_mac(attack_snippet, msg_len, (unsigned char *)key, iv, mac);

  bytesToHex(mac_hex, mac, 16);
  cout << "Forged Mac: " << mac_hex << endl;

  cout << ((memcmp(mac, victim_mac, 16) == 0) ? "Success!" : "Fail") << endl;
  cout << "Malicious Javascript: " << endl << attack_snippet << endl;

  close_openssl();
}
