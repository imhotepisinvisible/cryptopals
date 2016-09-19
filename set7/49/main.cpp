#include <iostream>
#include <sstream>
#include <cstdlib>
#include <vector>
#include <utility>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

unsigned char key[16];
const unsigned char fixed_iv[16] = {0};

void generate_cbc_mac_internal(const char *msg, const unsigned char *iv, unsigned char *mac) {
  unsigned char ciphertext[512];

  int ciphertext_len = encryptCbc((unsigned char *)msg, strlen(msg), key, iv, ciphertext);

  memcpy(mac,  &ciphertext[ciphertext_len-16], 16);
}

void generate_cbc_mac(const string &msg, unsigned char *iv, unsigned char *mac) {
  arc4random_buf(iv, 16);
  generate_cbc_mac_internal(msg.c_str(), iv, mac);
}

void generate_cbc_mac(const string &msg, unsigned char *mac) {
  generate_cbc_mac_internal(msg.c_str(), fixed_iv, mac);
}

bool verify_cbc_mac(const string &msg, const unsigned char *iv, const unsigned char *mac) {
  cout << "Verifying message " << msg << endl;
  unsigned char ciphertext[512];

  int ciphertext_len = encryptCbc((unsigned char *)msg.c_str(), msg.length(), (unsigned char *)key, iv, ciphertext);

  return (CRYPTO_memcmp(mac, &ciphertext[ciphertext_len-16], 16) == 0);
}

bool verify_cbc_mac(const string &msg, const unsigned char *mac) {
  return verify_cbc_mac(msg, fixed_iv, mac);
}

// takes from_id param for ease, but assume the client would not supply this
string create_msg(const int from_id, const int to_id, const int amount) {
  stringstream ss;
  // (Feel free to sanitize params if you're feeling anal-retentive.)
  ss << "from=" << from_id << "&to=" << to_id << "&amount=" << amount;
  return ss.str();
}

string create_msg(const int from_id, vector< pair<int,long> > trans_list) {
  stringstream ss;
  // (Feel free to sanitize params if you're feeling anal-retentive.)
  ss << "from=" << from_id;
  for (int i = 0; i < trans_list.size(); i++) {
    ss << (i == 0 ? "&tx_list=" : ";") << trans_list[i].first << ":" << trans_list[i].second;
  }
  return ss.str();
}

int main() {
  unsigned char iv[16];
  unsigned char mac[16];
  arc4random_buf(key, 16);

  init_openssl();

  // Let victim id = 1
  // Let third party id = 2
  // Let attacker id 1 = 3
  // Let attacker id 2 = 4

  // Part 1
  
  // Testing
  string msg = create_msg(1, 2, 1000);
  generate_cbc_mac(msg, iv, mac);
  bool valid = verify_cbc_mac(msg, iv, mac);
  cout << (valid ? "Valid" : "Not valid") << endl;

  // Attack time
  // First, get our valid message and sign it
  string attack_msg1 = create_msg(3, 4, 1000000);
  generate_cbc_mac(attack_msg1, iv, mac);
  valid = verify_cbc_mac(attack_msg1, iv, mac);
  cout << (valid ? "Valid" : "Not valid") << endl;

  // Now create our malicious message
  string attack_msg2 = "from=1&to=4&amount=1000000";

  // Now modify the IV.  Because the IV is XORd with the input,
  // the principle is to adjust the IV so that
  // attack_msg^new_iv = msg^iv
  unsigned char attack_iv[16];
  memcpy(attack_iv, iv, 16);
  attack_iv[5] ^= 2;

  // And test
  valid = verify_cbc_mac(attack_msg2, attack_iv, mac);
  cout << (valid ? "Valid" : "Not valid") << endl;
  
  // Part 2
  // Get a message from the victim
  pair<int,long> trans(2, 1000);
  vector< pair<int,long> > trans_list;
  trans_list.push_back(trans);
  string msg2 = create_msg(1, trans_list);
  generate_cbc_mac(msg2, mac);
  valid = verify_cbc_mac(msg2, mac);
  cout << (valid ? "Valid" : "Not valid") << endl;

  unsigned char victim_mac[16];
  memcpy(victim_mac, mac, 16);

  // Get a valid message from us which we will use
  pair<int,long> trans2(4, 1);
  pair<int,long> trans3(4, 1000000);
  vector< pair<int,long> > trans_list2;
  trans_list2.push_back(trans2);
  trans_list2.push_back(trans3);
  string attack_msg3 = create_msg(3, trans_list2);
  generate_cbc_mac(attack_msg3, mac);
  valid = verify_cbc_mac(attack_msg3, mac);
  cout << (valid ? "Valid" : "Not valid") << endl;

  // Our generated message was
  // from=3&tx_list=4:1;4:1000000
  // and we have a valid mac for it
  // Now all we need to do is add (mac ^ from=3&tx_list=4) to the
  // victim's message followed by ;4:1000000 and we should be good
  // Not that we'll also need to include valid padding in the middle,
  // hopefully the server will just ignore this...
  char full_attack[128] = {0};
  const char *attack_msg4 = "from=1&tx_list=2:1000\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
  int attack_prefix = strlen(attack_msg4);
  const char *attack_suffix = ":1;4:1000000";
  unsigned char attack_block[16];
  doXor(attack_block, victim_mac, (unsigned char *) "from=3&tx_list=4", 16);
  memcpy(full_attack, attack_msg4, attack_prefix);
  memcpy(full_attack+attack_prefix, attack_block, 16);
  memcpy(full_attack+attack_prefix+16, attack_suffix, strlen(attack_suffix));
  string attack_msg4S(full_attack);
  valid = verify_cbc_mac(attack_msg4S, mac);
  cout << (valid ? "Valid" : "Not valid") << endl;

  close_openssl();
}
