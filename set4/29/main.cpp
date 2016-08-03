#include <iostream>
#include <fstream>
#include <cstdlib>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"
#include "sha1.h"

using namespace std;

int compute_md_padding(uint64_t message_len, unsigned char *padding) {
  int padding_len = 0;
  message_len = message_len*8; //bits
  int sha_block_size = 512; //bits
  int final_block_len = message_len % sha_block_size; //bits

  if (sha_block_size - final_block_len < 64 + 1) {
    padding_len = sha_block_size + sha_block_size - final_block_len;
  } else {
    padding_len = sha_block_size - final_block_len;
  }

  *(padding++) = 0x80;
  for (int i = 0; i < (padding_len - 8 - 64)/8; i++) {
    *(padding++) = 0;
  }
  uint32_t len = htonl(*((uint32_t *)&message_len+1));
  memcpy(padding, (unsigned char *)&len, sizeof(uint32_t));
  len = htonl(*((uint32_t *)&message_len));
  memcpy(padding+4, (unsigned char *)&len, sizeof(uint32_t));
  
  return padding_len/8;
}

int main() {
  unsigned char mac[SHA1_HASH_LEN];
  unsigned char craftedMac[SHA1_HASH_LEN];
  char macHex[SHA1_HASH_LEN*2+1];
  char key[64];
  const char *message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
  const char *attack_string = ";admin=true";
  SHA1Context sha;
  unsigned char padding[1024];
  unsigned char newMessage[1024];
  char newMessageHex[1024*2+1];

  ifstream in_file("/usr/share/dict/words");
  int line = arc4random_uniform(235886)+1; //length of /usr/share/dict/words
  for (int i = 0; i < line; i++) {
    in_file.getline(key, 64);
  }

  if (!generate_secret_prefix_mac((unsigned char *)key, strlen(key), message, mac)) {
    cout << "Error generating MAC" << endl;
  }

  bytesToHex(macHex, mac, SHA1_HASH_LEN);
  cout << "Generated MAC: " << macHex << endl;

  // We have to guess key length - we can just brute force it
  for (int key_len = 1; key_len < 64; key_len++) {
    cout << "Key length: " << key_len << ". ";
    
    int padding_len = compute_md_padding(key_len + strlen(message), padding);

    // craft our fixated sha context
    SHA1Reset(&sha);
    for(int i = 0; i < 5 ; i++) {
      sha.Message_Digest[i] = ntohl(*((uint32_t *)mac+i));
    }
    sha.Length_Low = (key_len+strlen(message)+padding_len)*8;

    // add what we want to hash
    SHA1Input(&sha, (unsigned char *)attack_string, strlen(attack_string));
    if (!SHA1Result(&sha)) {
      cout << "ERROR-- could not compute message digest" << endl;
      return 1;
    }

    uint32_t bytes = 0;
    for(int i = 0; i < 5 ; i++) {
      bytes = htonl(sha.Message_Digest[i]);
      memcpy(craftedMac+i*4, (unsigned char *)&bytes, sizeof(uint32_t));
    }

    bytesToHex(macHex, craftedMac, SHA1_HASH_LEN);
    cout << "Crafted MAC: " << macHex << endl;

    // craft the full message to be sent to the server
    memcpy(newMessage, message, strlen(message));
    memcpy(newMessage+strlen(message), padding, padding_len);
    memcpy(newMessage+strlen(message)+padding_len, attack_string, strlen(attack_string));
    int newMessage_len = strlen(message)+padding_len+strlen(attack_string);
    if (!authenticate_secret_prefix_mac((unsigned char *)key, strlen(key), newMessage, newMessage_len, craftedMac)) {
      cout << "MAC could not be verified" << endl;
    } else {
      bytesToHex(newMessageHex, newMessage, newMessage_len);
      cout << "MAC verified" << endl << "Crafted message: " << newMessageHex << endl;
      break;
    }
  }

  return 0;
}
