#include <iostream>
#include <sstream>
#include <cstdlib>
#include <zlib.h>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

string format_request(const char *P) {
  stringstream ss;

  ss << "POST / HTTP/1.1" << endl
     << "Host: hapless.com" << endl
     << "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=" << endl
     << "Content-Length: " << strlen(P) << endl
     << P << endl;

  return ss.str();
}

int compress(unsigned char *buffer, const int buffer_size, const char *P) {
  // http://stackoverflow.com/questions/7540259/deflate-and-inflate-zlib-h-in-c
  // zlib struct
  z_stream defstream;
  defstream.zalloc = Z_NULL;
  defstream.zfree = Z_NULL;
  defstream.opaque = Z_NULL;
  defstream.avail_in = strlen(P); // size of input
  defstream.next_in = (Bytef *)P; // input char array
  defstream.avail_out = buffer_size; // size of output
  defstream.next_out = buffer; // output char array
    
  deflateInit(&defstream, Z_DEFAULT_COMPRESSION);
  deflate(&defstream, Z_FINISH);
  deflateEnd(&defstream);

  return defstream.total_out;
}

int oracle(const char *P) {
  string P_format = format_request(P);
  unsigned char P_compress[512];
  unsigned char P_encrypt[512];
  unsigned char key[16];
  arc4random_buf(key, 16);
  unsigned char nonce[8];
  arc4random_buf(nonce, 8);
  
  int compress_len = compress(P_compress, sizeof(P_compress), P_format.c_str());
     
  int ciphertext_len = encryptCtr(P_compress, compress_len, key, nonce, P_encrypt);

  return ciphertext_len;
}

int oracle2(const char *P) {
  string P_format = format_request(P);
  unsigned char P_compress[512];
  unsigned char P_encrypt[512];
  unsigned char key[16];
  arc4random_buf(key, 16);
  unsigned char iv[16];
  arc4random_buf(iv, 16);

  int compress_len = compress(P_compress, sizeof(P_compress), P_format.c_str());
     
  int ciphertext_len = encryptCbc(P_compress, compress_len, key, iv, P_encrypt);

  return ciphertext_len;
}

int main() {
  init_openssl();

  char cookie[128] = {0};
  int len1 = 0;
  int len2 = 0;
  // Assume we know the cookie begins 'sessionid='
  strcpy(cookie, "sessionid=");

  // CTR mode
  char match;
  // We use the two-tries method as described by
  // Duong and Rizzo
  for (int i = 10; i < 60; i++) {
    for (unsigned char c = 10; c < 123; c++) {
      cookie[i] = c;
      strcpy(&cookie[i+1], "{}{}{}{}");
      len1 = oracle(cookie);
      strcpy(&cookie[i], "{}{}{}{}");
      cookie[i+8] = c;
      len2 = oracle(cookie);
      if (len1 < len2) {
	match = c;
      }
    }
    cookie[i] = match;
    if (match == '\n') {
      cookie[i+1] = '\0';
      break;
    }
  }
  cout << cookie << endl;

  // CBC mode
  memset(cookie, 0, 128);
  strcpy(cookie, "sessionid=");

  // We need to figure out how much padding to add to bring
  // us to the block boundary
  const char *padding_hex = "C9F8D92BD56FB10CB8191375B93D5D51";
  unsigned char padding[16];
  hexToBytes(padding, padding_hex);
  int padding_len = 0;
  len1 = len2 = oracle2(cookie);
  while (len1 == len2) {
    padding_len++;
    memcpy(&cookie[10], padding, padding_len);
    len1 = oracle2(cookie);
  }

  for (int i = 10; i < 60; i++) {
    for (unsigned char c = 10; c < 123; c++) {
      cookie[i] = c;
      memcpy(&cookie[i+1], padding, padding_len-1);
      len2 = oracle2(cookie);
      if (len2 < len1) {
	match = c;
      }
    }
    cookie[i] = match;
    if (match == '\n') {
      cookie[i+1] = '\0';
      break;
    }
  }
  cout << cookie << endl;
  
  close_openssl();
}
