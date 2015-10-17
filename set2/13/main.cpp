#include <iostream>
#include <fstream>
#include <cstdlib>
#include <map>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

const char *key = "YELLOW SUBMARINE";

map<string, string> parseCookie(const char* cookie) {
  map<string, string> result;

  while (*cookie) {
    int keyend = 0;
    int valuestart = 0;
    int valueend = 0;
    for (int i = 0; true; i++) {
      if (cookie[i] == '=') {
	keyend = i;
	valuestart = i+1;
      }
      if (cookie[i] == '&' ||  cookie[i] == '\0') {
	valueend = i;
	break;
      }
    }
    string key(cookie, keyend);
    if (!key.empty()) {
      string value(cookie+valuestart, valueend-keyend-1);
      result[key] = value;
      cookie += valueend+1;
    }
    else
      break;
  }

  return result;
}

void printMap(map<string, string> cookie) {
  for (map<string,string>::iterator it=cookie.begin(); it!=cookie.end(); ++it)
    cout << it->first << " => " << it->second << '\n';
}

string profile_for(string email) {
  size_t found = email.find('=');
  while (found!=std::string::npos) {
    email.erase(found,1);
    found = email.find('=');
  }
  found = email.find('&');
  while (found!=std::string::npos) {
    email.erase(found,1);
    found = email.find('&');
  }
  string result("email="+email+"&uid=10&role=user");
  return result;
}

int main() {
  //char *input = new char[102400];
  string input;
  unsigned char plaintext[1024];
  unsigned char ciphertext[1024];
  char cipherHex[1024];
  int ciphertext_len, plaintext_len;

  cout << "Input pls" << endl;
  getline(cin, input);

  string cookieStr = profile_for(input);

  init_openssl();

  // Generate output such that 'admin' (included in the email address) appears at the start of a block
  // Generate a second output such that 'user' (in role=user) appears at the start of a block
  // Replace the user block with the admin block
  ciphertext_len = encryptEcb((unsigned char*)cookieStr.c_str(), cookieStr.size(), (unsigned char*)key, ciphertext, false);
  bytesToHex(cipherHex, ciphertext, ciphertext_len);
  cout << cipherHex << endl;

  // First output:   DE27B3C7A54319F3FCF65A388EDC52A661F8E71181FDADF573BF49D5EFCDF88580AA101B7B10A13CBEBB4D292CBCD91D
  // Second output:  DE27B3C7A54319F3FCF65A388EDC52A693368B623168DD9594B891AED3E00AF4834ECA357DD8EBE6F976C63D96610A50
  // Spliced output: DE27B3C7A54319F3FCF65A388EDC52A693368B623168DD9594B891AED3E00AF461F8E71181FDADF573BF49D5EFCDF885
  char cipherhex[512];
  strcpy(cipherhex, "DE27B3C7A54319F3FCF65A388EDC52A693368B623168DD9594B891AED3E00AF461F8E71181FDADF573BF49D5EFCDF885");
  ciphertext_len = hexToBytes(ciphertext, cipherhex);
  
  plaintext_len = decryptEcb(ciphertext, ciphertext_len, (unsigned char*)key, plaintext, true);
  plaintext[plaintext_len] = '\0';
  
  map<string, string> cookie = parseCookie((char*)plaintext);
  printMap(cookie);

  close_openssl();
}
