#include <iostream>
#include <iomanip>
#include <ctime>
#include <curl/curl.h>

#include "conversions.h"
#include "crypto.h"

using namespace std;

// http://stackoverflow.com/a/1468834
int timeval_subtract(struct timeval *result, struct timeval *t2, struct timeval *t1)
{
    long int diff = (t2->tv_usec + 1000000 * t2->tv_sec) - (t1->tv_usec + 1000000 * t1->tv_sec);
    result->tv_sec = diff / 1000000;
    result->tv_usec = diff % 1000000;

    return (diff<0);
}
 
int main() {
  CURL *curl;
  CURLcode res;
  string url;
  string file = "file";
  unsigned char hmac[SHA1_HASH_LEN];
  unsigned char realhmac[SHA1_HASH_LEN];
  char hmacStr[SHA1_HASH_LEN*2+1];
  memset(realhmac, 0, SHA1_HASH_LEN);

  struct timeval tvBegin, tvEnd, tvDiff;

  int highestms = 0;
  int totalms = 0;
  bool success = false;

  std::cout << unitbuf;
  curl = curl_easy_init();
  if(curl) {
    for (int i = 0; i < SHA1_HASH_LEN && !success; i++) {
      highestms = 0;
      memcpy(hmac, realhmac, SHA1_HASH_LEN);
      for (int j = 0; j < 256 && !success; j++) {
	totalms = 0;
	for (int k = 0; k < 10 && !success; k++) {
	  cout << setw(2) << setfill('0') << hex << j;
	  hmac[i] = j;
	  bytesToHex(hmacStr, hmac, SHA1_HASH_LEN);
	  url = "http://127.0.0.1:4567/test?file=" + file + "&signature=" + hmacStr;
	  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
 
	  /* Perform the request, res will get the return code */
	  gettimeofday(&tvBegin, NULL);
	  res = curl_easy_perform(curl);
	  /* Check for errors */ 
	  if(res == CURLE_OK) {
	    long http_code = 0;
	    curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
	    if (http_code == 200) {
	      success = true;
	    }
	    else {
	      gettimeofday(&tvEnd, NULL);
	      timeval_subtract(&tvDiff, &tvEnd, &tvBegin);
	      totalms += tvDiff.tv_usec;
	      cout << '\b' << '\b';
	    }
	  } else {
	    cout << "curl_easy_perform() failed: " << curl_easy_strerror(res) << endl;
	  }
	}
	curl_easy_reset(curl);
	if (totalms > highestms) {
	  highestms = totalms;
	  realhmac[i] = j;
	}
      }
      cout << setw(2) << setfill('0') << hex << (int)realhmac[i];
      if (success) {
	cout << endl << "Key found!" << endl;
      }
    }
 
    /* always cleanup */ 
    curl_easy_cleanup(curl);
  }
  return 0;
}
