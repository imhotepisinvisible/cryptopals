#include <iostream>

#include "conversions.h"

using namespace std;

static const char *codes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

void bytesToB64(char *dest, const unsigned char *source, int source_len) {
  int b;
  for (int i = 0; i < source_len; i += 3) {
    b = (source[i] & 0xFC) >> 2;
    *(dest++) = codes[b];
    b = (source[i] & 0x03) << 4;
    
    if (i + 1 < source_len) {
      b |= (source[i + 1] & 0xF0) >> 4;
      *(dest++) = codes[b];
      b = (source[i + 1] & 0x0F) << 2;
      
      if (i + 2 < source_len) {
	b |= (source[i + 2] & 0xC0) >> 6;
	*(dest++) = codes[b];
	b = source[i + 2] & 0x3F;
	*(dest++) = codes[b];
      } else {
	*(dest++) = codes[b];
	*(dest++) = codes[63];
      }
    } else {
      *(dest++) = codes[b];
      *(dest++) = codes[63];
      *(dest++) = codes[63];
    }
  }
  *dest = '\0';
}

int b64ToBytes(unsigned char *dest, const char *source){
  int source_len = strlen(source);
  char *mSource = new char[source_len];
  char *mSourceStart = mSource;
  int padding = 0;
  if (source[source_len-2] == '=')
    padding = 2;
  else if (source[source_len-1] == '=')
    padding = 1;
  
  while (*source) {
    if (*source >= 'A' && *source <= 'Z')
      *(mSource++) = *source - 'A';
    else if (*source >= 'a' && *source <= 'z')
      *(mSource++) = *source - ('a' - 26);
    else if (*source >= '0' && *source <= '9')
      *(mSource++) = *source - ('0' - 52);
    else if (*source == '+')
      *(mSource++) = 62;
    else if (*source == '/')
      *(mSource++) = 63;
    else if (*source != '=')
      source_len--;

    source++;
  }

  int dest_len = (source_len * 3) / 4;
  mSource = mSourceStart;
  int j = 0;
  for (int n = 0; n < source_len; n+=4) {
    unsigned char b[4];
    b[0] = *(mSource++);
    b[1] = *(mSource++);
    b[2] = *(mSource++);
    b[3] = *(mSource++);
    dest[j++] = ((b[0] << 2) | (b[1] >> 4));
    if (b[2] < 64) {
      dest[j++] = ((b[1] << 4) | (b[2] >> 2));
      if (b[3] < 64) {
	dest[j++] = ((b[2] << 6) | b[3]);
      }
    }
  }

  delete [] mSourceStart;
  return dest_len - padding;
}

void bytesToHex(char *dest, const unsigned char *source, int source_len) {
  unsigned char hexArray[] = "0123456789ABCDEF";
  for (int i = 0; i < source_len; i++) {
    int v = source[i] & 0xFF;
    dest[i * 2] = hexArray[v >> 4];
    dest[i * 2 + 1] = hexArray[v & 0x0F];
  }
  dest[source_len*2] = '\0';
}

int hexToBytes(unsigned char *dest, const char *source) {
  int source_len = strlen(source);
  char *mSource = new char[source_len];
  char *mSourceStart = mSource;
  
  while (*source) {
    if (*source >= 'A' && *source <= 'F')
      *mSource = *source - 'A' + 10;
    else if (*source >= 'a' && *source <= 'f')
      *mSource = *source - 'a' + 10;
    else if (*source >= '0' && *source <= '9')
      *mSource = *source - '0';

    mSource++;
    source++;
  }

  int dest_len = source_len/2;
  mSource = mSourceStart;
  int j = 0;
  for (int n = 0; n < source_len; n+=2) {
    unsigned char b[2];
    b[0] = *(mSource++);
    b[1] = *(mSource++);
    dest[j++] = ((b[0] << 4) | (b[1] & 0x0F));
  }

  delete [] mSourceStart;
  return dest_len;
}
