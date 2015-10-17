#ifndef CONVERSIONS_H
#define CONVERSIONS_H

void bytesToB64(char *dest, const unsigned char *source, int source_len);

int b64ToBytes(unsigned char *dest, const char *source);

void bytesToHex(char *dest, const unsigned char *source, int source_len);

int hexToBytes(unsigned char *dest, const char *source);

#endif
