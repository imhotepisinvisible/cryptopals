#ifndef UTILS_H
#define UTILS_H

void doXor(unsigned char *dest, const unsigned char *source1, const unsigned char *source2, int length);

int countSpaces(const unsigned char *source);

int calcHammingDistance(const unsigned char *source1, const unsigned char *source2, int length);

char singleCharXor(unsigned char *dest, unsigned char *source, int source_len);

void breakIntoBlocks(unsigned char **dest, const unsigned char *source, int no_blocks, int block_len);

void transposeBlocks(unsigned char **dest, unsigned char **source, int no_blocks, int keysize);

int pkcs7padding(unsigned char *block, int blockSize);

int detect_cipher(unsigned char *input, int input_len);

#endif
