#ifndef PERSON_H
#define PERSON_H

#include <openssl/bn.h>

class Person {
public:
  Person(const char *p_str, const char *g_str);
  Person(BIGNUM *_p, BIGNUM *_g, BIGNUM *_B);
  ~Person();
  BIGNUM *get_pub();
  BIGNUM *get_p();
  BIGNUM *get_g();
  void set_g(const char *g_str);
  void set_recipient_pub(BIGNUM *_B);
  int encrypt(const char *plaintext, unsigned char *iv, unsigned char *ciphertext);
  int decrypt(unsigned char *ciphertext, const int ciphertext_len, unsigned char *iv, char *plaintext);

private:
  BIGNUM *p;
  BIGNUM *g;
  BIGNUM *a;
  BIGNUM *A;
  BIGNUM *B;
  unsigned char *hash;

  void set_keys();
  unsigned char *calculate_hash();
  
};

#endif
