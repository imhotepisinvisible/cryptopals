#include <openssl/bn.h>

class SimpleClient {
public:
  SimpleClient(const char *N_str, const char *g_str, const char *k_str, const char *_I, const char *_P);
  ~SimpleClient();
  BIGNUM *generate_A();
  char *get_I();
  unsigned char *handshake(uint32_t salt, BIGNUM *B, BIGNUM *u);

private:
  BIGNUM *N;
  BIGNUM *g;
  BIGNUM *k;
  BIGNUM *A;
  BIGNUM *a;
  char *I;
  char *P;
  
};
