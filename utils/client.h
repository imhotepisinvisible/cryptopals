#include <openssl/bn.h>

class Client {
public:
  Client(const char *N_str, const char *g_str, const char *k_str, const char *_I, const char *_P);
  ~Client();
  BIGNUM *generate_A();
  char *get_I();
  unsigned char *handshake(uint32_t salt, BIGNUM *B);

private:
  BIGNUM *N;
  BIGNUM *g;
  BIGNUM *k;
  BIGNUM *A;
  BIGNUM *a;
  char *I;
  char *P;
  
};
