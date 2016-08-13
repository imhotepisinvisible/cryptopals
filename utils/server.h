#include <openssl/bn.h>

class Server {
public:
  Server(const char *N_str, const char *g_str, const char *k_str, const char *_I, const char *_P);
  ~Server();
  void handshake(const char *_I, BIGNUM *A, BIGNUM **B, uint32_t *_salt);
  bool validate_hmac(const unsigned char *_hmac);

private:
  BIGNUM *N;
  BIGNUM *g;
  BIGNUM *k;
  BIGNUM *v;
  char *I;
  char *P;
  uint32_t salt;
  unsigned char *hmac;
  
};
