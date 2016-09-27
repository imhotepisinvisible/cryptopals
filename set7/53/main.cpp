#include <iostream>
#include <sstream>
#include <cstdlib>
#include <vector>
#include <utility>
#include <cmath>

#include "utils.h"
#include "conversions.h"
#include "crypto.h"

using namespace std;

vector< pair<pair<char*,char*>, uint16_t> > find_collisions(const int k) {
  vector< pair<pair<char*,char*>, uint16_t> > ret;
  // Naive brute force
  char **collisions_M = new char*[65536];
  char **collisions_N = new char*[65536];
  uint16_t H = MD_MAGIC;
  for (int i = 1; i <= k; i++) {
    memset(collisions_M, 0, 65536*sizeof(char *));
    memset(collisions_N, 0, 65536*sizeof(char *));
    uint32_t N_len = (pow(2, k-i) + 1)*16;
    // Make dummy blocks and calc dummy H
    char *dummy_N = new char[N_len-16];
    arc4random_buf(dummy_N, N_len - 16);
    uint16_t dummy_J = md(dummy_N, N_len-16, H, false);
    while (true) {
      char *M = new char[16];
      arc4random_buf(M, 16);
      uint16_t I = md(M, 16, H, false);
      uint16_t J = md(M, 16, dummy_J, false);
      char *N = new char[N_len];
      memcpy(N, dummy_N, N_len-16);
      memcpy(N+N_len-16, M, 16);
      if (collisions_M[J] != 0) {
	//cout << "Collision1 found, H: " << J << endl;
	char *first = new char[16];
	memcpy(first, collisions_M[J], 16);
	char *second = new char[N_len];
	memcpy(second, N, N_len);
	pair<char*,char*> collision(first, second);
	pair<pair<char*,char*>, uint16_t> collision_hash(collision, J);
	ret.push_back(collision_hash);
	H = J;
	break;
      } else if (collisions_N[I] != 0) {
	//cout << "Collision2 found, H: " << I << endl;
	char *first = new char[16];
	memcpy(first, M, 16);
	char *second = new char[N_len];
	memcpy(second, collisions_N[I], N_len);
	pair<char*,char*> collision(first, second);
	pair<pair<char*,char*>, uint16_t> collision_hash(collision, I);
	ret.push_back(collision_hash);
	H = I;
	break;
      }
      collisions_M[I] = M;
      collisions_N[J] = N;
    }
    for (int i = 0; i < 65536; i++) {
      delete [] collisions_M[i];
      delete [] collisions_N[i];
    }
    delete [] dummy_N;
  }

  return ret;
}

void generate_prefix(vector< pair<pair<char*,char*>, uint16_t> > &collisions, const int k, const int len, char *M) {
  int len_remaining = len;
  int M_written = 0;
  uint32_t N_len = 0;
  for(int i = k - 1, j = 0; i >= 0; i--, j++) {
    N_len = (pow(2, i) + 1)*16;
    if (N_len + i*16 - 16 < len_remaining || (i == 0 && N_len == len_remaining)) {
      memcpy(M+M_written, collisions[j].first.second, N_len);
      len_remaining -= N_len;
      M_written += N_len;
    } else {
      memcpy(M+M_written, collisions[j].first.first, 16);
      len_remaining -= 16;
      M_written += 16;
    }
  }
}

int main() {
  init_openssl();

  int k = 14;
  uint32_t M_len = pow(2, k)*16;
  char *M = new char[M_len];
  arc4random_buf(M, M_len);
  M[M_len-1] = '\0';
  bool found = false;

  vector< pair<pair<char*,char*>, uint16_t> > collisions = find_collisions(k);

  // Generate map
  uint16_t *map_hash = new uint16_t[M_len/16];
  uint16_t H = MD_MAGIC;
  for (int i = 0; i < M_len/16; i++) {
    H = md(M+i*16, 16, H, false);
    map_hash[i] = H;
  }

  // Find collision into M_link
  char M_link[16];
  while (!found) {
    arc4random_buf(M_link, 16);
    uint16_t M_h = md(M_link, 16, collisions.back().second, false);
    for (int i = k; i < M_len/16; i++) {    
      if (map_hash[i] == M_h) {
	found = true;

	// Collision found, let's try and forge a message...
	int prefix_len = i*16;
	int suffix_len = M_len-(prefix_len+16);
	char *forgery = new char[M_len];
	
	generate_prefix(collisions, k, prefix_len, forgery);

	memcpy(forgery+prefix_len, M_link, 16);
	memcpy(forgery+prefix_len+16, M+(prefix_len+16), suffix_len);

	uint16_t H1 = md(M, M_len);
	uint16_t H2 = md(forgery, M_len);
	if (memcmp(M, forgery, M_len) == 0) {
	  cout << "Error, comparing the same message..." << endl;
	} else if (H1 != H2) {
	  cout << "Failure! Original hash: " << H1
	       << ". Forged hash: " << H2 << endl;
	} else {
	  cout << "Success! Original hash: " << H1
	       << ". Forged hash: " << H2 << endl;
	}

	delete [] forgery;
	break;
      }
    }
  }

  for (int i = 0; i < collisions.size(); i++) {
    delete [] collisions[i].first.first;
    delete [] collisions[i].first.second;
  }
  delete [] M;
  delete [] map_hash;
  
  close_openssl();
}
