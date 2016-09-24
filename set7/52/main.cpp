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

vector< pair<char*,char*> > find_collisions(const int n) {
  vector< pair<char*,char*> > ret;
  // Naive brute force
  char **collisions = new char*[65536];
  uint16_t H = 0xbeef;
  int total_collisions = 0;
  for (int i = 0; i < n; i++) {
    memset(collisions, 0, 65536*sizeof(char *));
    while (true) {
      total_collisions++;
      char *M = new char[16];
      arc4random_buf(M, 16);
      uint16_t I = md(M, 16, H, false);
      if (collisions[I] != 0) {
	//cout << "Collision found: " << flags[I] << " and " << i << ". H: " << I << endl;
	char *first = new char[16];
	memcpy(first, M, 16);
	char *second = new char[16];
	memcpy(second, collisions[I], 16);
	pair<char*,char*> collision(first, second);
	ret.push_back(collision);
	H = I;
	break;
      }
      collisions[I] = M;
    }
  }

  cout << "Total number of calls to the collision function was: " << total_collisions << endl;

  for (int i = 0; i < 65536; i++) {
    delete [] collisions[i];
  }

  return ret;
}

void generate_combos(const vector< pair<char*,char*> > &collisions, int i, char *M, vector< pair<char*,uint32_t> > &combinations) {
  // Base case: add to vector and return
  if (i == collisions.size()) {
    char *combo = new char[collisions.size()*16];
    memcpy(combo, M, collisions.size()*16);
    uint32_t hash = md2(combo, collisions.size()*16);
    pair<char*,uint32_t> combo_hash(combo, hash);
    combinations.push_back(combo_hash);
    return;
  }

  // Add first to M, call generate_combos
  memcpy(M+i*16, collisions[i].first, 16);
  generate_combos(collisions, i+1, M, combinations);

  // Add second to M, call generate_combos
  memcpy(M+i*16, collisions[i].second, 16);
  generate_combos(collisions, i+1, M, combinations);
}

int main() {
  init_openssl();

  int n = 16;
  char M[n*16];
  bool found = false;

  while (!found) {
    vector< pair<char*,char*> > collisions = find_collisions(n);
    vector< pair<char*,uint32_t> > combinations;

    generate_combos(collisions, 0, M, combinations);

    for (int i = 0; i < combinations.size() && !found; i++) {
      for (int j = i+1; j < combinations.size(); j++) {
	if (combinations[i].second == combinations[j].second) {
	  cout << "Found collision: " << endl;

	  char hex[(n*16*2)+1];
	  bytesToHex(hex, (unsigned char*)combinations[i].first, n*16);
	  cout << hex << endl;
	  bytesToHex(hex, (unsigned char*)combinations[j].first, n*16);
	  cout << hex << endl;
	
	  cout << md(combinations[i].first, n*16) << " "
	       << md(combinations[j].first, n*16) << " "
	       << md2(combinations[i].first, n*16) << " "
	       << md2(combinations[j].first, n*16) << endl;
	  found = true;
	  break;
	}
      }
    }

    for (int i = 0; i < collisions.size(); i++) {
      delete[] collisions[i].first;
      delete[] collisions[i].second;
    }
    for (int i = 0; i < combinations.size(); i++) {
      delete[] combinations[i].first;
    }
  }
  
  close_openssl();
}
