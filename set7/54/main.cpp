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

struct Node {
  Node() : parent(NULL), H(0), M(NULL) {}
  ~Node() {
    if (M) delete [] M;
  }
  Node *parent;
  uint16_t H;
  char *M;
};

Node *find_collision(Node *first, Node *second) {
  Node *parent = NULL;
  // Naive brute force
  char **collisions_M = new char*[65536];
  char **collisions_N = new char*[65536];
  
  memset(collisions_M, 0, 65536*sizeof(char *));
  memset(collisions_N, 0, 65536*sizeof(char *));
  while (true) {
    char *M = new char[16];
    arc4random_buf(M, 16);
    char *N = new char[16];
    arc4random_buf(N, 16);
    uint16_t I = md(M, 16, first->H, false);
    uint16_t J = md(N, 16, second->H, false);
    if (collisions_M[J] != 0) {
      //cout << "Collision1 found, H: " << J << endl;
      parent = new Node;
      parent->H = J;
      first->parent = parent;
      second->parent = parent;
      
      first->M = new char[16];
      memcpy(first->M, collisions_M[J], 16);
      second->M = new char[16];
      memcpy(second->M, N, 16);
      break;
    } else if (collisions_N[I] != 0) {
      //cout << "Collision2 found, H: " << I << endl;
      parent = new Node;
      parent->H = I;
      first->parent = parent;
      second->parent = parent;
      
      first->M = new char[16];
      memcpy(first->M, M, 16);
      second->M = new char[16];
      memcpy(second->M, collisions_N[I], 16);
      break;
    }
    collisions_M[I] = M;
    collisions_N[J] = N;
  }
  for (int i = 0; i < 65536; i++) {
    delete [] collisions_M[i];
    delete [] collisions_N[i];
  }

  return parent;
}

int main() {
  init_openssl();

  int k = 10;
  int max = pow(2, k);
  bool found = false;

  vector<Node*> funnel;

  for (int i = 0; i < max; i++) {
    Node *leaf = new Node;
    arc4random_buf(&(leaf->H), 2);
    funnel.push_back(leaf);
  }

  for (int depth = 0, width = max; width > 1; depth+=width, width/=2) {
    for (int i = 0; i < width; i+=2) {
      Node *parent = find_collision(funnel[i+depth], funnel[i+1+depth]);
      funnel.push_back(parent);
    }
  }

  Node *root;
  root = funnel[0];
  while (root->parent) {
    root = root->parent;
  }

  // If the padding of my simple md encoded the message
  // length we would add it here.  Instead add pkcs7 padding
  char padding_block[16];
  memset(padding_block, 16, 16);
  uint16_t prediction_H = md(padding_block, 16, root->H, false);
  cout << "My hashed prediction is: " << prediction_H << endl;

  const char *prediction = "Brexit will happen";
  int prediction_len = strlen(prediction);
  cout << "Prediction: " << prediction << endl;
  uint16_t orig_pred_H = md(prediction, prediction_len);
  cout << "Normal prediction hash: " << orig_pred_H << endl;

  // Find collision into M_link
  char M_link[16];
  while (!found) {
    arc4random_buf(M_link, 16);
    uint16_t M_h = md(M_link, 16, orig_pred_H, false);
    for (int i = 0; i < max; i++) {    
      if (funnel[i]->H == M_h) {
	found = true;

	// Collision found, let's try and forge a message...
	int prefix_len = (prediction_len/16 + 1)*16;
	int suffix_len = k*16;
	int M_len = prefix_len + 16 + suffix_len;
	char *forgery = new char[M_len+1];

	memcpy(forgery, prediction, prediction_len);
	// Pad out prediction
	int padding = 16 - (prediction_len%16);
	for(int k = 0; k < padding; k++) {
	  forgery[strlen(prediction)+k] = (char)padding;
	}
	
	memcpy(forgery+prefix_len, M_link, 16);

	root = funnel[i];
	int depth = 0;
	while (root->parent) {
	  memcpy(forgery+prefix_len+16+depth*16, root->M, 16);
	  root = root->parent;
	  depth++;
	}

	uint16_t forged_H = md(forgery, M_len);
	if (prediction_H != forged_H) {
	  cout << "Failure! Original hash: " << prediction_H
	       << ". Forged hash: " << forged_H << endl;
	} else {
	  cout << "Success! Original hash: " << prediction_H
	       << ". Forged hash: " << forged_H << endl;
	  forgery[M_len] = '\0';
	  cout << "Prediction: " << forgery << endl;
	}

	delete [] forgery;
	break;
      }
    }
  }

  for (int i = 0; i < funnel.size(); i++) {
    delete funnel[i];
  }
  
  close_openssl();
}
