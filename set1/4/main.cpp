#include <iostream>
#include <fstream>

#include "conversions.h"
#include "utils.h"

using namespace std;

int main() {
  char input[256];
  unsigned char inputBytes[1024];
  unsigned char winner[256];
  char overallWinner[256];
  char winningInput[256];

  ifstream in_file("4.txt");
  int overallResult;
  int overallTopScore = 0;
  while (!in_file.eof()) {
    in_file.getline(input, 256);
    int length = hexToBytes(inputBytes, input);

    singleCharXor(winner, inputBytes, length);

    //cout << winner << endl;
    overallResult = countSpaces(winner);
    if (overallResult > overallTopScore) {
      overallTopScore = overallResult;
      bytesToHex(winningInput, inputBytes, length);
      strcpy(overallWinner, (char *)winner);
    }
  }

  cout << winningInput << endl;
  cout << overallWinner << endl;
}
