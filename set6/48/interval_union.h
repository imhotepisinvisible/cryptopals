#ifndef UNION_H
#define UNION_H

#include <utility>
#include <vector>

#include <openssl/bn.h>

typedef std::pair<BIGNUM *, BIGNUM *> Interval;

class IntervalUnion {
 public:
  ~IntervalUnion();
  void add_interval(const Interval &new_interval);
  int number_intervals() const;
  Interval get_interval(const int n) const;
  void clear();

 private:
  std::vector<Interval> intervals;
  
  Interval union_two_intervals(const Interval &first, const Interval &second) const;
  bool contains(const Interval &outer, const Interval &inner) const;

};

#endif
