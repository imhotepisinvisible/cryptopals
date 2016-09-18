#include "interval_union.h"

IntervalUnion::~IntervalUnion() {
  for (int i = 0; i < intervals.size(); i++) {
    if (intervals[i].first) BN_free(intervals[i].first);
    if (intervals[i].second) BN_free(intervals[i].second);
  }
}

void IntervalUnion::add_interval(const Interval &new_interval) {
  // If candidate is contained within an existing interval, do nothing.
  // Otherwise if the new interval overlaps with an existing interval,
  // remove it from the set and add the overlapped new union as if
  // it were a new interval. Otherwise, add the new interval
  Interval interval_to_add;
  int interval_to_remove = 0;
  bool add_new_interval = true;
  bool overlap = false;
  for (int i = 0; i < intervals.size(); i++) {
    if (contains(intervals[i], new_interval)) {
      add_new_interval = false;
      break;
    }

    if (!overlap) {
      interval_to_add = union_two_intervals(intervals[i], new_interval);
      if (interval_to_add.first || interval_to_add.second) {
	interval_to_remove = i;
	overlap = true;
      }
    }
  }

  if (add_new_interval) {
    if (overlap) {
      if (intervals[interval_to_remove].first)
	BN_free(intervals[interval_to_remove].first);
      if (intervals[interval_to_remove].second)
	BN_free(intervals[interval_to_remove].second);
      intervals.erase(intervals.begin()+interval_to_remove);
      
      add_interval(interval_to_add);
      if (interval_to_add.first) BN_free(interval_to_add.first);
      if (interval_to_add.second) BN_free(interval_to_add.second);
    } else {
      BIGNUM *a = BN_dup(new_interval.first);
      BIGNUM *b = BN_dup(new_interval.second);
      Interval newint(a,b);
      intervals.push_back(newint);
    }
  }
  return;
}

int IntervalUnion::number_intervals() const {
  return intervals.size();
}

Interval IntervalUnion::get_interval(const int n) const {
  Interval ret(NULL, NULL);

  if (n < intervals.size()) {
    ret = intervals[n];
  }

  return ret;
}

void IntervalUnion::clear() {
  intervals.clear();
}

Interval IntervalUnion::union_two_intervals(const Interval &first, const Interval &second) const {
  Interval ret(NULL, NULL);

  if ((BN_cmp(first.second, second.first) >= 0)
      && (BN_cmp(second.second, first.first) >= 0)) {
    BIGNUM *min = NULL;
    BIGNUM *max = NULL;

    if (BN_cmp(first.first, second.first) < 0) {
      min = BN_dup(first.first);
    } else {
      min = BN_dup(second.first);
    }

    if (BN_cmp(first.second, second.second) > 0) {
      min = BN_dup(first.second);
    } else {
      min = BN_dup(second.second);
    }
    
    Interval u(min, max);
    ret = u;
  }
  
  return ret;
}

bool IntervalUnion::contains(const Interval &outer, const Interval &inner) const {
  bool ret = false;

  if ((BN_cmp(outer.first, inner.first) <= 0)
      && (BN_cmp(outer.second, inner.second) >= 0)) {
    ret = true;
  }

  return ret;
}
