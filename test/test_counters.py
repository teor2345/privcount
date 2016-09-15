#!/usr/bin/python

from privcount.util import SecureCounters
import sys

# This maximum must be kept the same as privcount's configured q value
q = 999999999959L

# A simple set of byte counters
counters = {
  'SanityCheck': {
    'bins':
    [
      [0.0, float('inf')],
    ],
    'sigma': 0.0
  },
  'Bytes': {
    'bins':
    [
      [0.0, 512.0],
      [512.0, 1024.0],
      [1024.0, 2048.0],
      [2048.0, 4096.0],
      [4096.0, float('inf')],
    ],
    'sigma': 0.0
  }
}

# create the counters for a data collector, who will generate the shares and
# noise
# uses q to generate the appropriate blinding factors
# returns a tuple containing a list of DCs and a list of SKs
def create_counters(counters, q):
    sc_dc = SecureCounters(counters, q)
    sc_dc.generate(['sk1', 'sk2'], 1.0)
    # get the shares used to init the secure counters on the share keepers
    shares = sc_dc.detach_blinding_shares()

    # create share keeper versions of the counters
    sc_sk1 = SecureCounters(counters, q)
    sc_sk1.import_blinding_share(shares['sk1'])
    sc_sk2 = SecureCounters(counters, q)
    sc_sk2.import_blinding_share(shares['sk2'])
    return ([sc_dc], [sc_sk1, sc_sk2])


# run a set of increments at the dc N times, using the two-argument form of
# increment() to increment by 1 each time
# each bin has 0, 1, or 2 values added per increment
# Returns long(N)
def increment_counters(dc_list, N):
    sc_dc = dc_list[0]
    # xrange only accepts python ints, which is ok, because it's impossible to
    # increment more than 2**31 times in any reasonable test duration
    assert N <= sys.maxint
    for _ in xrange(int(N)):
        # bin[0]
        sc_dc.increment('Bytes', 0.0)
        sc_dc.increment('Bytes', 511.0)
        #bin[1]
        sc_dc.increment('Bytes', 600.0)
        #bin[2]
        sc_dc.increment('Bytes', 1024.0)
        sc_dc.increment('Bytes', 2047.0)
        #bin[3]
        pass
        #bin[4]
        sc_dc.increment('Bytes', 4096.0)
        sc_dc.increment('Bytes', 10000.0)
    return long(N)

# run a set of increments at the dc N times, incrementing by X each time
# each bin has 0, 1, or 2 values added per increment
# Returns long(N) * long(X)
def increment_counters_num(dc_list, N, X=1L):
    sc_dc = dc_list[0]
    # xrange only accepts python ints, which is ok, because it's impossible to
    # increment more than 2**31 times in any reasonable test duration
    assert N <= sys.maxint
    for _ in xrange(int(N)):
        # bin[0]
        sc_dc.increment('Bytes', 0.0, long(X))
        sc_dc.increment('Bytes', 511.0, long(X))
        #bin[1]
        sc_dc.increment('Bytes', 600.0, long(X))
        #bin[2]
        sc_dc.increment('Bytes', 1024.0, long(X))
        sc_dc.increment('Bytes', 2047.0, long(X))
        #bin[3]
        pass
        #bin[4]
        sc_dc.increment('Bytes', 4096.0, long(X))
        sc_dc.increment('Bytes', 10000.0, long(X))
    return long(N)*long(X)

# Sums the counters in dc_list and sk_list, with maximum count q
# Returns a tallies object populated with the resulting counts
def sum_counters(counters, q, dc_list, sk_list):
    # get all of the counts, send for tallying
    counts_dc_list = [sc_dc.detach_counts() for sc_dc in dc_list]
    counts_sk_list = [sc_sk.detach_counts() for sc_sk in sk_list]

    # tally them up
    sc_ts = SecureCounters(counters, q)
    counts_list = counts_dc_list + counts_sk_list
    is_tally_success = sc_ts.tally_counters(counts_list)
    assert is_tally_success
    return sc_ts.detach_counts()

# Checks that the tallies are the expected values, based on the number of
# repetitions N
def check_counters(tallies, N):
    print tallies
    assert tallies['Bytes']['bins'][0][2] == 2*N
    assert tallies['Bytes']['bins'][1][2] == 1*N
    assert tallies['Bytes']['bins'][2][2] == 2*N
    assert tallies['Bytes']['bins'][3][2] == 0*N
    assert tallies['Bytes']['bins'][4][2] == 2*N
    assert tallies['SanityCheck']['bins'][0][2] == 0
    print "all counts are correct!"

# Check that secure counters increment correctly for small values of N
# using the default increment of 1
print "Multiple increments, 2-argument form of increment:"
N = 500L
(dc_list, sk_list) = create_counters(counters, q)
amount = increment_counters(dc_list, N)
assert amount == N
tallies = sum_counters(counters, q, dc_list, sk_list)
check_counters(tallies, amount)

# Check that secure counters increment correctly for a single increment
# using a small value of num_increment
print "Single increment, 3-argument form of increment:"
N = 1L
X = 500L
(dc_list, sk_list) = create_counters(counters, q)
amount = increment_counters_num(dc_list, N, X)
assert amount == N*X
tallies = sum_counters(counters, q, dc_list, sk_list)
check_counters(tallies, amount)

# And multiple increments using the 3-argument form
print "Multiple increments, 3-argument form of increment, explicit +1:"
N = 500L
X = 1L
(dc_list, sk_list) = create_counters(counters, q)
amount = increment_counters_num(dc_list, N, X)
assert amount == N*X
tallies = sum_counters(counters, q, dc_list, sk_list)
check_counters(tallies, amount)

print "Multiple increments, 3-argument form of increment, explicit +2:"
N = 250L
X = 2L
(dc_list, sk_list) = create_counters(counters, q)
amount = increment_counters_num(dc_list, N, X)
assert amount == N*X
tallies = sum_counters(counters, q, dc_list, sk_list)
check_counters(tallies, amount)
