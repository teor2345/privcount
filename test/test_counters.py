#!/usr/bin/python

from privcount.util import SecureCounters

# This maximum must be kept the same as privcount's configured q value
q = 999999999959

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

# do N increments at the dc, some bins get more increments than others
def increment_counters(dc_list, N):
    sc_dc = dc_list[0]
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
    assert tallies['Bytes']['bins'][0][2] == 2.0*N
    assert tallies['Bytes']['bins'][1][2] == 1.0*N
    assert tallies['Bytes']['bins'][2][2] == 2.0*N
    assert tallies['Bytes']['bins'][3][2] == 0.0*N
    assert tallies['Bytes']['bins'][4][2] == 2.0*N
    assert tallies['SanityCheck']['bins'][0][2] == 0.0
    print "all counts are correct!"

# Check that secure counters increment correctly for small values of N
N = 500.0
(dc_list, sk_list) = create_counters(counters, q)
increment_counters(dc_list, N)
tallies = sum_counters(counters, q, dc_list, sk_list)
check_counters(tallies, N)
