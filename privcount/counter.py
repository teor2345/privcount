'''
Created on Dec 6, 2016

@author: teor
'''

import logging

from random import SystemRandom
from copy import deepcopy
from math import sqrt

from privcount.statistics_noise import DEFAULT_DUMMY_COUNTER_NAME

## Counters ##

def counter_modulus():
    '''
    The hard-coded modulus value for a blinded counter
    Blinded counters are unsigned
    In PrivCount, this does not have to be prime, and there is no need for it
    to be configurable
    All PrivCount counters should use unlimited-length Python longs, so that
    counter_modulus can exceed 64 bits, the size of a native C long
    '''
    # PrivCount counters are limited by the modulus, so it needs to be large
    # Here's an over-estimate of PrivCount's capacity:
    # In 2016, Tor traffic was 75 Gbits, or ~2**34 bytes per second
    # (In 2015, Internet traffic was 230 Tbits, or ~2**43 bytes per second)
    # Tor traffic might grow by 2**10 while PrivCount is in use
    # A year has ~2**25 seconds
    # PrivCount counters overflow at modulus/2
    # 2**34 * 2**10 * 2**25 * 2 = 2**70
    # Using modulus > 2**64 also ensures PrivCount is unlimited-integer clean
    # and that it can handle longs that just happen to be integers
    # (1 in 2**6 blinding factors are less than 2**64)
    return 2L**70L
    # historical q values
    #return 2147483647L
    #return 999999999959L
    # modulus was limited to 2**64 when sample() only unpacked 8 bytes
    #return 2L**64L

def min_blinded_counter_value():
    '''
    The hard-coded minimum value for a blinded counter
    Blinded counters are unsigned
    Always zero
    '''
    return 0L

def max_blinded_counter_value():
    '''
    The hard-coded maximum value for a blinded counter
    Blinded counters are unsigned
    '''
    return counter_modulus() - 1L

def min_tally_counter_value():
    '''
    The hard-coded minimum value for a tallied counter
    Tallied counters are signed, to allow for negative noise
    '''
    return adjust_count_signed((counter_modulus() + 1L)//2L,
                               counter_modulus())

def max_tally_counter_value():
    '''
    The hard-coded maximum value for a tallied counter
    Tallied counters are signed, to allow for negative noise
    '''
    return adjust_count_signed((counter_modulus() + 1L)//2L - 1L,
                               counter_modulus())

def add_counter_limits_to_config(config):
    '''
    Add the hard-coded counter limits to a deep copy of the config dictionary
    Returns the modified deep copy of the config dictionary
    '''
    assert config is not None
    config = deepcopy(config)
    # call this modulus so it sorts near the other values
    config['modulus'] = counter_modulus()
    config['min_blinded_counter_value'] = min_blinded_counter_value()
    config['max_blinded_counter_value'] = max_blinded_counter_value()
    config['min_tally_counter_value'] = min_tally_counter_value()
    config['max_tally_counter_value'] = max_tally_counter_value()
    return config

MAX_DC_COUNT = 10**6

def check_dc_threshold(dc_threshold, description="threshold"):
    '''
    Check that dc_threshold is a valid dc threshold.
    DC thresholds must be positive non-zero, and less than or equal to
    MAX_DC_COUNT.
    Returns True if the dc threshold is valid.
    Logs a specific warning using description and returns False if it is not.
    '''
    if dc_threshold <= 0:
        logging.warning("Data collector {} must be at least 1, was {}"
                        .format(description, dc_threshold))
        return False
    if dc_threshold > MAX_DC_COUNT:
        logging.warning("Data collector {} can be at most {}, was {}"
                        .format(description, MAX_DC_COUNT, dc_threshold))
        return False
    return True

def check_noise_weight_value(noise_weight_value, description="value"):
    '''
    Check that noise_weight_value is a valid noise weight.
    Noise weights must be positive and less than or equal to the maximum
    tallied counter value.
    Returns True if the noise weight value is valid.
    Logs a specific warning using description, and returns False if it is not.
    '''
    if noise_weight_value < 0.0:
        logging.warning("Noise weight {} must be positive, was {}".format(
                description, noise_weight_value))
        return False
    if noise_weight_value > max_tally_counter_value():
        logging.warning("Noise weight {} can be at most {}, was {}".format(
                description, max_tally_counter_value(), noise_weight_value))
        return False
    return True

def check_noise_weight_sum(noise_weight_sum, description="sum"):
    '''
    Check that noise_weight_sum is a valid summed noise weight.
    Noise weight sums must pass check_noise_weight_value().
    Returns True if the noise weight sum is valid.
    Logs a specific warning using description and returns False if it is not.
    '''
    if not check_noise_weight_value(noise_weight_sum, description):
        return False
    return True

def check_noise_weight_config(noise_weight_config, dc_threshold):
    '''
    Check that noise_weight_config is a valid noise weight configuration.
    Each noise weight must also pass check_noise_weight_value().
    Returns True if the noise weight config is valid.
    Logs a specific warning and returns False if it is not.
    '''
    if not check_dc_threshold(dc_threshold):
        return False
    # there must be noise weights for a threshold of DCs
    if len(noise_weight_config) < dc_threshold:
        logging.warning("There must be at least as many noise weights as the threshold of data collectors. Noise weights: {}, Threshold: {}."
                        .format(len(noise_weight_config), dc_threshold))
        return False
    # each noise weight must be individually valid
    for dc in noise_weight_config:
        if not check_noise_weight_value(noise_weight_config[dc]):
            return False
    # the sum must be valid
    if not check_noise_weight_sum(sum(noise_weight_config.values())):
        return False
    return True

def check_event_set_case(event_set):
    '''
    Check that event_set is a set, and each event in it has the correct case
    Returns True if all checks pass, and False if any check fails
    '''
    if not isinstance(event_set, (set, frozenset)):
        return False
    for event in event_set:
        if event != event.upper():
            return False
    return True

def check_event_set_valid(event_set):
    '''
    Check that event_set passes check_event_set_case, and also that each event
    is in the set of valid events
    Returns True if all checks pass, and False if any check fails
    '''
    if not check_event_set_case(event_set):
        return False
    for event in event_set:
        if event not in get_valid_events():
            return False
    return True

# internal
DNS_EVENT = 'PRIVCOUNT_DNS_RESOLVED'
BYTES_EVENT = 'PRIVCOUNT_STREAM_BYTES_TRANSFERRED'
STREAM_EVENT = 'PRIVCOUNT_STREAM_ENDED'
CIRCUIT_EVENT = 'PRIVCOUNT_CIRCUIT_ENDED'
CONNECTION_EVENT = 'PRIVCOUNT_CONNECTION_ENDED'

def get_valid_events():
    '''
    Return a set containing the name of each privcount event, in uppercase
    '''
    event_set = { DNS_EVENT,
                  BYTES_EVENT,
                  STREAM_EVENT,
                  CIRCUIT_EVENT,
                  CONNECTION_EVENT }
    assert check_event_set_case(event_set)
    return event_set

PRIVCOUNT_COUNTER_EVENTS = {
# these counters depend on stream end
# they are updated in _handle_stream_event
'StreamsAll' : { STREAM_EVENT },
'StreamBytesAll' : { STREAM_EVENT },
'StreamBytesOutAll' : { STREAM_EVENT },
'StreamBytesInAll' : { STREAM_EVENT },
'StreamBytesRatioAll' : { STREAM_EVENT },
'StreamsWeb' : { STREAM_EVENT },
'StreamBytesWeb' : { STREAM_EVENT },
'StreamBytesOutWeb' : { STREAM_EVENT },
'StreamBytesInWeb' : { STREAM_EVENT },
'StreamBytesRatioWeb' : { STREAM_EVENT },
'StreamLifeTimeWeb' : { STREAM_EVENT },
'StreamsInteractive' : { STREAM_EVENT },
'StreamBytesInteractive' : { STREAM_EVENT },
'StreamBytesOutInteractive' : { STREAM_EVENT },
'StreamBytesInInteractive' : { STREAM_EVENT },
'StreamBytesRatioInteractive' : { STREAM_EVENT },
'StreamLifeTimeInteractive' : { STREAM_EVENT },
'StreamsP2P' : { STREAM_EVENT },
'StreamBytesP2P' : { STREAM_EVENT },
'StreamBytesOutP2P' : { STREAM_EVENT },
'StreamBytesInP2P' : { STREAM_EVENT },
'StreamBytesRatioP2P' : { STREAM_EVENT },
'StreamLifeTimeP2P' : { STREAM_EVENT },
'StreamsOther' : { STREAM_EVENT },
'StreamBytesOther' : { STREAM_EVENT },
'StreamBytesOutOther' : { STREAM_EVENT },
'StreamBytesInOther' : { STREAM_EVENT },
'StreamBytesRatioOther' : { STREAM_EVENT },
'StreamLifeTimeOther' : { STREAM_EVENT },
# these counters depend on circuit end
# they are updated in _do_rotate,
# and use data updated in _handle_circuit_event
'ClientIPsUnique' : { CIRCUIT_EVENT },
'ClientIPsActive' : { CIRCUIT_EVENT },
'ClientIPsInactive' : { CIRCUIT_EVENT },
'ClientIPCircuitsActive' : { CIRCUIT_EVENT },
'ClientIPCircuitsInactive' : { CIRCUIT_EVENT },
# these counters depend on circuit end
# they are updated in _handle_circuit_event
'CircuitsAllEntry' : { CIRCUIT_EVENT },
'CircuitsActiveEntry' : { CIRCUIT_EVENT },
'CircuitCellsIn' : { CIRCUIT_EVENT },
'CircuitCellsOut' : { CIRCUIT_EVENT },
'CircuitCellsRatio' : { CIRCUIT_EVENT },
'CircuitsInactiveEntry' : { CIRCUIT_EVENT },
'CircuitsAll' : { CIRCUIT_EVENT },
'CircuitLifeTimeAll' : { CIRCUIT_EVENT },
# these counters depend on stream end and circuit end
# they are updated in _handle_circuit_event,
# and use data updated in _handle_stream_event
'CircuitsActive' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitsInactive' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitLifeTimeActive' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitLifeTimeInactive' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitStreamsAll' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitInterStreamCreationTime' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitsWeb' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitStreamsWeb' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitInterStreamCreationTimeWeb' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitsInteractive' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitStreamsInteractive' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitInterStreamCreationTimeInteractive' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitsP2P' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitStreamsP2P' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitInterStreamCreationTimeP2P' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitsOther' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitStreamsOther' : { STREAM_EVENT, CIRCUIT_EVENT },
'CircuitInterStreamCreationTimeOther' : { STREAM_EVENT, CIRCUIT_EVENT },
# these counters depend on connection end
'ConnectionsAll' : { CONNECTION_EVENT },
'ConnectionLifeTime' : { CONNECTION_EVENT },
# the sanity check counter doesn't depend on any events
DEFAULT_DUMMY_COUNTER_NAME : set(),
}

def get_valid_counters():
    '''
    Return a set containing the name of each privcount counter, in titlecase.
    (Or whatever the canonical case of the counter name is.)
    '''
    counter_set = set(PRIVCOUNT_COUNTER_EVENTS.keys())
    # we can't check case consistency, so just return the set
    return counter_set

def get_events_for_counter(counter):
    '''
    Return the set of events required by counter
    '''
    # when you add an event, but forget to update the table above,
    # you will get an error here
    event_set = PRIVCOUNT_COUNTER_EVENTS[counter]
    assert check_event_set_valid(event_set)
    return event_set

def get_events_for_counters(counter_list):
    '''
    Return the set of events required by at least one of the counters in
    counter_list.
    '''
    event_set = set()
    if counter_list is not None:
        for counter in counter_list:
            counter_events = get_events_for_counter(counter)
            event_set = event_set.union(counter_events)
    assert check_event_set_valid(event_set)
    return event_set

def get_events_for_known_counters():
    '''
    Return the set of events required by at least one of the counters we know
    about.
    '''
    return get_events_for_counters(PRIVCOUNT_COUNTER_EVENTS.keys())

def check_counter_names(counters):
    '''
    Check that each counter's name is in the set of valid counter names.
    Returns False if any counter name is unknown, True if all are known.
    '''
    # sort names alphabetically, so the logs are in a sensible order
    for counter_name in sorted(counters.keys()):
        if counter_name not in get_valid_counters():
            logging.warning("counter name {} is unknown"
                            .format(counter_name))
            return False
    return True

def check_bins_config(bins):
    '''
    Check that bins are non-overlapping.
    Returns True if all bins are non-overlapping, and False if any overlap.
    Raises an exception if any counter does not have bins, or if any bin does
    not have a lower and upper bound
    '''
    if not check_counter_names(bins):
        return False
    # sort names alphabetically, so the logs are in a sensible order
    for key in sorted(bins.keys()):
        # this sorts the bins by the first element in ascending order
        # (if the first elements are equal, the bins are sorted by the second
        # element)
        sorted_bins = sorted(bins[key]['bins'])
        prev_bin = None
        for bin in sorted_bins:
            # bins are an array [l, u, c], where c counts values such that:
            # l <= value < u
            # c is optional, and is ignored by this code
            l = bin[0]
            u = bin[1]
            # check for inverted bounds
            if l >= u:
                logging.warning("bin {} in counter {} will never count any values, because its lower bound is greater than or equal to its upper bound"
                                .format(bin, key))
                return False
            # make sure we have a bin to compare to
            if prev_bin is not None:
                prev_l = prev_bin[0]
                prev_u = prev_bin[1]
                # two sorted bins overlap if:
                # - their lower bounds are equal, or
                # - the upper bound of a bin is greater than the lower bound
                #   of the next bin
                if prev_l == l:
                    logging.warning("bin {} in counter {} overlaps bin {}: their lower bounds are equal"
                                    .format(prev_bin, key, bin))
                    return False
                elif prev_u > l:
                    logging.warning("bin {} in counter {} overlaps bin {}: the first bin's upper bound is greater than the second bin's lower bound"
                                    .format(prev_bin, key, bin))
                    return False
            prev_bin = bin
    return True

def check_sigmas_config(sigmas):
    '''
    Check that each sigma value in sigmas is valid.
    Returns True if all sigma values are valid, and False if any are invalid.
    Raises an exception if any sigma value is missing.
    '''
    if not check_counter_names(sigmas):
        return False
    # sort names alphabetically, so the logs are in a sensible order
    for key in sorted(sigmas.keys()):
        if sigmas[key]['sigma'] < 0.0:
            logging.warning("invalid sigma for counter {}: less than zero".format(key))
            return False
    return True

def combine_counters(bins, sigmas):
    '''
    Combine the counters in bins and sigmas, excluding any counters that are
    missing from either bins or sigmas.
    Combine the keys and values from both bins and sigmas in the output
    counters, according to what the tally server is permitted to update.
    (Both bins and sigmas are configured at the tally server.)
    Return a dictionary containing the combined keys.
    '''
    # we allow the tally server to update the set of counters
    # (we can't count keys for which we don't have both bins and sigmas)
    common_keys = set(bins.keys()).intersection(sigmas.keys())

    # warn about missing bins and sigmas
    # sort names alphabetically, so the logs are in a sensible order
    for key in sorted(set(bins.keys()).difference(common_keys)):
            logging.warning("skipping counter '{}' because it has a bin, but no sigma".format(key))
    for key in sorted(set(sigmas.keys()).difference(common_keys)):
            logging.warning("skipping counter '{}' because it has a sigma, but no bin".format(key))

    counters_combined = {}
    # sort names alphabetically, so the logs are in a sensible order
    for key in sorted(common_keys):
        if 'bins' in bins[key] and 'sigma' in sigmas[key]:
            # Use the values from the sigmas
            counters_combined[key] = deepcopy(sigmas[key])
            # Except for the bin values, which come from bins
            # we allow the tally server to update the bin widths
            counters_combined[key]['bins'] = deepcopy(bins[key]['bins'])
        elif 'bins' not in bins[key]:
            logging.warning("skipping counter '{}' because we have a bin counter, but it does not have any bins configured".format(key))
        elif 'sigma' not in sigmas[key]:
            logging.warning("skipping counter '{}' because we have a sigma counter, but it does not have any sigmas configured".format(key))
        else:
            # if we've correctly handled all the cases, then...
            logging.error("this line should be unreachable")
    return counters_combined

def check_combined_counters(bins, sigmas):
    '''
    Sanity check bins against sigmas.
    Returns False if:
      - the set of counters in bins and sigmas is not the same, or
      - any counter is missing bins, or
      - any counter is missing a sigma, or
      - any counter is duplicated.
    '''
    combined_counters = combine_counters(bins, sigmas)
    return (len(combined_counters) == len(bins) and
            len(combined_counters) == len(sigmas))

def check_counters_config(bins, sigmas):
    '''
    Sanity check bins and sigmas individually.
    Check that bins and sigmas have the same set of counters.
    '''
    return (check_bins_config(bins) and check_sigmas_config(sigmas) and
            check_combined_counters(bins, sigmas))

def noise(sigma, sum_of_sq, p_exit):
    '''
    Sample noise from a gussian distribution
    the distribution is over +/- sigma, scaled by the noise weight, which is
    calculated from the exit probability p_exit, and the overall sum_of_sq
    bandwidth
    returns a floating-point value between +sigma and -sigma, scaled by
    noise_weight
    '''
    sigma_i = p_exit * sigma / sqrt(sum_of_sq)
    # the noise needs to be cryptographically secure, because knowing the RNG
    # state could allow an adversary to remove the noise
    random_sample = SystemRandom().gauss(0, sigma_i)
    return random_sample

def sample(modulus):
    '''
    Sample a uniformly distributed value from the SystemRandom CSPRNG
    (uses rejection sampling to avoid bias)
    returns a long uniformly distributed in [0, modulus)
    '''
    # sanitise input
    modulus = long(modulus)
    assert modulus > 0
    # to get values up to modulus-1, we need this many bits
    sample_bit_count = (modulus-1).bit_length()
    # handle the case where modulus is 1
    if sample_bit_count == 0:
        sample_bit_count = 1
    # check the bit count is sane
    assert modulus <= 2L**sample_bit_count
    assert modulus >= 2L**(sample_bit_count-1)
    ## Unbiased sampling through rejection sampling
    while True:
        # sample that many bits
        v = SystemRandom().getrandbits(sample_bit_count)
        assert v >= 0
        assert v < 2L**sample_bit_count
        # the maximum rejection rate is 1 in 2, when modulus is 2**N + 1
        if 0L <= v < modulus:
            break
    return v

def sample_randint(a, b):
    """
    Like random.randint(), returns a random long N such that a <= N <= b.
    """
    return a + sample(b - a + 1)

def derive_blinding_factor(secret, modulus, positive=True):
    '''
    Calculate a blinding factor less than modulus, based on secret
    If secret is None, sample a blinding factor and return it
    When positive is True, returns the blinding factor, and when positive is
    False, returns the unblinding factor (the inverse value mod modulus)
    Typically called as:
      blinding   = derive_blinding_factor(None,     counter_modulus(), True)
      unblinding = derive_blinding_factor(blinding, counter_modulus(), False)
    '''
    # sanitise input
    modulus = long(modulus)
    if secret is None:
        v = sample(modulus)
    else:
        # sanitise input
        v = long(secret)
    assert v < modulus
    s0 = v if positive else modulus - v
    return s0

def adjust_count_signed(count, modulus):
    '''
    Adjust the unsigned 0 <= count < modulus, returning a signed integer
    For odd  modulus, returns { -modulus//2, ... , 0, ... , modulus//2 }
    For even modulus, returns { -modulus//2, ... , 0, ... , modulus//2 - 1 }
    The smallest positive values >= modulus//2 [- 1] become the largest
    negative values
    This is the inverse operation of x % modulus, when x is in the appropriate
    range (x % modulus always returns a positive integer when modulus is
    positive)
    '''
    # sanitise input
    count = long(count)
    modulus = long(modulus)
    # sanity check input
    assert count < modulus
    # When implementing this adjustment,
    # { 0, ... , (modulus + 1)//2 - 1}  is interpreted as that value,
    # { (modulus + 1)//2, ... , modulus - 1 } is interpreted as
    # that value minus modulus, or
    # { (modulus + 1)//2 - modulus, ... , modulus - 1 - modulus }
    #
    # For odd modulus, (modulus + 1)//2 rounds up to modulus//2 + 1, so the
    # positive case simplifies to:
    # { 0, ... , modulus//2 + 1 - 1 }
    # { 0, ... , modulus//2 }
    # and because modulus == modulus//2 + modulus//2 + 1 for odd modulus, the
    # negative case simplifies to:
    # { modulus//2 + 1 - modulus//2 - modulus//2 - 1, ... ,
    #   modulus - 1 - modulus}
    # { -modulus//2, ... , -1 }
    # Odd modulus has the same number of values above and below 0:
    # { -modulus//2, ... , 0, ... , modulus//2 }
    #
    # For even modulus, (modulus+1)//2 rounds down to modulus//2, so the
    # positive case simplifies to:
    # { 0, ... , modulus//2 - 1 }
    # and because modulus == modulus//2 + modulus//2 for even modulus, the
    # negative case simplifies to:
    # { modulus//2 - modulus//2 - modulus//2, ... , modulus - 1 - modulus}
    # { -modulus//2, ... , -1 }
    # Even modulus has the 1 more value below 0 than above it:
    # { -modulus//2, ... , 0, ... , modulus//2 - 1 }
    # This is equivalent to signed two's complement, if modulus is an integral
    # power of two
    if count >= ((modulus + 1L) // 2L):
        signed_count = count - modulus
    else:
        signed_count = count
    # sanity check output
    assert signed_count >= -modulus//2L
    if modulus % 2L == 1L:
        # odd case
        assert signed_count <= modulus//2L
    else:
        # even case
        assert signed_count <= modulus//2L - 1L
    return signed_count

class SecureCounters(object):
    '''
    securely count any number of labels
    counters should be in the form like this:
    {
      'CircuitCellsInOutRatio': {
        'bins':
        [
          [0.0, 0.1],
          [0.1, 0.25],
          [0.25, 0.5],
          [0.5, 0.75],
          [0.75, 0.9],
          [0.9, 1.0],
          [1.0, float('inf')],
        ],
        'sigma': 2090007.68996
      },
      'CircuitCellsIn': {
        'bins':
        [
          [0.0, 512.0],
          [512.0, 1024.0],
          [1024.0, 2048.0],
          [2048.0, 4096.0],
          [4096.0, float('inf')],
        ],
        'sigma': 2090007.68996
      }
    }
    All of data collectors, share keepers, and tally server use this to store
    counters.
    It is used approximately like this:

    data collector:
    init(), generate_blinding_shares(), detach_blinding_shares(),
    generate_noise(), increment()[repeated],
    detach_counts()
    the blinding shares are sent to each share keeper
    the counts are sent to the tally server at the end

    share keeper:
    init(), import_blinding_share()[repeated], detach_counts()
    import..() uses the shares from each data collector
    the counts are sent to the tally server at the end

    tally server:
    init(), tally_counters(), detach_counts()
    tally..() uses the counts received from all of the data collectors and
    share keepers
    this produces the final, unblinded, noisy counts of the privcount process

    see privcount/test/test_counters.py for some test cases
    '''

    def __init__(self, counters, modulus):
        '''
        deepcopy counters and initialise each counter to 0L
        cast modulus to long and store it
        '''
        self.counters = deepcopy(counters)
        self.modulus = long(modulus)
        self.shares = None

        # initialize all counters to 0L
        # counters use unlimited length integers to avoid overflow
        for key in self.counters:
            assert('bins' in self.counters[key])
            for item in self.counters[key]['bins']:
                assert len(item) == 2
                # bin is now, e.g.: [0.0, 512.0, 0L] for bin_left, bin_right,
                # count
                item.append(0L)

        # take a copy of the zeroed counters to use when generating blinding
        # factors
        self.zero_counters = deepcopy(self.counters)

    def _check_counter(self, counter):
        '''
        Check that the keys and bins in counter match self.counters
        Also check that each bin has a count.
        If these checks pass, return True. Otherwise, return False.
        '''
        for key in self.counters:
            if key not in counter:
                return False
            # disregard sigma, it's only required at the data collectors
            if 'bins' not in counter[key]:
                return False
            num_bins = len(self.counters[key]['bins'])
            if num_bins != len(counter[key]['bins']):
                return False
            for i in xrange(num_bins):
                tally_item = counter[key]['bins'][i]
                if len(tally_item) != 3:
                    return False
        return True

    def _derive_all_counters(self, blinding_factors, positive):
        '''
        If blinding_factors is None, generate and apply a counters structure
        containing uniformly random blinding factors.
        Otherwise, apply the passed blinding factors.
        If positive is True, apply blinding factors. Otherwise, apply
        unblinding factors.
        Returns the applied (un)blinding factors, or None on error.
        '''
        # if there are no blinding_factors, initialise them to zero
        generate_factors = False
        if blinding_factors is None:
            blinding_factors = deepcopy(self.zero_counters)
            generate_factors = True

        # validate that the counter data structures match
        if not self._check_counter(blinding_factors):
            return None

        # determine the blinding factors
        for key in blinding_factors:
            for item in blinding_factors[key]['bins']:
                if generate_factors:
                    original_factor = None
                else:
                    original_factor = long(item[2])
                blinding_factor = derive_blinding_factor(original_factor,
                                                         self.modulus,
                                                         positive=positive)
                item[2] = blinding_factor

        # add the blinding factors to the counters
        self._tally_counter(blinding_factors)

        # return the applied blinding factors
        return blinding_factors

    def _blind(self):
        '''
        Generate and apply a counters structure containing uniformly random
        blinding factors.
        Returns the generated blinding factors.
        '''
        generated_counters = self._derive_all_counters(None, True)
        # since we generate blinding factors based on our own inputs, a
        # failure here is a programming bug
        assert generated_counters is not None
        return generated_counters

    def _unblind(self, blinding_factors):
        '''
        Generate unblinding factors from blinding_factors, and apply them to
        self.counters.
        Returns the applied unblinding factors.
        '''
        # since we generate unblinding factors based on network input, a
        # failure here should be logged, and the counters ignored
        return self._derive_all_counters(blinding_factors, False)

    def generate_blinding_shares(self, uids):
        '''
        Generate and apply blinding factors for each counter and share keeper
        uid.
        '''
        self.shares = {}
        for uid in uids:
            # add blinding factors to all of the counters
            blinding_factors = self._blind()
            # the caller can add additional annotations to this dictionary
            self.shares[uid] = {'secret': blinding_factors, 'sk_uid': uid}

    def generate_noise(self, noise_weight):
        '''
        Generate and apply noise for each counter.
        '''
        # generate noise for each counter independently
        noise_values = deepcopy(self.zero_counters)
        for key in noise_values:
            for item in noise_values[key]['bins']:
                sigma = noise_values[key]['sigma']
                sampled_noise = noise(sigma, 1, noise_weight)
                # exact halfway values are rounded towards even integers
                # values over 2**53 are not integer-accurate
                # but we don't care, because it's just noise
                item[2] = long(round(sampled_noise))

        # add the noise to each counter
        self._tally_counter(noise_values)

    def detach_blinding_shares(self):
        '''
        Deletes this class' reference to self.shares.
        Does not securely delete, as python does not have secure delete.
        Detaches and returns the value of self.shares.
        Typically, the caller then uses encrypt() on the returned shares.
        '''
        shares = self.shares
        # TODO: secure delete
        # del only deletes the reference binding
        # deallocation is implementation-dependent
        del self.shares
        self.shares = None
        return shares

    def import_blinding_share(self, share):
        '''
        Generate and apply reverse blinding factors to all of the counters.
        If encrypted, these blinding factors must be decrypted and decoded by
        the caller using decrypt(), before calling this function.
        Returns True if unblinding was successful, and False otherwise.
        '''
        unblinding_factors = self._unblind(share['secret'])
        if unblinding_factors is None:
            return False
        return True

    def increment(self, counter_key, bin_value, num_increments=1L):
        if self.counters is not None and counter_key in self.counters:
            for item in self.counters[counter_key]['bins']:
                if bin_value >= item[0] and bin_value < item[1]:
                    item[2] = ((long(item[2]) + long(num_increments))
                               % self.modulus)

    def _tally_counter(self, counter):
        if self.counters == None:
            return False

        # validate that the counter data structures match
        if not self._check_counter(counter):
            return False

        # ok, the counters match
        for key in self.counters:
            num_bins = len(self.counters[key]['bins'])
            for i in xrange(num_bins):
                tally_bin = self.counters[key]['bins'][i]
                tally_bin[2] = ((long(tally_bin[2]) +
                                 long(counter[key]['bins'][i][2]))
                                % self.modulus)

        # success
        return True

    def tally_counters(self, counters):
        # first add up all of the counters together
        for counter in counters:
            if not self._tally_counter(counter):
                return False
        # now adjust so our tally can register negative counts
        # (negative counts are possible if noise is negative)
        for key in self.counters:
            for tally_bin in self.counters[key]['bins']:
                tally_bin[2] = adjust_count_signed(tally_bin[2], self.modulus)
        return True

    def detach_counts(self):
        counts = self.counters
        self.counters = None
        return counts
