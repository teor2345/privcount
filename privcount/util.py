'''
Created on Dec 15, 2015

@author: rob
'''
import sys
import struct
import traceback
import logging
import socket
import datetime
import uuid
import json

from random import SystemRandom
from os import path
from math import sqrt
from time import time, strftime, gmtime
from copy import deepcopy
from base64 import b64encode, b64decode

from hashlib import sha256 as DigestHash
# encryption using SHA256 requires cryptography >= 1.4
from cryptography.hazmat.primitives.hashes import SHA256 as CryptoHash

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import UnsupportedAlgorithm

from statistics_noise import DEFAULT_SIGMA_TOLERANCE

def load_private_key_string(key_string):
    return serialization.load_pem_private_key(key_string, password=None, backend=default_backend())

def load_private_key_file(key_file_path):
    with open(key_file_path, 'rb') as key_file:
        private_key = load_private_key_string(key_file.read())
    return private_key

def load_public_key_string(key_string):
    return serialization.load_pem_public_key(key_string, backend=default_backend())

def load_public_key_file(key_file_path):
    with open(key_file_path, 'rb') as key_file:
        public_key = load_public_key_string(key_file.read())
    return public_key

def get_public_bytes(key_string, is_private_key=True):
    if is_private_key:
        private_key = load_private_key_string(key_string)
        public_key = private_key.public_key()
    else:
        public_key = load_public_key_string(key_string)
    return public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

def get_public_digest_string(key_string, is_private_key=True):
    return DigestHash(get_public_bytes(key_string, is_private_key)).hexdigest()

def get_public_digest(key_path, is_private_key=True):
    with open(key_path, 'rb') as key_file:
        digest = get_public_digest_string(key_file.read(), is_private_key)
    return digest

def get_serialized_public_key(key_path, is_private_key=True):
    with open(key_path, 'rb') as key_file:
        data = get_public_bytes(key_file.read(), is_private_key)
    return data

def encode_data(data_structure):
    """
    Encode an arbitrary python data structure in a format that is suitable
    for encryption (encrypt() expects bytes).
    The data structure can only contain basic python types, those supported
    by json.dumps (including longs, but no arbitrary objects).
    Performs the following transformations, in order:
    - dump the data structure using json: b64encode doesn't encode objects
    - b64encode the json: avoid any round-trip string encoding issues
    Returns a base64 blob that can safely be encrypted, decrypted, then passed
    to decode_data to produce the original data structure.
    """
    json_string = json.dumps(data_structure)
    return b64encode(json_string)

def decode_data(encoded_string):
    """
    Decode an arbitrary python data structure from the format provided by
    encode_data().
    The data structure can only contain basic python types, those supported
    by json.loads (including longs, but no arbitrary objects).
    Performs the inverse transformations to encode_data().
    Returns a python data structure.
    """
    json_string = b64decode(encoded_string)
    # json.loads is safe to use on untrusted data (from the network)
    return json.loads(json_string)

def generate_symmetric_key():
    """
    Generate and return a new secret key that can be used for symmetric
    encryption.
    """
    return Fernet.generate_key()

def encrypt_symmetric(secret_key, plaintext):
    """
    Encrypt plaintext with the Fernet symmetric key secret_key.
    This key must be kept secret, as it can be used to decrypt the message.
    The encrypted message contains its own creation time in plaintext:
    this time is visible to an attacker.
    See https://cryptography.io/en/latest/fernet/ for the details of this
    encryption scheme.
    Returns the encrypted ciphertext.
    """
    f = Fernet(secret_key)
    return f.encrypt(plaintext)

def decrypt_symmetric(secret_key, ciphertext, ttl=None):
    """
    Decrypt ciphertext with the Fernet symmetric key secret_key.
    See https://cryptography.io/en/latest/fernet/ for the details of this
    encryption scheme.
    Returns the decrypted plaintext
    Throws an exception if secret_key or ciphertext are invalid, or the
    message is older than ttl seconds.
    """
    f = Fernet(secret_key)
    # fernet requires the ciphertext to be bytes, it will raise an exception
    # if it is a string
    return f.decrypt(bytes(ciphertext), ttl)

def encrypt_pk(pub_key, plaintext):
    """
    Encrypt plaintext with the RSA public key pub_key, using CryptoHash()
    as the OAEP/MGF1 padding hash.
    plaintext is limited to the size of the RSA key, minus the padding, or a
    few hundred bytes.
    Returns a b64encoded ciphertext string.
    Encryption failures result in an exception being raised.
    """
    try:
        ciphertext = pub_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=CryptoHash()),
                algorithm=CryptoHash(),
                label=None
                )
            )
    except UnsupportedAlgorithm as e:
        # a failure to encrypt our own data is a fatal error
        # the most likely cause of this error is an old cryptography library
        # although some newer binary cryptography libraries are linked with
        # old OpenSSL versions, to fix, check 'openssl version' >= 1.0.2, then:
        # pip install -I --no-binary cryptography cryptography
        logging.error("Fatal error: encryption hash {} unsupported, try upgrading to cryptography >= 1.4 compiled with OpenSSL >= 1.0.2. Exception: {}".format(
                          CryptoHash, e))
        # re-raise the exception for the caller to handle
        raise e
    return b64encode(ciphertext)

def decrypt_pk(priv_key, ciphertext):
    """
    Decrypt a b64encoded ciphertext string with the RSA private key priv_key,
    using CryptoHash() as the OAEP/MGF1 padding hash.
    Returns the plaintext.
    Fails and calls os._exit on an UnsupportedAlgorithm exception.
    (Other decryption failures result in an exception being raised.)
    """
    try:
        plaintext = priv_key.decrypt(
            b64decode(ciphertext),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=CryptoHash()),
                algorithm=CryptoHash(),
                label=None
                )
            )
    except UnsupportedAlgorithm as e:
        # a failure to dencrypt someone else's data is not typically a fatal
        # error, but in this particular case, the most likely cause of this
        # error is an old cryptography library
        logging.error("Fatal error: encryption hash {} unsupported, try upgrading to cryptography >= 1.4. Exception: {}".format(
                          CryptoHash, e))
        # re-raise the exception for the caller to handle
        raise e
    return plaintext

def encrypt(pub_key, data_structure):
    """
    Encrypt an arbitrary python data structure, using the following scheme:
    - transform the data structure into a b64encoded json string
    - encrypt the string with a single-use symmetric encryption key
    - encrypt the single-use key using asymmetric encryption with pub_key
    The data structure can contain any number of nested dicts, lists, strings,
    doubles, ints, and longs.
    Returns a data structure containing ciphertexts, which should be treated
    as opaque.
    Encryption failures result in an exception being raised.
    """
    encoded_string = encode_data(data_structure)
    # TODO: secure delete
    secret_key = generate_symmetric_key()
    sym_encrypted_data = encrypt_symmetric(secret_key, encoded_string)
    pk_encrypted_secret_key = encrypt_pk(pub_key, secret_key)
    return { 'pk_encrypted_secret_key': pk_encrypted_secret_key,
             'sym_encrypted_data': sym_encrypted_data}

def decrypt(priv_key, ciphertext):
    """
    Decrypt ciphertext, yielding an arbitrary python data structure, using the
    same scheme as encrypt().
    ciphertext is a data structure produced by encrypt(), and should be
    treated as opaque.
    Returns a python data structure.
    Decryption failures result in an exception being raised.
    """
    pk_encrypted_secret_key = ciphertext['pk_encrypted_secret_key']
    sym_encrypted_data = ciphertext['sym_encrypted_data']
    # TODO: secure delete
    secret_key = decrypt_pk(priv_key, pk_encrypted_secret_key)
    encoded_string = decrypt_symmetric(secret_key, sym_encrypted_data)
    return decode_data(encoded_string)

def generate_keypair(key_out_path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    with open(key_out_path, 'wb') as outf:
        print >>outf, pem

def generate_cert(key_path, cert_out_path):
    private_key = load_private_key_file(key_path)
    public_key = private_key.public_key()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(x509.OID_COMMON_NAME, u'PrivCount User'),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(x509.OID_COMMON_NAME, u'PrivCount Authority'),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))
    builder = builder.not_valid_after(datetime.datetime(2020, 1, 1))
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(public_key)
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())

    with open(cert_out_path, 'wb') as outf:
        print >>outf, certificate.public_bytes(encoding=serialization.Encoding.PEM)

def get_random_free_port():
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # choose an evenly distributed port that doesn't leak RNG state
        port = sample_randint(10000, 60000)
        rc = s.connect_ex(('127.0.0.1', port))
        s.close()
        if rc != 0: # error connecting, port is available
            return port

## File Paths ##

def normalise_path(path_str):
    '''
    Return the abolute path corresponding to path_str, with user directories
    expanded, and the current working directory assumed for relative paths
    '''
    expanded_path = path.expanduser(path_str)
    return path.abspath(expanded_path)

## Logging ##

def log_error():
    _, _, tb = sys.exc_info()
    #traceback.print_tb(tb) # Fixed format
    tb_info = traceback.extract_tb(tb)
    filename, line, func, text = tb_info[-1]
    logging.warning("An error occurred in file '%s', at line %d, in func %s, in statement '%s'", filename, line, func, text)

## Logging: Time Formatting Functions ##
## a timestamp is an absolute point in time, in seconds since unix epoch
## a period is a relative time duration, in seconds
## a time argument is either a period or a timestamp
## a desc argument is a string description of the timestamp's meaning
## All period and timestamp arguments are normalised using normalise_time()
## before any calculations or formatting are performed

def normalise_time(time):
    '''
    Return the normalised value of time
    An abstraction used for consistent time rounding behaviour
    '''
    # we ignore microseconds
    return int(time)

def current_time():
    '''
    Return the normalised value of the current time
    '''
    return normalise_time(time())

def format_period(period):
    '''
    Format a time period as a human-readable string
    period is in seconds
    Returns a string of the form:
    1w 3d 12h 20m 32s
    starting with the first non-zero period (seconds are always included)
    '''
    period = normalise_time(period)
    period_str = ""
    # handle negative times by prepending a minus sign
    if period < 0:
        period_str += "-"
        period = -period
    # there's no built-in way of formatting a time period like this in python.
    # strftime is almost there, but would have issues with year-long periods.
    # divmod gives us the desired floor division result, and the remainder,
    # which will be floating point if normalise_time() returns floating point
    (week,   period) = divmod(period, 7*24*60*60)
    (day,    period) = divmod(period,   24*60*60)
    (hour,   period) = divmod(period,      60*60)
    (minute, period) = divmod(period,         60)
    # if normalise_time yields floating point values (microseconds), this will
    # produce a floating point result, which will be formatted as NN.NN
    # if it's an integer, it will format as NN. This is the desired behaviour.
    second           =        period % (      60)
    # now build the formatted string starting with the first non-zero period
    larger_period = 0
    if week > 0:
        period_str += "{}w ".format(week)
        larger_period = 1
    if day > 0 or larger_period:
        period_str += "{}d ".format(day)
        larger_period = 1
    if hour > 0 or larger_period:
        period_str += "{}h ".format(hour)
        larger_period = 1
    if minute > 0 or larger_period:
        period_str += "{}m ".format(minute)
    # seconds are always included, even if they are zero, or if there is no
    # larger period
    period_str += "{}s".format(second)
    return period_str

def format_datetime(timestamp):
    '''
    Format a timestamp as a human-readable UTC date and time string
    timestamp is in seconds since the epoch
    Returns a string of the form:
    2016-07-16 17:58:00
    '''
    timestamp = normalise_time(timestamp)
    return strftime("%Y-%m-%d %H:%M:%S", gmtime(timestamp))

def format_epoch(timestamp):
    '''
    Format a timestamp as a unix epoch numeric string
    timestamp is in seconds since the epoch
    Returns a string of the form:
    1468691880
    '''
    timestamp = normalise_time(timestamp)
    return str(timestamp)

def format_time(period, desc, timestamp):
    '''
    Format a period and timestamp as a human-readable string in UTC
    period is in seconds, and timestamp is in seconds since the epoch
    Returns a string of the form:
    1w 3d 12h 20m 32s (desc 2016-07-16 17:58:00 1468691880)
    '''
    return "{} ({} {} {})".format(format_period(period),
                                  desc,
                                  format_datetime(timestamp),
                                  format_epoch(timestamp))

def format_interval(period, desc, begin_timestamp, end_timestamp):
    '''
    Format a period and two interval timestamps as a human-readable string in UTC
    period is in seconds, and the timestamps are in seconds since the epoch
    Returns a string of the form:
    1w 3d 12h 20m 32s (desc 2016-07-16 17:58:00 to 2016-07-27 06:18:32,
    1468691880 to 1469600312)
    '''
    return "{} ({} {} to {}, {} to {})".format(format_period(period),
                                               desc,
                                               format_datetime(begin_timestamp),
                                               format_datetime(end_timestamp),
                                               format_epoch(begin_timestamp),
                                               format_epoch(end_timestamp))

def format_elapsed_time_wait(elapsed_period, desc):
    '''
    Format the time elapsed since a past event, and the past event time in UTC
    elapsed_period is in seconds
    The event time is the current time minus elapsed_period
    elapsed_period is typically time_since_checkin, and desc is typically 'at'
    Returns a string of the form:
    1w 3d 12h 20m 32s (desc 2016-07-27 06:18:32 1469600312)
    '''
    # Normalise before calculation to avoid truncation errors
    elapsed_period = normalise_time(elapsed_period)
    past_timestamp = current_time() - elapsed_period
    return format_time(elapsed_period, desc, past_timestamp)

def format_elapsed_time_since(past_timestamp, desc):
    '''
    Format the time elapsed since a past event, and that event's time in UTC
    past_timestamp is in seconds since the epoch
    The elapsed time is from past_timestamp to the current time
    past_timestamp is typically status['time'], and desc is typically 'since'
    Returns a string of the form:
    1w 3d 12h 20m 32s (desc 2016-07-16 17:58:00 1468691880)
    '''
    # Normalise before calculation to avoid truncation errors
    past_timestamp = normalise_time(past_timestamp)
    elapsed_period = current_time() - past_timestamp
    return format_time(elapsed_period, desc, past_timestamp)

def format_delay_time_wait(delay_period, desc):
    '''
    Format the time delay until a future event, and the expected event time
    in UTC
    delay_period is in seconds
    The event time is the current time plus delay_period
    delay_period is typically config['defer_time'], and desc is typically 'at'
    Returns a string of the form:
    1w 3d 12h 20m 32s (desc 2016-07-27 06:18:32 1469600312)
    '''
    # Normalise before calculation to avoid truncation errors
    delay_period = normalise_time(delay_period)
    future_timestamp = current_time() + delay_period
    return format_time(delay_period, desc, future_timestamp)

def format_delay_time_until(future_timestamp, desc):
    '''
    Format the time delay until a future event, and the expected event time
    in UTC
    The time delay is the difference between future_timestamp and the current
    time
    future_timestamp is in seconds since the epoch
    future_timestamp is typically config['defer_time'], and desc is typically 'at'
    returns a string of the form:
    1w 3d 12h 20m 32s (desc 2016-07-27 06:18:32 1469600312)
    '''
    # Normalise before calculation to avoid truncation errors
    future_timestamp = normalise_time(future_timestamp)
    delay_period = future_timestamp - current_time()
    return format_time(delay_period, desc, future_timestamp)

def format_interval_time_between(begin_timestamp, desc, end_timestamp):
    '''
    Format the interval elapsed between two events, and the times of those
    events in UTC
    The timestamps are in seconds since the epoch
    The interval is between begin_time and end_time
    desc is typically 'from'
    Returns a string of the form:
    1w 3d 12h 20m 32s (desc 2016-07-16 17:58:00 to 2016-07-27 06:18:32,
    1468691880 to 1469600312)
    '''
    # Normalise before calculation to avoid truncation errors
    begin_timestamp = normalise_time(begin_timestamp)
    end_timestamp = normalise_time(end_timestamp)
    period = end_timestamp - begin_timestamp
    return format_interval(period, desc, begin_timestamp, end_timestamp)

def format_last_event_time_since(last_event_timestamp):
    '''
    Format the time elapsed since the last Tor event, and that event's time
    in UTC
    last_event_timestamp is in seconds since the epoch, and can be None
    for no events
    The elapsed time is from last_event_timestamp to the current time
    Returns a string in one of the following forms:
    no Tor events received
    last Tor event was 1w 3d 12h 20m 32s (at 2016-07-16 17:58:00 1468691880)
    '''
    if last_event_timestamp is None:
        return "no Tor events received"
    else:
        return "last Tor event was {}".format(format_elapsed_time_since(
                                                  last_event_timestamp, 'at'))

## Calculation ##

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

def check_bins_config(bins):
    '''
    Check that bins are non-overlapping.
    Returns True if all bins are non-overlapping, and False if any overlap.
    Raises an exception if any counter does not have bins, or if any bin does
    not have a lower and upper bound
    '''
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
    # sort names alphabetically, so the logs are in a sensible order
    for key in sorted(sigmas.keys()):
        if sigmas[key]['sigma'] < 0.0:
            logging.warning("invalid sigma for counter {}: less than zero".format(key))
            return False
    return True

def _extra_counter_keys(first, second):
    '''
    Return the extra counter keys in first that are not in second.
    '''
    return set(first.keys()).difference(second.keys())

def extra_counters(first, second, first_name, second_name):
    '''
    Return the extra counter keys in first that are not in second.
    Warn about any missing counters.
    '''
    extra_keys = _extra_counter_keys(first, second)
    # Log missing keys
    # sort names alphabetically, so the logs are in a sensible order
    for key in sorted(extra_keys):
            logging.warning("skipping counter '{}' because it has a {}, but no {}".format(key, first, second))

    return extra_keys

def _common_counter_keys(first, second):
    '''
    Return the set of counter keys shared by first and second.
    '''
    return set(first.keys()).intersection(second.keys())

def common_counters(first, second, first_name, second_name):
    '''
    Return the counter keys shared by first and second.
    Warn about any missing counters.
    '''
    # ignore the extra counters return values, we just want the logging
    extra_counters(first, second, first_name, second_name)
    extra_counters(second, first, second_name, first_name)

    # return common keys
    return _common_counter_keys(first, second)

def _skip_missing(counters, expected_subkey, detailed_source=None):
    '''
    Check that each key in counters has a subkey with the name expected_subkey.
    If any key does not have a subkey named expected_subkey, skip it and log a
    warning.
    If detailed_source is not None, use it to describe the counters.
    Otherwise, use expected_subkey.
    Returns a copy of counters with invalid keys skipped.
    '''
    if detailed_source is None:
        detailed_source = expected_subkey
    valid_counters = {}
    # sort names alphabetically, so the logs are in a sensible order
    for key in sorted(counters.keys()):
        if expected_subkey in counters[key]:
            valid_counters[key] = counters[key]
        else:
            logging.warning("skipping counter '{}' because it is configured as a {} counter, but it does not have any {} value"
                            .format(key, detailed_source, expected_subkey))
    return valid_counters

def skip_missing_bins(bins, detailed_source=None):
    '''
    Check each key in bins has a bins list.
    If any key does not have a bins list, skip it and log a warning.
    Returns a copy of counters with invalid keys skipped.
    '''
    return _skip_missing(bins, 'bins', detailed_source)

def skip_missing_sigmas(sigmas, detailed_source=None):
    '''
    Check each key in sigmas has a sigma value.
    If any key does not have a sigma, skip it and log a warning.
    Returns a copy of counters with invalid keys skipped.
    '''
    return _skip_missing(sigmas, 'sigma')

def combine_counters(bins, sigmas):
    '''
    Combine the counters in bins and sigmas, excluding any counters that are
    missing from either bins or sigmas.
    Combine the keys and values from both bins and sigmas in the output
    counters, according to what the tally server is permitted to update.
    (Both bins and sigmas are configured at the tally server.)
    Return a dictionary containing the combined keys.
    '''
    # Remove invalid counters
    bins = skip_missing_bins(bins)
    sigmas = skip_missing_sigmas(sigmas)

    # we allow the tally server to update the set of counters
    # (we can't count keys for which we don't have both bins and sigmas)
    common_keys = common_counters(bins, sigmas, 'bins', 'sigmas')

    counters_combined = {}
    for key in common_keys:
        # skip_missing_* ensures these exist
        assert 'bins' in bins[key]
        assert 'sigma' in sigmas[key]
        # Use the values from the sigmas
        counters_combined[key] = deepcopy(sigmas[key])
        # Except for the bin values, which come from bins
        # we allow the tally server to update the bin widths
        counters_combined[key]['bins'] = deepcopy(bins[key]['bins'])
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

def float_representation_accuracy():
    '''
    When converting an exact number to a python float, the maximum possible
    proportional change in the value of the float.
    For the exact number n, converting n to a float could change the value by
    at most +/- n * float_representation_accuracy().
    Returns a floating point number representing the maximum relative increase
    or decrease in the value of the original exact number.
    '''
    # When converting an exact value to a python float, the maximum possible
    # proportional change is half the distance between one float value and the
    # next largest or smallest float value.
    # Conventiently, the distance between adjacent floats is at most the float
    # epsilon multiplied by the value of the float, as the distance between
    # adjacent floats scales as they get larger or smaller.
    # On most platforms, the float epsilon is 2 ** -53.
    return sys.float_info.epsilon/2.0

def float_string_accuracy():
    '''
    When converting a python float to a string and back, the maximum possible
    proportional change in the value of the float.
    For the float f, converting f to a string and back could change the value
    by at most +/- f * float_string_accuracy().
    Returns a floating point number representing the maximum relative increase
    or decrease in the value of the original float.
    '''
    # sys.float_info.dig is the number of significant figures that are
    # guaranteed to be preserved when converting a float to a string and
    # then back to a float (PrivCount does this when sending sigma between
    # the TS and the SKs/DCs).
    # This is based on python's float repr() rule, introduced in versions 2.7
    # and 3.1:
    # Python "displays a value based on the shortest decimal fraction that
    # rounds correctly back to the true binary value"
    # On most 32 and 64-bit platforms, sys.float_info.dig is 15 digits.
    # Therefore, the maximum change in value that can occur is the 15th digit
    # (of least significance) changing by +/- 1.
    # But we can't just multiply the original value by 10 ** -15, because
    # the (significand of the) float can have any value in [0.1, 0.999...].
    # Therefore, we need to multiply the tolerance by another 10x.
    # This gives us a tolerance of 10 ** -14 on most systems.
    return 10.0 ** (-sys.float_info.dig + 1)

def float_accuracy():
    '''
    The maximum proportional change in an exact value when converted to a
    float, then a string, then back to a float.
    For the exact number n, converting n to a float then string then float
    could change the value by at most +/- n * float_accuracy().
    Returns a floating point number representing the maximum relative increase
    or decrease in the value of the original exact number.
    '''
    # If the inaccuracies are both in the same direction, the total inaccuracy
    # is the sum of all inaccuracies
    return float_representation_accuracy() + float_string_accuracy()

class CollectionDelay(object):
    '''
    Ensures a configurable delay between rounds with different noise
    allocations.
    Usage:
    (all nodes do these checks, but the nodes listed must enforce them)
    TS: configures round
        uses get_next_round_start_time() for status updates
        checks round_start_permitted() before starting collection
    TODO: DC: checks round_start_permitted() before sending blinding shares
    TODO: SK: checks round_start_permitted() before accepting blinding shares
    (round runs)
    TODO: SK: set_stop_result() when round stops and blinding shares are sent
    TODO: DC: set_stop_result() when round stops and counters are sent
    TS: set_stop_result() when round ends successfully
    (repeat for next round, if TS has continue set in its config)
    '''

    def __init__(self):
        '''
        Initialise the noise allocations and times required to track collection
        delays.
        '''
        # The earliest noise allocation in a series of equivalent noise
        # allocations
        self.starting_noise_allocation = None
        # The end time of the successful round to use an equivalent allocation
        self.last_round_end_time = None

    DEFAULT_SIGMA_DECREASE_TOLERANCE = DEFAULT_SIGMA_TOLERANCE

    @staticmethod
    def sigma_change_needs_delay(
            previous_sigma, proposed_sigma,
            tolerance=DEFAULT_SIGMA_DECREASE_TOLERANCE,
            logging_label=None):
        '''
        Check if there should be a delay between rounds using the previous
        and proposed sigma values for the same counter.
        A counter can use two sigma values without a delay between them if:
        - The values are equal (within a small tolerance), or
        - The proposed value is greater than the previous value.
        Returns True if the sigma values need a delay, False if they do not.
        '''
        assert previous_sigma is not None
        assert proposed_sigma is not None
        assert tolerance is not None
        if proposed_sigma >= previous_sigma:
            # the sigma has increased: no delay requires
            return False
        elif proposed_sigma - previous_sigma <= tolerance:
            # the sigma has decreased, but not by enough to matter
            return False
        # the sigma has decreased too much - enforce a delay
        if logging_label is not None:
            logging.warning("Delaying round: proposed sigma %.2g is less than previous sigma %.2g, and not within tolerance %.2g, in counter %s",
                            proposed_sigma,
                            previous_sigma,
                            tolerance,
                            logging_label)
        return True

    @staticmethod
    def noise_change_needs_delay(
            previous_allocation, proposed_allocation,
            tolerance=DEFAULT_SIGMA_DECREASE_TOLERANCE):
        '''
        Check if there should be a delay between rounds using the previous
        and proposed noise allocations.
        Two allocations can be used without a delay between them if:
        - They have the same keys, and
        - The sigma values for those keys do not need a delay, using the
          acceptable sigma decrease tolerance.
        Returns True if the allocations need a delay, False if they do not.
        '''
        # There must be an allocation for a valid round
        assert proposed_allocation is not None
        assert tolerance is not None
        # No delay for the first round
        if previous_allocation is None:
            return False

        # Ignore and log missing sigmas
        previous_sigmas = skip_missing_sigmas(
            previous_allocation['counters'],
            'proposed sigma')
        proposed_sigmas = skip_missing_sigmas(
            proposed_allocation['counters'],
            'proposed sigma')

        # Check that we have the same set of counters
        common_sigmas = common_counters(previous_sigmas, proposed_sigmas,
                                        'previous sigma', 'proposed sigma')
        if len(common_sigmas) != len(previous_sigmas):
            # ignore the extra counters return values, we just want the logging
            extra_counters(previous_sigmas, proposed_sigmas,
                           'previous sigmas', 'proposed sigmas')
            return True
        if len(common_sigmas) != len(proposed_sigmas):
            # ignore the extra counters return values, we just want the logging
            extra_counters(proposed_sigmas, previous_sigmas,
                           'proposed sigmas', 'previous sigmas')
            return True

        # check the sigma values are the same
        for key in sorted(common_sigmas):
            if CollectionDelay.sigma_change_needs_delay(previous_sigmas[key],
                                                        proposed_sigmas[key],
                                                        tolerance,
                                                        key):
                return True
        return False

    def get_next_round_start_time(
            self, noise_allocation, delay_period, always_delay=False,
            tolerance=DEFAULT_SIGMA_DECREASE_TOLERANCE):
        '''
        Return the earliest time at which a round with noise allocation could
        start, where delay_period is the configurable delay.
        If always_delay is True, always delay the round by delay_period.
        (This is intended for use while testing.)
        tolerance is the acceptable sigma decrease.
        '''
        # there must be a configured delay_period (or a default must be used)
        assert delay_period is not None
        assert always_delay is not None
        # there must be a noise allocation for the next round
        assert noise_allocation is not None
        assert tolerance is not None

        noise_change_delay = self.noise_change_needs_delay(
                                      self.starting_noise_allocation,
                                      noise_allocation,
                                      tolerance)
        needs_delay = always_delay or noise_change_delay

        if noise_change_delay:
            # if there was a change, there must have been a previous allocation
            assert self.starting_noise_allocation

        if self.last_round_end_time is None:
            # a delay is meaningless, there have been no previous successful
            # rounds
            # we can start any time
            return 0
        elif needs_delay:
            # if there was a previous round, and we need to delay after it,
            # there must have been an end time for that round
            next_start_time = self.last_round_end_time + delay_period
            if next_start_time > time():
                if always_delay:
                    delay_reason = "we are configured to always delay"
                else:
                    delay_reason = "noise allocation changed"
                logging.debug("Delaying round for %s because %s",
                              format_delay_time_until(next_start_time,
                                                      'until'),
                              delay_reason)
            return next_start_time
        else:
            # we can start any time after the last round ended
            return self.last_round_end_time

    def round_start_permitted(
            self, noise_allocation, start_time, delay_period,
            always_delay=False,
            tolerance=DEFAULT_SIGMA_DECREASE_TOLERANCE):
        '''
        Check if we are permitted to start a round with noise allocation
        at start time, with the configured delay_period.
        If always_delay is True, always delay the round by delay_period.
        (This is intended for use while testing.)
        tolerance is the acceptable sigma decrease.
        Return True if starting the round is permitted, False if it is not.
        '''
        # there must be a start time
        assert start_time is not None
        # all the other assertions are at the top of the called function
        return start_time >= self.get_next_round_start_time(noise_allocation,
                                                            delay_period,
                                                            always_delay,
                                                            tolerance)

    def set_stop_result(
            self, round_successful, noise_allocation, start_time, end_time,
            delay_period, always_delay=False,
            tolerance=DEFAULT_SIGMA_DECREASE_TOLERANCE):
        '''
        Called when a round ends.
        If the new noise allocation is not equivalent to the stored noise,
        update the stored noise. Update the stored last round end time.
        No updates are performed for failed rounds.
        Log a warning if it appears that the round was started too early.
        (This can also occur if the config is changed mid-round.)
        If always_delay is True, assume the round was delayed, regardless of
        the noise allocation. (This is intended for use while testing.)
        tolerance is the acceptable sigma decrease.
        '''
        # make sure we haven't violated our own preconditions
        assert round_successful is not None
        assert noise_allocation is not None
        assert start_time < end_time
        assert delay_period > 0
        assert always_delay is not None
        assert tolerance is not None
        # did we forget to check if we needed to delay this round?
        # warn, because this can happen if the delay is reconfigured,
        # or if another node fails a round because it starts sooner than its
        # configured delay
        if not self.round_start_permitted(noise_allocation,
                                          start_time,
                                          delay_period,
                                          always_delay,
                                          tolerance):
            expected_start = self.get_next_round_start_time(noise_allocation,
                                                            delay_period,
                                                            always_delay,
                                                            tolerance)
            status = "successfully" if round_successful else "failed and"
            logging.warning("Round that just {} stopped was started {} before enforced delay elapsed. Round started {}, expected start {}."
                            .format(status,
                                    format_period(expected_start - start_time),
                                    format_elapsed_time_since(start_time,
                                                              'at'),
                                    format_elapsed_time_since(expected_start,
                                                              'at')))
        if round_successful:
            # The end time is always updated
            self.last_round_end_time = end_time
            if self.starting_noise_allocation is None or always_delay:
                # It's the first noise allocation this run, or it's a
                # noise allocation for which we've delayed collection
                self.starting_noise_allocation = noise_allocation
            elif not self.noise_change_needs_delay(
                              self.starting_noise_allocation,
                              noise_allocation,
                              tolerance):
                # The latest noise allocation could have been used immediately
                # after the starting noise allocation.
                # Keep the starting noise allocation, so that a TS can't
                # gradually decrease the noise each round
                pass
            else:
                # It's a noise allocation from a successful round, and it's
                # different enough from the starting allocation. Assume we
                # waited for the enforced delay before the round started.
                self.starting_noise_allocation = noise_allocation

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

"""
def prob_exit(consensus_path, my_fingerprint, fingerprint_pool=None):
    '''
    this func is currently unused
    if it becomes used later, we must add stem as a required python library
    '''
    from stem.descriptor import parse_file

    if fingerprint_pool == None:
        fingerprint_pool = [my_fingerprint]

    net_status = next(parse_file(consensus_path, document_handler='DOCUMENT', validate=False))
    DW = float(net_status.bandwidth_weights['Wed'])/10000
    EW = float(net_status.bandwidth_weights['Wee'])/10000

    # we must use longs here, because otherwise sum_of_sq_bw can overflow on
    # platforms where python has 32-bit ints
    # (on these platforms, this happens when router_entry.bandwidth > 65535)
    my_bandwidth, DBW, EBW, sum_of_sq_bw = 0L, 0L, 0L, 0L

    if my_fingerprint in net_status.routers:
        my_bandwidth = net_status.routers[my_fingerprint].bandwidth

    for (fingerprint, router_entry) in net_status.routers.items():
        if fingerprint not in fingerprint_pool or 'BadExit' in router_entry.flags:
            continue

        if 'Guard' in router_entry.flags and 'Exit' in router_entry.flags:
            DBW += router_entry.bandwidth
            sum_of_sq_bw += router_entry.bandwidth**2

        elif 'Exit' in router_entry.flags:
            EBW += router_entry.bandwidth
            sum_of_sq_bw += router_entry.bandwidth**2

    TEWBW = DBW*DW + EBW*EW
    prob = my_bandwidth/TEWBW
    sum_of_sq = sum_of_sq_bw/(TEWBW**2)
    return prob, sum_of_sq
"""
