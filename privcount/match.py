'''
  Created on Nov 17, 2017

  @author: teor

  See LICENSE for licensing information
  '''

import bisect

def exact_match_prepare_collection(exact_collection):
    '''
    Prepare a collection for efficient exact matching.
    Returns an object that can be passed to exact_match().
    This object must be treated as opaque and read-only.
    '''
    # Set matching uses a hash table, so it's more efficient
    return frozenset(exact_collection)

def exact_match(exact_obj, item):
    '''
    Performs an efficient O(1) exact match for item in exact_obj.
    exact_obj must have been created by exact_match_prepare_collection().
    '''
    # This code works efficiently on set, frozenset, and dict
    assert hasattr(exact_obj, 'issubset') or hasattr(exact_obj, 'has_key')
    # This is a single hash table lookup
    return item in exact_obj

def reverse_string(s):
    '''
    Reverse the string s
    '''
    return "".join(reversed(s))

def suffix_match_prepare_collection(suffix_collection, separator=""):
    '''
    Prepare a collection of strings for efficient suffix matching.
    If specified, the separator is also required before the suffix.
    For example, domain suffixes use "." as a separator between components.

    Returns an object that can be passed to suffix_match().
    This object must be treated as opaque and read-only.
    '''
    # A binary search is efficient, even if it does double the RAM
    # requirement. And it's unlikely we could get rid of all the references to
    # the strings in the collection after reversing them, anyway.

    # A binary search requires a prefix match, so we have to reverse all the
    # strings, then sort them.
    # A generalised suffix tree might be faster here

    # TODO: validate list suffix uniqueness
    return sorted([reverse_string(s) + separator for s in suffix_collection])

def suffix_match(suffix_obj, search_str):
    '''
    Performs an efficient O(log(N)) suffix match on search_str in suffix_obj.
    suffix_obj must have been created by suffix_match_prepare_collection().
    Returns True on a suffix match, but False on exact match and no match.
    Use exact_match() to find exact matches.
    '''
    # This code works on sorted lists, but checking is expensive
    # assert suffix_obj == sorted(suffix_obj)
    # We could also store the separator, and check it is the same

    # this is O(log(N)) because it's a binary search followed by a string prefix match
    # it works even if there are multiple matches, because shorter strings sort before longer strings
    reversed_search_str = reverse_string(search_str)
    # Longer strings sort after shorter strings, so our candidate is the
    # previous string. I don't know if this works when their are multiple
    # possible matches.
    candidate_idx = bisect.bisect_left(suffix_obj, reversed_search_str) - 1
    # We should always get an entry in the list
    assert candidate_idx < len(suffix_obj)
    # If there is no previous entry, the string is definitely not a match
    if candidate_idx < 0:
        return False
    candidate_reversed_suffix = suffix_obj[candidate_idx]
    #logging.warning("{} -> {} candidate {} -> {} in {}".format(search_str, reversed_search_str, candidate_idx, candidate_reversed_suffix, suffix_obj))
    return reversed_search_str.startswith(candidate_reversed_suffix)

