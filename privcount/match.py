'''
  Created on Nov 17, 2017

  @author: teor

  See LICENSE for licensing information
  '''

import bisect
import logging

def exact_match_prepare_collection(exact_collection):
    '''
    Prepare a string collection for efficient exact matching.
    Returns an object that can be passed to exact_match().
    This object must be treated as opaque and read-only.
    '''
    # Set matching uses a hash table, so it's more efficient
    exact_collection = [s.lower() for s in exact_collection]
    exact_set = frozenset(exact_collection)
    # Log a message if there were any duplicates
    # Finding each duplicate takes a lot longer
    if len(exact_collection) != len(exact_set):
      logging.warning("Removing {} duplicates from the collection"
                      .format(len(exact_collection) - len(exact_set)))
    return exact_set


def exact_match(exact_obj, search_str):
    '''
    Performs an efficient O(1) case-insensitive exact match for search_str in
    exact_obj.
    exact_obj must have been created by exact_match_prepare_collection().
    '''
    # This code works efficiently on set, frozenset, and dict
    assert hasattr(exact_obj, 'issubset') or hasattr(exact_obj, 'has_key')
    # This is a single hash table lookup
    return search_str.lower() in exact_obj

def reverse_string(s):
    '''
    Reverse the string s
    '''
    return "".join(reversed(s))

def suffix_match_collate_collection(suffix_collection, separator=""):
    '''
    Collate a collection of strings for efficient suffix matching.
    If specified, the separator is also required before the suffix.
    For example, domain suffixes use "." as a separator between components.

    If suffix_collection contains any strings that are exact duplicates,
    log an warning-level message, and remove them.

    Returns an object that can be passed to suffix_match().
    This object must be treated as opaque and read-only.
    But in most cases, you will want to use suffix_match_prepare_collection()
    to uniquify the suffixes in the collection as well.
    '''
    # A binary search requires a prefix match, so we have to reverse all the
    # strings, then sort them. Stripping any separators makes sure that the
    # match works.
    # A generalised suffix tree might be faster here.

    suffix_collection = [s.lower() for s in suffix_collection]
    sorted_suffix_list = sorted([reverse_string(s.strip(separator)) + separator
                                 for s in suffix_collection])

    # This takes about 2 seconds on the Alexa Top 1 million, and doesn't find
    # any duplicates. So we avoid doing it
    #suffix_set = set(sorted_suffix_list)
    # Log a message if there were any duplicates
    # Finding each duplicate takes a lot longer
    #if len(suffix_collection) != len(suffix_set):
    #    logging.warning("Removing {} duplicate suffixes from the collection"
    #                    .format(len(suffix_collection) - len(suffix_set)))

    return sorted_suffix_list

def suffix_match_uniquify_collection(suffix_obj, separator=""):
    '''
    Check if suffix_obj contains any strings that are a suffix of any other
    strings, log an warning-level message, and remove them.

    If specified, the separator is also required before the suffix.
    For example, domain suffixes use "." as a separator between components.
    '''
    # Find longer suffixes that match shorter suffixes in the list
    longer_suffix_matches = []
    for s in suffix_obj:
        # this doesn't match s itself, only longer duplicates
        if suffix_match(suffix_obj, reverse_string(s), separator):
            # don't modify the list while iterating it
            longer_suffix_matches.append(s)

    # Removing the longer suffixes is safe, because the list remains in-order
    logging.warning("Removing {} duplicate longer suffixes from the collection"
                    .format(len(longer_suffix_matches)))
    for s in longer_suffix_matches:
        # if there are multiple duplicates, they will all be removed
        suffix_obj.remove(s)

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

    suffix_obj = suffix_match_collate_collection(suffix_collection, separator)
    # This takes about 20 seconds for the Alexa Top 1 million, and only finds
    # 239 duplicates. So maybe it's not worth doing.
    #suffix_match_uniquify_collection(suffix_obj, separator)
    return suffix_obj

def suffix_match(suffix_obj, search_str, separator=""):
    '''
    Performs an efficient O(log(N)) case-insensitive suffix match on
    search_str in suffix_obj.
    If specified, the separator is also required before the suffix.
    For example, domain suffixes use "." as a separator between components.

    suffix_obj must have been created by suffix_match_prepare_collection(),
    with the same separator.

    Returns True on a suffix match, but False on exact match and no match.
    Use exact_match() to find exact matches.
    '''
    # This code works on sorted lists, but checking is expensive
    # assert suffix_obj == sorted(suffix_obj)
    # We could also store the separator, and check it is the same

    # this is O(log(N)) because it's a binary search followed by a string
    # prefix match
    # We need to strip separators to make sure the match works.
    reversed_search_str = reverse_string(search_str.lower().strip(separator))
    # Longer strings sort after shorter strings, so our candidate is the
    # previous string. This works when there are multiple possible matches,
    # but it is inefficient.
    candidate_idx = bisect.bisect_left(suffix_obj, reversed_search_str) - 1
    # We should always get an entry in the list
    assert candidate_idx < len(suffix_obj)
    # If there is no previous entry, the string is definitely not a match
    if candidate_idx < 0:
        return False
    candidate_reversed_suffix = suffix_obj[candidate_idx]
    #logging.warning("{} -> {} candidate {} -> {} in {}".format(search_str, reversed_search_str, candidate_idx, candidate_reversed_suffix, suffix_obj))
    return reversed_search_str.startswith(candidate_reversed_suffix)

