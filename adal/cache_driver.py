#-------------------------------------------------------------------------
#
# Copyright Microsoft Open Technologies, Inc.
#
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http: *www.apache.org/licenses/LICENSE-2.0
#
# THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
# OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
# ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
# PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
#
# See the Apache License, Version 2.0 for the specific language
# governing permissions and limitations under the License.
#
#--------------------------------------------------------------------------

import hashlib
import base64
import json
from datetime import datetime, timedelta

from . import log
from . import constants
from .constants import Cache, TokenResponseFields

# TODO: remove this.
# There is a PM requirement that developers be able to look in to the cache and manipulate the cache based on
# the parameters (authority, resource, clientId, userId), in any combination.  They must be able find, add, and remove
# tokens based on those parameters.  Any default cache that the API supplies must allow for this query pattern.
# This has the following implications:
#  The developer must not be required to calculate any special fields, such as hashes or unique keys.
#
#  The default cache implementation can not include optimizations that break the previous requirement.
#  This means that we can only do complete scans of the data and equality can only be calculated based on
#  equality of all of the individual fields.
#
#  The cache interface can not make any assumption about the query efficiency of the cache nor can
#  it help in optimizing those queries.
#
#  There is no simple sorting optimization, rather a series of indexes, and index intersection would
#  be necessary.
#
#  If for some reason the developer tries to update the cache with a new entry that may be a refresh
#  token, they will not know that they need to update all of the refresh tokens or they may get strange
#  behavior.
#
#  Related to the above, there is no definition of a coherent cache.  And if there was there would be
#  no way for our API to enforce it.  What about duplicates?
#
# there be a single cache entry per (authority, resource, clientId)
# tuple, with no special tokens (i.e. MRRT tokens)
# Required cache operations


METADATA_CLIENTID = '_clientId'
METADATA_AUTHORITY = '_authority'

def is_MRRT(entry):
    return True if entry.get('resource') else False

def nop(place_holder, callback):
    callback()


class nopCache(object):
    """
    This is a place holder cache that does nothing.
    """
    add = nop
    add_many = nop
    remove = nop
    remove_many = nop
    find = nop

def create_token_hash(token):
    token_encoded = token.encode()

    hash_alg = hashlib.sha256()
    hash_alg.update(token_encoded)
    return base64.b64encode(hash_alg.digest())

def create_token_id_message(entry):

    access_token_hash = create_token_hash(entry[TokenResponseFields.ACCESS_TOKEN])
    message = "AccessTokenId: {0}".format(access_token_hash)

    if entry.get(TokenResponseFields.REFRESH_TOKEN):
        refresh_token_hash = create_token_hash(entry[TokenResponseFields.REFRESH_TOKEN])
        message += ", RefreshTokenId: {0}".format(refresh_token_hash)

    return message

class CacheDriver(object):

    def __init__(self, call_context, authority, resource, client_id, cache, refresh_function):
        self._call_context = call_context
        self._log = log.Logger('CacheDriver', call_context['log_context'])
        self._authority = authority
        self._resource = resource
        self._client_id = client_id
        self._cache = cache if cache else nopCache()
        self._refresh_function = refresh_function

    def _find(self, query, callback):

        authority_query = {}
        authority_query[METADATA_AUTHORITY] = self._authority

        query.update(authority_query)
        self._cache.find(query, callback)

    def _get_potential_entries(self, query, callback):

        potential_entries_query = {}

        if query.get('client_id'):
            potential_entries_query[METADATA_CLIENTID] = query['client_id']

        if query.get('user_id'):
            potential_entries_query[TokenResponseFields.USER_ID] = query['user_id']

        self._log.debug("Looking for potential cache entries:")
        self._log.debug(json.dumps(potential_entries_query))

        def _callback(err, entries):
            self._log.debug("Found {0} potential entries".format(len(potential_entries_query)))
            callback(err, entries)

        self._find(potential_entries_query, _callback)

    def _find_MRRT_tokens_for_user(self, user, callback):

        self._find({'isMRRT':True, 'user_id':user}, callback)

    def _load_single_entry_from_cache(self, query, callback):
        
        def _callback(err, potential_entries):
            if err:
                callback(err)
                return

            return_val = None
            is_resource_specific = False

            if potential_entries:
                resource_specific_entries = [entry for entry in potential_entries if entry['resource'] == self._resource]

                if not resource_specific_entries:
                    self._log.debug('No resource specific cache entries found.')

                    mrrt_tokens = [entry for entry in potential_entries if entry['isMRRT'] == True]
                    if mrrt_tokens:
                        self._log.debug('Found an MRRT token.')
                        return_val = mrrt_tokens[0]
                    else:
                        self._log.debug('No MRRT tokens found.')

                elif len(resource_specific_entries) == 1:
                    self._log.debug('Resource specific token found.')
                    return_val = resource_specific_entries[0]
                    is_resource_specific = True

                else:
                    callback(self._log.create_error('More than one token matches the criteria.  The result is ambiguous.'), None, None)
                    return

            if return_val:
                self._log.debug("Returning token from cache lookup, {0}".format(create_token_id_message(return_val)))

            callback(None, return_val, is_resource_specific)

        self._get_potential_entries(query, _callback)


    def _create_entry_from_refresh(self, entry, refresh_response):

        new_entry = dict(entry)
        new_entry.update(refresh_response)
        self._log.debug("Created new cache entry from refresh response.")
        return new_entry

    def _replace_entry(self, entry_to_replace, new_entry, callback):

        def _callback(err):
            if err:
                callback(err)
                return
            self.add(new_entry, callback)

        self.remove(entry_to_replace, _callback)

    def _refresh_expired_entry(self, entry, callback):

        def _callback(err, token_response):
            if err:
                callback(err, None)
                return

            new_entry = self._create_entry_from_refresh(entry, token_response)

            def _call(err):
                if err:
                    self._log.error('error refreshing expired token', err)
                else:
                    self._log.info('Returning token refreshed after expiry.')
                callback(err, new_entry)

            self._replace_entry(entry, new_entry, _call)

        self._refresh_function(entry, None, _callback)

    def _acquire_new_token_from_mrrt(self, entry, callback):

        def _callback(err, token_response):
            if err:
                callback(err, None)
                return

            new_entry = self._create_entry_from_refresh(entry, token_response)

            def _call(err):
                if err:
                    self._log.error("Error refreshing MRRT.", err)
                else:
                    self._log.info("Returning token derived from mrrt refresh.")
                callback(err, new_entry)
            self.add(new_entry, _call)

        self._refresh_function(entry, self._resource, _callback)

    def _refresh_entry_if_necessary(self, entry, is_resource_specific, callback):

        expiry_date = entry[TokenResponseFields.EXPIRES_ON]
        now = datetime.now()
        now_plus_buffer = now + timedelta(0,0,0,0,constants.Misc.CLOCK_BUFFER)

        if is_resource_specific and now_plus_buffer > expiry_date:
            self._log.info("Cached token is expired. Refreshing: {0}".format(expiry_date))
            self._refresh_expired_entry(entry, callback)
            return

        elif not is_resource_specific and entry.get('isMRRT') == True:
            self._log.info("Acquiring new access token from MRRT token.")
            self._acquire_new_token_from_mrrt(entry, callback)
            return

        else:
            callback(None, entry)

    def _update_refresh_tokens(self, entry, callback):

        if is_MRRT(entry):

            def _callback(err, mrrt_tokens):
                if err:
                    callback(err)
                    return

                if not mrrt_tokens:
                    callback(None)
                    return

                self._log.debug("Updating {0} cached refresh tokens".format(len(mrrt_tokens)))

                def _call(err):
                    if err:
                        callback(err)
                        return

                    for token in mrrt_tokens:
                        token[TokenResponseFields.REFRESH_TOKEN] = entry[TokenResponseFields.REFRESH_TOKEN]

                    def _c(err):
                        callback(err)
                        return
                    self._add_many(mrrt_tokens, _c)

                self._remove_many(mrrt_tokens, _call)

            self._find_MRRT_tokens_for_user(entry.get('user_id'), _callback)
        else:
            callback(None)

    def _entry_has_metadata(self, entry):
        if entry.get(METADATA_CLIENTID) and entry.get(METADATA_AUTHORITY):
            return True
        return False

    def _augment_entry_with_cache_metadata(self, entry):

        if self._entry_has_metadata(entry):
            return

        if is_MRRT(entry):
            self._log.debug("Added entry is MRRT")
            entry['isMRRT'] = True

        else:
            entry['resource'] = self._resource

        entry[METADATA_CLIENTID] = self._client_id
        entry[METADATA_AUTHORITY] = self._authority

    def _remove_many(self, entries, callback):

        self._log.debug("Removing many: {0}".format(len(entries)))

        def _callback(err):
            callback(err)
            return

        self._cache.remove(entries, _callback)

    def _add_many(self, entries, callback):

        self._log.debug("Adding many: {0}".format(len(entries)))

        def _callback(err):
            callback(err)
            return

        self._cache.add(entries, _callback)

    def find(self, query, callback):

        query = query if query else {}

        self._log.debug("Finding with query: {0}".format(query))

        def _callback(err, entry, is_resource_specific):
            if err:
                callback(err, None)
                return

            if not entry:
                callback(None, None)
                return

            def _call(err, new_entry):
                callback(err, new_entry)
                return
            self._refresh_entry_if_necessary(entry, is_resource_specific, _call)

        self._load_single_entry_from_cache(query, _callback)

    def remove(self, entry, callback):

        self._log.debug("Removing entry.")

        def _callback(err):
            callback(err)
            return

        self._cache.remove([entry], _callback)

    def add(self, entry, callback):

        self._log.debug("Adding entry: {0}".format(create_token_id_message(entry)))
        self._augment_entry_with_cache_metadata(entry)

        def _callback(err):
            if err:
                callback(err)
                return

            def _call(err, _):
                callback(err)
                return
            self._cache.add([entry], _call)
        self._update_refresh_tokens(entry, _callback)





