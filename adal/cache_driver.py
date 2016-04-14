﻿#------------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. 
# All rights reserved.
# 
# This code is licensed under the MIT License.
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files(the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions :
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#------------------------------------------------------------------------------

import base64
import copy
import hashlib
import json
from datetime import datetime, timedelta
from dateutil import parser

from .adal_error import AdalError
from .constants import TokenResponseFields, Misc
from . import log

#surppress warnings: like accces to a protected member of "_AUTHORITY", etc
# pylint: disable=W0212

def _create_token_hash(token):
    hash_object = hashlib.sha256()
    hash_object.update(token.encode('utf8'))
    return base64.b64encode(hash_object.digest())

def _create_token_id_message(entry):
    access_token_hash = _create_token_hash(entry[TokenResponseFields.ACCESS_TOKEN])
    message = 'AccessTokenId: ' + str(access_token_hash)
    if entry.get(TokenResponseFields.REFRESH_TOKEN):
        refresh_token_hash = _create_token_hash(entry[TokenResponseFields.REFRESH_TOKEN])
        message += ', RefreshTokenId: ' + str(refresh_token_hash)
    return message

class CacheDriver(object):
    def __init__(self, call_context, authority, resource, client_id, cache, refresh_function):
        self._call_context = call_context
        self._log = log.Logger("OAuth2Client", call_context['log_context'])
        self._authority = authority
        self._resource = resource
        self._client_id = client_id
        self._cache = cache
        self._refresh_function = refresh_function

    def _get_potential_entries(self, query):
        potential_entries_query = {}

        if query.get(TokenResponseFields._CLIENT_ID):
            potential_entries_query[TokenResponseFields._CLIENT_ID] = query[TokenResponseFields._CLIENT_ID]
      
        if query.get(TokenResponseFields.USER_ID):
            potential_entries_query[TokenResponseFields.USER_ID] = query[TokenResponseFields.USER_ID]

        self._log.debug('Looking for potential cache entries:')
        self._log.debug(json.dumps(potential_entries_query))
        entries = self._cache.find(potential_entries_query)
        self._log.debug('Found %s potential entries.', len(entries))
        return entries
    
    def _find_mrrt_tokens_for_user(self, user):
        return self._cache.find({
            TokenResponseFields.IS_MRRT: True,
            TokenResponseFields.USER_ID: user,
            TokenResponseFields._CLIENT_ID : self._client_id            
            })

    def _load_single_entry_from_cache(self, query):
        return_val = []
        is_resource_tenant_specific = False

        potential_entries = self._get_potential_entries(query)
        if potential_entries:
            resource_tenant_specific_entries = [
                x for x in potential_entries 
                if x[TokenResponseFields.RESOURCE] == self._resource and 
                x[TokenResponseFields._AUTHORITY] == self._authority]

            if not resource_tenant_specific_entries:
                self._log.debug('No resource specific cache entries found.')

                #There are no resource specific entries.  Find an MRRT token.
                mrrt_tokens = [x for x in potential_entries if x[TokenResponseFields.IS_MRRT]]
                if mrrt_tokens:
                    self._log.debug('Found an MRRT token.')
                    return_val = mrrt_tokens[0]
                else:
                    self._log.debug('No MRRT tokens found.')
            elif len(resource_tenant_specific_entries) == 1:
                self._log.debug('Resource specific token found.')
                return_val = resource_tenant_specific_entries[0]
                is_resource_tenant_specific = True
            else:
                raise AdalError('More than one token matches the criteria. The result is ambiguous.')

        if return_val:
            self._log.debug('Returning token from cache lookup, %s',
                            _create_token_id_message(return_val))

        return (return_val, is_resource_tenant_specific)

    def _create_entry_from_refresh(self, entry, refresh_response):
        new_entry = copy.deepcopy(entry)
        new_entry.update(refresh_response)

        if entry[TokenResponseFields.IS_MRRT] and self._authority != entry[TokenResponseFields._AUTHORITY]:
            new_entry[TokenResponseFields._AUTHORITY] = self._authority

        self._log.debug('Created new cache entry from refresh response.')
        return new_entry

    def _replace_entry(self, entry_to_replace, new_entry):
        self.remove(entry_to_replace)
        self.add(new_entry)

    def _refresh_expired_entry(self, entry):
        token_response = self._refresh_function(entry, None)
        new_entry = self._create_entry_from_refresh(entry, token_response)
        self._replace_entry(entry, new_entry)
        self._log.info('Returning token refreshed after expiry.')
        return new_entry

    def _acquire_new_token_from_mrrt(self, entry):
        token_response = self._refresh_function(entry, self._resource)
        new_entry = self._create_entry_from_refresh(entry, token_response)
        self.add(new_entry)
        self._log.info('Returning token derived from mrrt refresh.')
        return new_entry

    def _refresh_entry_if_necessary(self, entry, is_resource_specific):
        expiry_date = parser.parse(entry[TokenResponseFields.EXPIRES_ON])
        now = datetime.now(expiry_date.tzinfo)
            
        # Add some buffer in to the time comparison to account for clock skew or latency.
        now_plus_buffer = now + timedelta(minutes=Misc.CLOCK_BUFFER)

        if is_resource_specific and now_plus_buffer > expiry_date:
            self._log.info('Cached token is expired.  Refreshing: %s', expiry_date)
            return self._refresh_expired_entry(entry)
        elif (not is_resource_specific) and entry.get(TokenResponseFields.IS_MRRT):
            self._log.info('Acquiring new access token from MRRT token.')
            return self._acquire_new_token_from_mrrt(entry)
        else:
            return entry

    def find(self, query):
        if query is None:
            query = {}
        self._log.debug('finding with query: %s', json.dumps(query))
        entry, is_resource_tenant_specific = self._load_single_entry_from_cache(query)
        if entry:
            return self._refresh_entry_if_necessary(entry, is_resource_tenant_specific)
        else:
            return None

    def remove(self, entry):
        self._log.debug('Removing entry.')
        self._cache.remove([entry])

    def _remove_many(self, entries):
        self._log.debug('Remove many:%s', len(entries))
        self._cache.remove(entries)

    def _add_many(self, entries):
        self._log.debug('Add many: %s', len(entries))
        self._cache.add(entries)

    @staticmethod
    def _is_mrrt(entry):
        return bool(entry[TokenResponseFields.RESOURCE])

    def _update_refresh_tokens(self, entry):
        if CacheDriver._is_mrrt(entry) and entry.get(TokenResponseFields.REFRESH_TOKEN):
            mrrt_tokens = self._find_mrrt_tokens_for_user(entry.get(TokenResponseFields.USER_ID))
            if mrrt_tokens:
                self._log.debug('Updating %s cached refresh tokens', len(mrrt_tokens))
                self._remove_many(mrrt_tokens)
               
                for t in mrrt_tokens:
                    t[TokenResponseFields.REFRESH_TOKEN] = entry[TokenResponseFields.REFRESH_TOKEN]

                self._add_many(mrrt_tokens)

    @staticmethod
    def _entry_has_metadata(entry):
        return (TokenResponseFields._CLIENT_ID in entry) and (TokenResponseFields._AUTHORITY in entry)

    def _argument_entry_with_cached_metadata(self, entry):
        if CacheDriver._entry_has_metadata(entry):
            return

        if CacheDriver._is_mrrt(entry):
            self._log.debug('Added entry is MRRT')
            entry[TokenResponseFields.IS_MRRT] = True
        else:
            entry[TokenResponseFields.RESOURCE] = self._resource

        entry[TokenResponseFields._CLIENT_ID] = self._client_id
        entry[TokenResponseFields._AUTHORITY] = self._authority

    def add(self, entry):
        self._log.debug('Adding entry %s', _create_token_id_message(entry))
        self._argument_entry_with_cached_metadata(entry)
        self._update_refresh_tokens(entry)
        self._cache.add([entry])
