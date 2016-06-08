﻿import json

from .constants import TokenResponseFields

def _string_cmp(str1, str2):
    if not str1 and not str2:
        return True
    elif not str1 or not str2:
        return False
    else:
        return str1.lower() == str2.lower()

class TokenCacheKey(object):
    #To clarify with AAD team, comparing with C# version
    #  https://github.com/AzureAD/azure-activedirectory-library-for-dotnet/blob/master/src/ADAL.Common/TokenCacheKey.cs
    #We don't hash 'TokenSubjectType' and 'DisplayableId', big deal?
    def __init__(self, authority, resource, client_id, user_id):
        self.authority = authority
        self.resource = resource
        self.client_id = client_id
        self.user_id = user_id

    def __hash__(self):
        return hash((self.authority, self.resource, self.client_id, self.user_id))

    def __eq__(self, other):
        return _string_cmp(self.authority, other.authority) and \
               _string_cmp(self.resource, other.resource) and \
               _string_cmp(self.client_id, other.client_id) and \
               _string_cmp(self.user_id, other.user_id)

    def __ne__(self, other):
        return not self == other

#TODO: ensure thread safety
class TokenCache(object):
    def __init__(self, state=None):
        self._cache = {}
        if state:
            self.deserialize(state)
        self.has_state_changed = False

    def find(self, query):
        entries = self._query_cache(
            query.get(TokenResponseFields.IS_MRRT), 
            query.get(TokenResponseFields.USER_ID), 
            query.get(TokenResponseFields._CLIENT_ID))
        return entries

    def remove(self, entries):
        for e in entries:
           key = TokenCache._get_cache_key(e)
           self._cache.pop(key)
        self.has_state_changed = True

    def add(self, entries):
        for e in entries:
            key = TokenCache._get_cache_key(e)
            self._cache[key] = e
        self.has_state_changed = True

    def serialize(self):
        state = json.dumps(list(self._cache.values()))
        return state

    def deserialize(self, state):
        self._cache.clear()
        if state:
            tokens = json.loads(state)
            for t in tokens:
                key = self._get_cache_key(t)
                self._cache[key] = t

    def read_items(self):
        '''output list of tuples in (key, authentication-result)'''
        return self._cache.items()

    @staticmethod
    def _get_cache_key(entry):
        return TokenCacheKey(
            entry.get(TokenResponseFields._AUTHORITY), 
            entry.get(TokenResponseFields.RESOURCE), 
            entry.get(TokenResponseFields._CLIENT_ID), 
            entry.get(TokenResponseFields.USER_ID))

    def _query_cache(self, is_mrrt, user_id, client_id):
        matches = []
        for k in self._cache:
            v = self._cache[k]
            if (is_mrrt is None or is_mrrt == v.get(TokenResponseFields.IS_MRRT)) and \
               (user_id is None or _string_cmp(user_id, v.get(TokenResponseFields.USER_ID))) and \
               (client_id is None or _string_cmp(client_id, v.get(TokenResponseFields._CLIENT_ID))):
                matches.append(v)
        return matches
