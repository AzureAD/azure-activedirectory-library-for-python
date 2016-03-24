
def _string_cmp(self, str1, str2):
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
        return not(self == other)

class TokenCache(object):
    def __init__(self):
        self._cache = {}

    def find(self, query):
        entries = []
        for e in self._entries:
            matched = True
            for key in query:
                if query[key] != e[key]:
                    matched = False
                    break
            if matched:
                entries.append(e)

        return entries

    def remove(self, entries):
        for e in entries:
           key = self._get_cache_key(e)
           self._cache.pop(key)

    def add(self, entries):
        for e in entries:
            self._add_single_entry(e)

    def _add_single_entry(self, entry): #TODO: constantlize all field name like 'METADATA' stuff
        key = self._get_cache_key(entry)
        self._cache[key] = entry

    def _get_cache_key(self, entry):
        return TokenCacheKey(entry['_authority'], entry['resource'], entry['_clientId'], entry['userId'])

    def _query_cache(self, is_mrrt, user_id, client_id):
        matches = []
        for k in self._cache:
            v = self._cache[k]
            if (is_mrrt == None or is_mrrt == v['isMRRT']) and \
               (user_id == None or _string_cmp(user_id, v['userId']) and \
               (client_id == None or _string_cmp(client_id, v['clientId'])):
                matches.append(v)
        return matches
                 
