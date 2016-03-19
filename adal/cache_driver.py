import copy
import datetime
import json

from .constants import TokenResponseFields, Misc
from . import log

METADATA_CLIENTID = '_clientId'
METADATA_AUTHORITY = '_authority'

def _create_token_hash(token):
    raise NotImplementedError()

def _create_token_id_message(entry):
    access_token_hash = _create_token_hash(entry[TokenResponseFields.ACCESS_TOKEN])
    message = 'AccessTokenId: ' + accessTokenHash
    if entry[TokenResponseFields.REFRESH_TOKEN]:
        refreshTokenHash = _create_token_hash(entry[TokenResponseFields.REFRESH_TOKEN])
        message += ', RefreshTokenId: ' + refreshTokenHash;
    return message;

class CacheDriver(object):
    def __init__(self, call_context, authority, resource, client_id, cache, refresh_function):
        self._call_context = call_context
        self._log = log.Logger("OAuth2Client", call_context['log_context'])
        self._authority = authority
        self._resource = resource
        self._client_id = client_id
        self._cache = cache
        self._refresh_function = refresh_function
    
    def _find (self, query):
        self._cache.find(query)

    def _get_potential_entries(self, query):
      potential_rntries_query = {};

      if query.client_id:
        potential_entries_query[METADATA_CLIENTID] = query[client_id]
      
      if query.user_id:
        potential_entries_query[TokenResponseFields.USER_ID] = query.userId

      self._log.debug('Looking for potential cache entries:')
      self._log.debug(json.dumps(potential_entries_query))
      entries = self._find(potential_entries_query)
      self._log.debug('Found {} potential entries.'.format(len(entries)))
      return entries
    
    def _find_mrrt_tokens_for_user(self, user):
        entries = self._find({
            'isMRRT': True,
            'userId': user,
            '_clientId' : self._client_id            
            })
        return entries

    def _load_single_entry_from_cache(self, query):
        return_val = []
        is_resource_tenant_specific = False

        potential_entries = self._get_potential_entries(query)
        if potential_entries:
            resource_tenant_sepcific_entries = [
                x for x in potential_entries if x['resource'] == self._resource and x['authority'] == self._authority]

            if not resource_tenant_sepcific_entries:
                self._log.debug('No resource specific cache entries found.')

                #There are no resource specific entries.  Find an MRRT token.
                mrrt_tokens = [x for x in potential_entries if x['isMRRT']]
                if mrrt_tokens:
                    self._log.debug('Found an MRRT token.')
                    return_val = mrrt_tokens[0]
                else:
                    self._log.debug('No MRRT tokens found.')
            elif len(resource_tenant_sepcific_entries) == 1:
                self._log.debug('Resource specific token found.')
                return_val = resource_tenant_sepcific_entries[0]
                is_resource_tenant_specific = True
            else:
                raise ValueError('More than one token matches the criteria.  The result is ambiguous.')

        if return_val:
            self._log.debug(
                'Returning token from cache lookup, {}'.format(_create_token_id_message(return_val)))

        return (return_val, is_resource_tenant_specific)

    def _create_entry_from_refresh(self, entry, refresh_response):
        new_entry = copy.deepcopy(entry)
        new_entry.update(refresh_response)

        if entry['isMRRT'] and self_authority != entry[METADATA_AUTHORITY]:
            new_entry[METADATA_AUTHORITY] = self._authority

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
        expiry_date = entry[TokenResponseFields.EXPIRES_ON]

        # Add some buffer in to the time comparison to account for clock skew or latency.
        now_plus_buffer = datetime.datetime.now() + datetime.timedelta(minutes=Misc.CLOCK_BUFFER)

        if is_resource_specific and now_plus_buffer > expiry_date:
            self._log.info('Cached token is expired.  Refreshing: {}'.format(expiry_date))
            new_entry = self._refresh_expired_entry(entry)
            return new_entry
        elif (not is_resource_specific) and entry['isMRRT']:
            self._log.info('Acquiring new access token from MRRT token.')
            new_entry = self._acquire_new_token_from_mrrt(entry)
            return new_entry
        else:
            return entry

    def find(self, query):
        if query is None:
            query = {}
        self._log.debug('finding with query: {}'.format(json.dumps(query)))
        entry, is_resource_tenant_specific = self._load_single_entry_from_cache(query)
        if entry:
            new_entry = self._refresh_entry_if_necessary(entry, is_resource_tenant_specific)
            return new_entry
        else:
            return None

    def remove(self, entry):
        self._log('Removing entry.')
        self._cache.remove([entry])

    def _remove_many(self, entries):
        self._log.debug('Remove many:{}'.format(len(entries)))
        self._cache.remove(entries)

    def _add_many(self, entries):
        self._log.debug('Add many:' + len(entries))
        self._cache.add(entries)

    @staticmethod
    def _is_mrrt(entry):
        return bool(entry['resource'])

    def _update_refresh_tokens(self, entry):
        if CacheDriver._is_mrrt(entry):
            mrrt_tokens = self._find_mrrt_tokens_for_user(entry['userId'])
            if mrrt_tokens:
               self._log.debug('Updating {} cached refresh tokens'.format(len(mrrt_tokens)))
               self._remove_many(mrrt_tokens)
               
               for t in mrrt_tokens:
                   t[TokenResponseFields.REFRESH_TOKEN] = entry[TokenResponseFields.REFRESH_TOKEN]

               self._add_many(mrrt_tokens)

    @staticmethod
    def _entry_has_metadata(entry):
        return (METADATA_CLIENTID in entry) and (METADATA_AUTHORITY in entry)

    def _argument_entry_with_cached_metadata(self, entry):
        if CacheDriver._entry_has_metadata(entry):
            return

        if CacheDriver._is_mrrt(entry):
            self._log.debug('Added entry is MRRT')
            entry['isMRRT'] = True
        else:
            entry['resource'] = self._resource

        entry[METADATA_CLIENTID] = self._client_id
        entry[METADATA_AUTHORITY] = self._authority

    def add(self, entry):
        self._log.debug('Adding entry, ' + createTokenIdMessage(entry))
        self._argument_entry_with_cached_metadata(entry)
        self._update_refresh_tokens(entry)
        self._cache.add([entry])

