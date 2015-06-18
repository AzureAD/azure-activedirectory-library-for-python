import sys
import requests
import httpretty
import json
from adal.self_signed_jwt import SelfSignedJwt
from datetime import datetime
from adal.authority import Authority
from copy import deepcopy
from adal.memory_cache import MemoryCache
from adal.cache_driver import CacheDriver

try:
    import unittest2 as unittest
except ImportError:
    import unittest
    
try:
    from unittest import mock
except ImportError:
    import mock

import adal
from adal.authentication_context import AuthenticationContext
from tests import util
from tests.util import parameters as cp

class TestCacheDriver(unittest.TestCase):
    def test_add_entry(self):
        pass

    def unexpected_refresh_function(self):
        self.fail('Unexpected attempt to refresh a token.')

    def assert_entries_equal(self, expected, received, message):
        response = util.dicts_equal(expected, received)
        if response: 
            print('Expected:')
            print(expected)
            print('Received')
            print(received)
            self.fail('{}: {}'.format(message, response))

    def compareInputAndCache(self, input, cache, numMRRTTokens, mrrtRefreshToken):
        '''
        Compares two lists of cache entries.  The lists will be sorted before comparison and the comparison will
        take in to account the different ways that MRRT is indicated when a cache entry is submitted to the cache
        and once it is in the cache.
        '''

        foundNumMRRTTokens = 0
        cacheEntries = cache._entries
        authority = cp['authorityTenant']
        userId = cp['username']

        self.assertEqual(len(input), len(cacheEntries), 'Input responses and cache len(entries)s are not the same: ' + len(input) + ',' + len(cacheEntries))
        
        shared_items = set(input.keys()) & set(cacheEntries.keys())
        self.assertTrue(len(shared_items) == len(input), 'Input and cache do not have the same items')
        
        for i in input.keys():
            expected = deepcopy(input[i])
            received = deepcopy(cacheEntries[i])

            if (received.isMRRT):
                foundNumMRRTTokens += 1
                if (received._authority == authority and received.userId == userId):
                    # Everything should match except the refresh token.  We will check that below.
                    del expected['refreshToken']
                    del received['refreshToken']
                
            self.assert_entries_equal(expected, received, 'Found a modified entry number ' + i)

        if numMRRTTokens:
            self.assertTrue(numMRRTTokens == foundNumMRRTTokens, 'Found wrong number of MRRT tokens in the cache: ' + numMRRTTokens + ',' + foundNumMRRTTokens)

            # Ensure that when the last refresh token was added that all mrrt refresh tokens were updated to contain that same
            # refresh token.
            for i in cacheEntries:
                if i.isMRRT:
                    self.assertTrue(i['refreshToken'] == mrrtRefreshToken, 'One of the responses refresh token was not correctly updated: ' + i)
    
    def test_add_entry(self):
        fake_token_request = util.create_empty_adal_object()
        response = util.create_response()
        expectedResponse = response['cachedResponse']

        memCache = MemoryCache()
        cacheDriver = CacheDriver(fake_token_request['call_context'], response['authority'], response['resource'], response['clientId'], memCache, self.unexpected_refresh_function)

        def callback(err):
            stack = err.stack if err else 'None'
            self.assertFalse(err, 'Received unexpected error: {}'.format(stack))
            length = len(memCache._entries)
            self.assertTrue(length == 1, 'Cache after test has does not have the correct number of entries {}: {}'.format(length, memCache._entries))
            self.assert_entries_equal(expectedResponse, memCache._entries[0], 'The saved cache entry has been modified')

        cacheDriver.add(response['decodedResponse'], callback)
    
    def test_add_entry_no_cache(self):
        fake_token_request = util.create_empty_adal_object()

        response = util.create_response()

        cacheDriver = CacheDriver(fake_token_request['call_context'], response['authority'], response['resource'], cp['clientId'], None, self.unexpected_refresh_function)

        def callback(err):
            stack = err.stack if err else 'None'
            self.assertFalse(err, 'Received unexpected error: {}'.format(stack))
        
        cacheDriver.add(response['decodedResponse'], callback)
   
    def test_add_entry_single_mrrt(self):
        fake_token_request = util.create_empty_adal_object()

        responseOptions = { 'mrrt' : True }
        response = util.create_response(responseOptions)
        expectedResponse = response['cachedResponse']
        resource = response['resource']

        memCache = MemoryCache()
        cacheDriver = CacheDriver(fake_token_request['call_context'], response['authority'], resource, cp['clientId'], memCache, self.unexpected_refresh_function)

        def callback(err):
            stack = err.stack if err else 'None'
            self.assertFalse(err, 'Received unexpected error: {}'.format(stack))
            length = len(memCache._entries)
            self.assertTrue(length == 1, 'Cache after test has does not have the correct number of entries {}: {}'.format(length, memCache._entries))
            self.assert_entries_equal(expectedResponse, memCache._entries[0], 'The saved cache entry has been modified')

        cacheDriver.add(response['decodedResponse'], callback)
          

    '''
  /**
   * Creates a CacheDriver with a MemoryCache and fills it with test entries.
   * @param  {int}   numEntries The total number of entries that should be in the cache
   * @param  {int}   numMrrt    The number of tokens in the cache that should be mrrt tokens.  This number must
   *                            be smaller than numEntries.
   * @param  {Function} callback   returns an object with the CacheDriver etc...
   */
  function fillCache(numEntries, numMrrt, addExpired, callback) {
    fake_token_request = util.create_empty_adal_object()

    memCache = MemoryCache()
    authority = cp['authorityTenant']

    responses = []
    divisor = Math.floor(numEntries / numMrrt)
    finalMrrt
    expiredEntry
    for (i = 0 i < numEntries i++) {
      responseOptions = { authority : cp['authorityTenant']}
      if (numMrrt && ((i + 1) % divisor) == 0) {
        responseOptions.mrrt = True
      } else if (addExpired) {
        responseOptions.expired = expiredEntry ? false : True
      }
      newResponse = util.create_response(responseOptions, i)
      finalMrrt = responseOptions.mrrt ? newResponse.refreshToken : finalMrrt
      expiredEntry = responseOptions.expired ? newResponse : expiredEntry
      responses.push(newResponse)
    }

    count = 0
    finalRefreshToken
    async.whilst(
      function() { return count < numEntries },
      function(callback) {
        resource = responses[count].resource
        clientId = responses[count].clientId
        cacheDriver = CacheDriver(fake_token_request['call_context'], authority, resource, clientId, memCache, self.unexpected_refresh_function)
        responseToAdd = _.clone(responses[count].decodedResponse)
        cacheDriver.add(responseToAdd, function(err) {
          count++
          process.nextTick(function() {
            callback(err)
            return
          })
        })
      },
      function(err) {
        cachedResponses = []
        for (j = 0 j < len(responses) j++) {
          cachedResponses.push(responses[j].cachedResponse)
        }

        testValues = {
          cachedResponses : cachedResponses,
          memCache : memCache,
          finalMrrt : finalMrrt,
          fake_token_request : fake_token_request,
          authority : authority,
          expiredEntry : expiredEntry
        }
        callback(err, testValues, finalRefreshToken)
      }
    )
  }

  test('add-multiple-entries-ensure-authority-respected', function(done) {
    numMRRTTokens = 6
    fillCache(20, numMRRTTokens, false, function(err, testValues) {
      responses = testValues.cachedResponses
      memCache = testValues.memCache
      fake_token_request = testValues.fake_token_request

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens)

        otherAuthority = 'someOtherAuthority'
        responseOptions = { authority : otherAuthority, mrrt : True, resource : responses[0].resource }
        differentAuthorityResponse = util.create_response(responseOptions)
        delete responseOptions.authority
        extraMRRTResponse = util.create_response(responseOptions, 21)
        responses.push(extraMRRTResponse.cachedResponse)
        responses.push(differentAuthorityResponse.cachedResponse)
        numMRRTTokens += 2

        # order is important here.  We want to ensure that when we add the second MRRT it has only updated
        # the refresh token of the entries with the same authority.
        cacheDriver = CacheDriver(fake_token_request['call_context'], otherAuthority, differentAuthorityResponse.resource, differentAuthorityResponse.clientId, memCache, self.unexpected_refresh_function)
        cacheDriver.add(differentAuthorityResponse.decodedResponse, function(err) {
          self.assertTrue(!err, 'Unexpected err adding entry with different authority.')

          cacheDriver2 = CacheDriver(fake_token_request['call_context'], cp['authorityTenant'], extraMRRTResponse.resource, extraMRRTResponse.clientId, memCache, self.unexpected_refresh_function)
          cacheDriver2.add(extraMRRTResponse.decodedResponse, function(err2) {
            self.assertTrue(!err2, 'Unexpected error adding second entry with previous authority.')
            compareInputAndCache(responses, memCache, numMRRTTokens)

            # ensure that we only find the mrrt with the different authority.
            cacheDriver.find( { resource : differentAuthorityResponse.resource}, function(err3, entry) {
              self.assertTrue(!err3, 'Unexpected error returned from find.')
              self.assert_entries_equal(differentAuthorityResponse.cachedResponse, entry, 'Queried entry did not match expected indicating authority was not respected')
            })
            done()
          })
        })
      }
    })
  })

  test('add-multiple-entries-find-non-mrrt', function(done) {
    numMRRTTokens = 6
    fillCache(20, numMRRTTokens, false, function(err, testValues) {
      responses = testValues.cachedResponses
      memCache = testValues.memCache
      fake_token_request = testValues.fake_token_request

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens)

        findResponse = _.find(responses, function(entry) { return !entry.isMRRT })
        cacheDriver = CacheDriver(fake_token_request['call_context'], cp['authorityTenant'], findResponse.resource, findResponse.clientId, memCache, self.unexpected_refresh_function)
        cacheDriver.find({}, function(err, entry) {
          if (!err) {
            self.assertTrue(entry, 'Find did not return any entry')
            self.assert_entries_equal(findResponse, entry, 'Queried entry did not match expected: ' + JSON.stringify(entry))
          }
          done(err)
          return
        })
      } else {
        done(err)
        return
      }
    })
  })

  test('add-multiple-entries-mrrt', function(done) {
    numMRRTTokens = 6
    fillCache(19, numMRRTTokens, false, function(err, testValues) {
      responses = testValues.cachedResponses
      memCache = testValues.memCache
      finalMrrt = testValues.finalMrrt

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt)
      }

      done()
      return
    })
  })

  # This test is actually testing two different things.
  #  1. When a MRRT is added to the cache only MRRT
  #     tokens with the same userId are updated.
  #  2. Check that url safe base64 decoding is happening
  #     correctly.
  test('add-multiple-entries-mrrt-different-users--url-safe-id_token', function(done) {
    numMRRTTokens = 6
    fillCache(19, numMRRTTokens, false, function(err, testValues) {
      responses = testValues.cachedResponses
      memCache = testValues.memCache
      finalMrrt = testValues.finalMrrt
      fake_token_request = testValues.fake_token_request

      responseOptions = { 'mrrt' : True, refreshedRefresh : True, urlSafeUserId : True }
      refreshedResponse = util.create_response(responseOptions)

      # verify that the returned response contains an id_token that will actually
      # test url safe base64 decoding.
      self.assertTrue(-1 !== refreshedResponse.wireResponse['id_token'].indexOf('_'), 'No special characters in the test id_token.  ' +
        'This test is not testing one of the things it was intended to test.')

      responses.push(refreshedResponse.cachedResponse)

      cacheDriver = CacheDriver(fake_token_request['call_context'], testValues.authority, refreshedResponse.resource, refreshedResponse.clientId, memCache, self.unexpected_refresh_function)
      cacheDriver.add(refreshedResponse.decodedResponse, function(err) {
        if (!err) {
          compareInputAndCache(responses, memCache, numMRRTTokens + 1, finalMrrt)
        }
        done(err)
        return
      })
    })
  })

  test('add-multiple-entries-find-mrrt', function(done) {
    numMRRTTokens = 6
    fillCache(20, numMRRTTokens, false, function(err, testValues) {
      responses = testValues.cachedResponses
      memCache = testValues.memCache
      fake_token_request = testValues.fake_token_request

      mrrtEntry = _.findWhere(memCache._entries, { isMRRT : True })

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens)

        cacheDriver = CacheDriver(fake_token_request['call_context'], cp['authorityTenant'], mrrtEntry.resource, mrrtEntry._clientId, memCache, self.unexpected_refresh_function)
        cacheDriver.find({}, function(err, entry) {
          if (!err) {
            self.assertTrue(entry, 'Find did not return any entry')
            self.assert_entries_equal(mrrtEntry, entry, 'Queried entry did not match expected: ' + JSON.stringify(entry))
          }
          done(err)
          return
        })
      } else {
        done(err)
        return
      }
    })
  })

  function createRefreshFunction(expectedRefreshToken, response) {
    refreshFunction = function(entry, resource, callback) {
      if (expectedRefreshToken !== entry['refreshToken']) {
        print('RECEIVED:')
        print(entry.refreshToken)
        print('EXPECTED')
        print(expectedRefreshToken)
        self.assertTrue(false, 'RefreshFunction received unexpected refresh token: ' + entry['refreshToken'])
      }
      self.assertTrue(_.isFunction(callback), 'callback parameter is not a function')

      callback(None, response)
    }

    return refreshFunction
  }

  test('add-multiple-entries-mrrt-find-refreshed-mrrt', function(done) {
    numMRRTTokens = 5
    fillCache(20, 5, false, function(err, testValues) {
      responses = testValues.cachedResponses
      memCache = testValues.memCache
      fake_token_request = testValues.fake_token_request
      finalMrrt = testValues.finalMrrt
      authority = testValues.authority

      unknownResource = 'unknownResource'
      responseOptions = { resource : unknownResource, mrrt : True, refreshedRefresh : True }
      refreshedResponse = util.create_response(responseOptions)
      refreshedRefreshToken = refreshedResponse.refreshToken
      refreshFunction = createRefreshFunction(finalMrrt, refreshedResponse.decodedResponse)

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt)

        responses.push(refreshedResponse.cachedResponse)
        cacheDriver = CacheDriver(fake_token_request['call_context'], authority, unknownResource, cp['clientId'], memCache, refreshFunction)
        cacheDriver.find(None, function(err, entry) {
          if (!err) {
            self.assertTrue(entry, 'Expected a matching entry, but none was returned.')
            self.assertTrue(entry.resource == unknownResource, 'Unexpected resource returned:' + entry.resource)
            self.assertTrue(refreshedRefreshToken == entry['refreshToken'], 'Returned refresh token did not match expected')
            compareInputAndCache(responses, memCache, numMRRTTokens + 1, entry.refreshToken)

            # Now ensure that the refreshed token can be successfully found in the cache.
            query = {
              userId : entry.userId,
              clientId : cp['clientId']
            }
            cacheDriver.find(query, function(err, recentlyCachedEntry) {
              if (!err) {
                self.assertTrue(recentlyCachedEntry, 'Expected a returned entry but none was returned.')
                self.assert_entries_equal(entry, recentlyCachedEntry, 'Token returned from cache was not the same as the one that was recently cached.')
                compareInputAndCache(responses, memCache, numMRRTTokens + 1, entry.refreshToken)
              }
              done(err)
              return
            })
          } else {
            done(err)
            return
          }
        })
      } else {
        done(err)
        return
      }
    })
  })

  test('add-multiple-entries-failed-mrrt-refresh', function(done) {
    numMRRTTokens = 5
    fillCache(20, 5, false, function(err, testValues) {
      responses = testValues.cachedResponses
      memCache = testValues.memCache
      fake_token_request = testValues.fake_token_request
      finalMrrt = testValues.finalMrrt
      authority = testValues.authority

      unknownResource = 'unknownResource'
      refreshFunction = function(entry, resource, callback) { callback(Error('FAILED REFRESH')) }

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt)

        cacheDriver = CacheDriver(fake_token_request['call_context'], authority, unknownResource, cp['clientId'], memCache, refreshFunction)
        cacheDriver.find(None, function(err) {
          self.assertTrue(err, 'Did not receive expected error.')
          self.assertTrue(-1 !== err.message.indexOf('FAILED REFRESH'), 'Error message did not contain correct text')
          compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt)
          done()
          return
        })
      } else {
        done(err)
        return
      }
    })
  })

  function removeResponse(collection, response) {
    return _.filter(collection, function(entry) {
      if (_.isEqual(response, entry)) {
        return false
      }
      return True
    })
  }

  test('expired-access-token', function(done) {
    numMRRTTokens = 5
    fillCache(20, 5, True, function(err, testValues) {
      responses = testValues.cachedResponses
      memCache = testValues.memCache
      fake_token_request = testValues.fake_token_request
      authority = testValues.authority
      expiredEntry = testValues.expiredEntry.cachedResponse
      finalMrrt = testValues.finalMrrt

      responseOptions = { resource : expiredEntry.resource, refreshedRefresh : True }
      refreshedResponse = util.create_response(responseOptions)
      refreshedRefreshToken = refreshedResponse.refreshToken
      refreshFunction = createRefreshFunction(expiredEntry['refreshToken'], refreshedResponse.decodedResponse)

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt)

        responses = removeResponse(responses, expiredEntry)
        responses.push(refreshedResponse.cachedResponse)
        cacheDriver = CacheDriver(fake_token_request['call_context'], authority, expiredEntry.resource, cp['clientId'], memCache, refreshFunction)
        cacheDriver.find(None, function(err, entry) {
          if (!err) {
            self.assertTrue(entry, 'Expected a matching entry, but none was returned.')
            self.assertTrue(entry.resource == expiredEntry.resource, 'Unexpected resource returned:' + entry.resource)
            self.assertTrue(refreshedRefreshToken == entry['refreshToken'], 'Returned refresh token did not match expected')
            compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt)

            # Now ensure that the refreshed token can be successfully found in the cache.
            query = {
              userId : entry.userId,
              clientId : cp['clientId']
            }
            cacheDriver.find(query, function(err, recentlyCachedEntry) {
              if (!err) {
                self.assertTrue(recentlyCachedEntry, 'Expected a returned entry but none was returned.')
                self.assert_entries_equal(entry, recentlyCachedEntry, 'Token returned from cache was not the same as the one that was recently cached.')
                compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt)
              }
              done(err)
              return
            })
          } else {
            done(err)
            return
          }
        })
      } else {
        done(err)
        return
      }
    })
  })

  test('expired-access-token-failed-refresh', function(done) {
    numMRRTTokens = 5
    fillCache(20, 5, True, function(err, testValues) {
      responses = testValues.cachedResponses
      memCache = testValues.memCache
      fake_token_request = testValues.fake_token_request
      authority = testValues.authority
      expiredEntry = testValues.expiredEntry.cachedResponse
      finalMrrt = testValues.finalMrrt

      refreshFunction = function(entry, resource, callback) { callback(Error('FAILED REFRESH')) }

      if (!err) {
        compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt)

        cacheDriver = CacheDriver(fake_token_request['call_context'], authority, expiredEntry.resource, cp['clientId'], memCache, refreshFunction)
        cacheDriver.find(None, function(err) {
          self.assertTrue(err, 'Did not receive expected error about failed refresh.')
          self.assertTrue(-1 !== err.message.indexOf('FAILED REFRESH'), 'Error message did not contain correct text')
          compareInputAndCache(responses, memCache, numMRRTTokens, finalMrrt)
          done()
          return
        })
      } else {
        done(err)
        return
      }
    })
  })
})
'''

if __name__ == '__main__':
    unittest.main()