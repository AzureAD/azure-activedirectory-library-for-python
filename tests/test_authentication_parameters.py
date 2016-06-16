#------------------------------------------------------------------------------
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

import sys
import requests
import httpretty

try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    from unittest import mock
except ImportError:
    import mock

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

import adal
from tests import util
from tests.util import parameters as cp

class TestAuthenticationParameters(unittest.TestCase):

    def setUp(self):
        testHost = 'https://this.is.my.domain.com'
        testPath = '/path/to/resource'
        testQuery = 'a=query&string=really'
        self.testUrl = testHost + testPath + '?' + testQuery
        return super(TestAuthenticationParameters, self).setUp()

    def run_data(self, test_data, test_func):

        for index, test_case in enumerate(test_data):
            parameters = None
            error = None
            test_input = test_case[0]
            test_params = test_case[1]

            try:
                parameters = test_func(test_input)
            except Exception as exp:
                error = exp

            prefix = "Test case: {0} - ".format(index)
            if test_params:
                self.assertIsNone(error, "{0}Parse failed but should have succeeded. {1}".format(prefix, error))
                self.assertEqual(parameters.authorization_uri, test_params.get('authorizationUri'),
                                 "{0}Parsed authorizationUri did not match expected value.: {1}".format(prefix, parameters.authorization_uri))
                self.assertEqual(parameters.resource, test_params.get('resource'),
                                 "{0}Parsed resource  did not match expected value.: {1}".format(prefix, parameters.resource))
            else:
                self.assertIsNotNone(error, "{0}Parse succeeded but should have failed.".format(prefix))


    def test_create_from_header(self):

        test_data = [
          [
            'Bearer authorization_uri="foobar,lkfj,;l,", fruitcake="f",resource="clark, &^()- q32,shark" , f="foo"',
            {
              'authorizationUri' : 'foobar,lkfj,;l,',
              'resource' : 'clark, &^()- q32,shark',
            }
          ],
          [
            'Bearer  resource="clark, &^()- q32,shark", authorization_uri="foobar,lkfj,;l,"',
            {
              'authorizationUri' : 'foobar,lkfj,;l,',
              'resource' : 'clark, &^()- q32,shark',
            }
          ],
          [
            'Bearer authorization_uri="' + cp['authorityTenant'] + '", resource="' + cp['resource'] + '"',
            {
              'authorizationUri' : cp['authorityTenant'],
              'resource' : cp['resource'],
            }
          ],
          [
            'Bearer authorization_uri="' + cp['authorizeUrl'] + '", resource="' + cp['resource'] + '"',
            {
              'authorizationUri' : cp['authorizeUrl'],
              'resource' : cp['resource'],
            }
          ],
          # Add second = sign on first pair.
          [
            'Bearer authorization_uri=="foobar,lkfj,;l,", resource="clark, &^()- q32,shark",fruitcake="f" , f="foo"',
            None
          ],
          # Add second = sign on second pair.
          [
            'Bearer authorization_uri="foobar,lkfj,;l,", resource=="clark, &^()- q32,shark",fruitcake="f" , f="foo"',
            None
          ],
          # Add second quote on first pair.
          [
            'Bearer authorization_uri=""foobar,lkfj,;l,", resource="clark, &^()- q32,shark",fruitcake="f" , f="foo"',
            None
          ],
          # Add second quote on second pair.
          [
            'Bearer authorization_uri=foobar,lkfj,;l,", resource="clark, &^()- q32,shark"",fruitcake="f" , f="foo"',
            None
          ],
          # Add trailing quote.
          [
            'Bearer authorization_uri=foobar,lkfj,;l,", resource="clark, &^()- q32,shark",fruitcake="f" , f="foo""',
            None
          ],
          # Add trailing comma at end of string.
          [
            'Bearer authorization_uri=foobar,lkfj,;l,", resource="clark, &^()- q32,shark",fruitcake="f" , f="foo",',
            None
          ],
          # Add second comma between 2 and 3 pairs.
          [
            'Bearer authorization_uri=foobar,lkfj,;l,", resource="clark, &^()- q32,shark",fruitcake="f" ,, f="foo"',
            None
          ],
          # Add second comma between 1 and 2 pairs.
          [
            'Bearer authorization_uri=foobar,lkfj,;l,", , resource="clark, &^()- q32,shark",fruitcake="f" , f="foo"',
            None
          ],
          # Add random letter between Bearer and first pair.
          [
            'Bearer  f authorization_uri=foobar,lkfj,;l,", resource="clark, &^()- q32,shark",fruitcake="f" , f="foo"',
            None
          ],
          # Add random letter between 2 and 3 pair.
          [
            'Bearer  authorization_uri=foobar,lkfj,;l,", a resource="clark, &^()- q32,shark",fruitcake="f" , f="foo"',
            None
          ],
          # Add random letter between 3 and 2 pair.
          [
            'Bearer  authorization_uri=foobar,lkfj,;l,", resource="clark, &^()- q32,shark",fruitcake="f" a, f="foo"',
            None
          ],
          # Mispell Bearer
          [
            'Berer authorization_uri=foobar,lkfj,;l,", resource="clark, &^()- q32,shark",fruitcake="f" , f="foo"',
            None
          ],
          # Missing resource.
          [
            'Bearer authorization_uri="foobar,lkfj,;l,"',
            {
              'authorizationUri' : 'foobar,lkfj,;l,'
            }
          ],
          # Missing authoritzation uri.
          [
            'Bearer resource="clark, &^()- q32,shark",fruitcake="f" , f="foo"',
            None
          ],
          # Boris's test.
          [
            'Bearer foo="bar" ANYTHING HERE, ANYTHING PRESENT HERE, foo1="bar1"',
            None
          ],
          [
            'Bearerauthorization_uri="authuri", resource="resourceHere"',
            None
          ],
        ]
        self.run_data(test_data, adal.authentication_parameters.create_authentication_parameters_from_header)

    def test_create_from_response(self):

        test_data = [
          [
            mock.Mock(status_code=401, headers={ 'www-authenticate' : 'Bearer authorization_uri="foobar,lkfj,;l,", fruitcake="f",resource="clark, &^()- q32,shark" , f="foo"' }),
            {
              'authorizationUri' : 'foobar,lkfj,;l,',
              'resource' : 'clark, &^()- q32,shark',
            }
          ],
          [
            mock.Mock(status_code=200, headers={ 'www-authenticate' : 'Bearer authorization_uri="foobar,lkfj,;l,", fruitcake="f",resource="clark, &^()- q32,shark" , f="foo"' }),
            None
          ],
          [
            mock.Mock(status_code=401),
            None
          ],
          [
            mock.Mock(status_code=401, headers={ 'foo' : 'this is not the www-authenticate header' }),
            None
          ],
          [
            mock.Mock(status_code=401, headers={ 'www-authenticate' : 'Berer authorization_uri=foobar,lkfj,;l,", resource="clark, &^()- q32,shark",fruitcake="f" , f="foo"' }),
            None
          ],
          [
            mock.Mock(status_code=401, headers={ 'www-authenticate' : None }),
            None
          ],
          [
            mock.Mock(headers={ 'www-authenticate' : None }),
            None
          ],
          [
            None,
            None
          ]
        ]

        self.run_data(test_data, adal.authentication_parameters.create_authentication_parameters_from_response)

    @httpretty.activate
    def test_create_from_url_happy_string_url(self):

        httpretty.register_uri(httpretty.GET, uri=self.testUrl, body='foo', status=401, **{'www-authenticate':'Bearer authorization_uri="foobar,lkfj,;l,", fruitcake="f",resource="clark, &^()- q32,shark" , f="foo"'})

        # maybe try-catch here to catch the error
        parameters = adal.authentication_parameters.create_authentication_parameters_from_url(self.testUrl)

        test_params = {
            'authorizationUri' : 'foobar,lkfj,;l,',
            'resource' : 'clark, &^()- q32,shark',
        }
        self.assertEqual(parameters.authorization_uri, test_params['authorizationUri'],
                            'Parsed authorizationUri did not match expected value.: {0}'.format(parameters.authorization_uri))
        self.assertEqual(parameters.resource, test_params['resource'],
                            'Parsed resource  did not match expected value.: {0}'.format(parameters.resource))

        req = httpretty.last_request()
        util.match_standard_request_headers(req)

    @httpretty.activate
    def test_create_from_url_happy_path_url_object(self):

        httpretty.register_uri(httpretty.GET, uri=self.testUrl, body='foo', status=401, **{'www-authenticate':'Bearer authorization_uri="foobar,lkfj,;l,", fruitcake="f",resource="clark, &^()- q32,shark" , f="foo"'})

        url_obj = urlparse(self.testUrl)

        try:
            parameters = adal.authentication_parameters.create_authentication_parameters_from_url(url_obj)
            test_params = {
                'authorizationUri' : 'foobar,lkfj,;l,',
                'resource' : 'clark, &^()- q32,shark',
            }
            self.assertEqual(parameters.authorization_uri, test_params['authorizationUri'],
                                'Parsed authorizationUri did not match expected value.: {0}'.format(parameters.authorization_uri))
            self.assertEqual(parameters.resource, test_params['resource'],
                                'Parsed resource  did not match expected value.: {0}'.format(parameters.resource))

        except Exception as err:
            self.assertIsNone(err, "An error was raised during function {0}".format(err))

        req = httpretty.last_request()
        util.match_standard_request_headers(req)

    def test_create_from_url_bad_object(self):

        try:
            parameters = adal.authentication_parameters.create_authentication_parameters_from_url({})
        except Exception as exp:
            self.assertIsNotNone(exp, "Did not receive expected error.")
            pass

    def test_create_from_url_not_passed(self):

        try:
            parameters = adal.authentication_parameters.create_authentication_parameters_from_url(None)
        except Exception as exp:
            self.assertIsNotNone(exp, "Did not receive expected error.")
            pass

    @httpretty.activate
    def test_create_from_url_no_header(self):

        httpretty.register_uri(httpretty.GET, uri=self.testUrl, body='foo', status=401)

        receivedException = False
        try:
            adal.authentication_parameters.create_authentication_parameters_from_url(self.testUrl)
        except Exception as err:
            receivedException = True
            self.assertTrue(str(err).find('header') >= 0, 'Error did not include message about missing header')
            pass
        finally:
            self.assertTrue(receivedException)

        req = httpretty.last_request()
        util.match_standard_request_headers(req)

    def test_create_from_url_network_error(self):

        try:
            adal.authentication_parameters.create_authentication_parameters_from_url('https://0.0.0.0/foobar')
        except Exception as err:
            self.assertIsNotNone(err, "Did not receive expected error.")

if __name__ == '__main__':
    unittest.main()
