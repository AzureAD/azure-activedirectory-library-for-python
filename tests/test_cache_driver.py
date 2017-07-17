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

import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from adal.log import create_log_context
from adal.cache_driver import CacheDriver


class TestCacheDriver(unittest.TestCase):
    def test_rt_less_item_wont_cause_exception(self):  # Github issue #82
        rt_less_entry_came_from_previous_client_credentials_grant = {
            "expiresIn": 3600,
            "_authority": "https://login.microsoftonline.com/foo",
            "resource": "spn:00000002-0000-0000-c000-000000000000",
            "tokenType": "Bearer",
            "expiresOn": "1999-05-22 16:31:46.202000",
            "isMRRT": True,
            "_clientId": "client_id",
            "accessToken": "this is an AT",
            }
        refresh_function = mock.MagicMock(return_value={})
        cache_driver = CacheDriver(
            {"log_context": create_log_context()}, "authority", "resource",
            "client_id", mock.MagicMock(), refresh_function)
        entry = cache_driver._refresh_entry_if_necessary(
            rt_less_entry_came_from_previous_client_credentials_grant, False)
        refresh_function.assert_not_called()  # Otherwise it will cause an exception
        self.assertIsNone(entry)

