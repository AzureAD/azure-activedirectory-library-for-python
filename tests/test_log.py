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
import json
import unittest
from adal import log
from tests import util
from tests.util import parameters as cp

class TestLog(unittest.TestCase):
    def test_settings_none(self):
        current_options = log.get_logging_options()

        log.set_logging_options()

        options = log.get_logging_options()
        log.set_logging_options(current_options)

        noOptions = len(options) == 1 and options['level'] == 0
        self.assertTrue(noOptions, 'Did not expect to find any logging options set: ' + json.dumps(options))

    def test_console_settings(self):
        currentOptions = log.get_logging_options()
        util.turn_on_logging()
        options = log.get_logging_options()
        level = options['level']

        # Set the looging options back to what they were before this test so that
        # future tests are logged as they should be.
        log.set_logging_options(currentOptions)

        self.assertEqual(level, log.LOGGING_LEVEL.DEBUG, 'Logging level was not the expected value of LOGGING_LEVEL.DEBUG: {}'.format(level))

if __name__ == '__main__':
    unittest.main()
