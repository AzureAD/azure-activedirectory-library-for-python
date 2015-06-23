import unittest
from adal import log
import json
from tests import util
from tests.util import parameters as cp

class TestLog(unittest.TestCase):
    def test_settings_none(self):
        current_options = log.get_logging_options()
        
        log.set_logging_options()
        
        options = log.get_logging_options()
        log.set_logging_options(current_options)

        noOptions = len(options) == 1 and options['level'] == 0
        self.assertTrue(noOptions, 'Did not expect to find any logging options set: ' + json.dumps(options));

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
