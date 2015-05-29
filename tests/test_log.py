import unittest
from adal.adal import logging
import json
from tests import util
from tests.util import parameters as cp

class TestLog(unittest.TestCase):
    def test_settings_none(self):
        current_options = logging.get_logging_options()
        
        logging.set_logging_options()
        
        options = logging.get_logging_options()
        logging.set_logging_options(current_options)

        noOptions = len(options) == 1 and options['level'] == 0
        self.assertTrue(noOptions, 'Did not expect to find any logging options set: ' + json.dumps(options));

    def test_console_settings(self):
        currentOptions = logging.get_logging_options()
        util.turn_on_logging()
        options = logging.get_logging_options()
        level = options['level']

        # Set the looging options back to what they were before this test so that
        # future tests are logged as they should be.
        logging.set_logging_options(currentOptions)

        self.assertEqual(level, logging.LOGGING_LEVEL.DEBUG, 'Logging level was not the expected value of LOGGING_LEVEL.DEBUG: {}'.format(level))

if __name__ == '__main__':
    unittest.main()
