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

import logging
import uuid
import traceback

ADAL_LOGGER_NAME = 'adal-python'

LEVEL_STRING_MAP = {
    0: 'ERROR:',
    1: 'WARNING:',
    2: 'INFO:',
    3: 'DEBUG:'
    }

class LOGGING_LEVEL:
    ERROR = 0
    WARN = 1
    INFO = 2
    DEBUG = 3

LEVEL_PY_MAP = {
    LOGGING_LEVEL.ERROR  : 40,
    LOGGING_LEVEL.WARN   : 30,
    LOGGING_LEVEL.INFO   : 20,
    LOGGING_LEVEL.DEBUG  : 10
    }

def create_log_context(correlation_id=None):
    return {'correlation_id' : correlation_id or str(uuid.uuid4())}

def set_logging_options(options=None):
    '''
    To set level: {'level': adal.log.LOGGING_LEVEL.DEBUG}
    To add console log: { 'handler': logging.StreamHandler()}
    to add file log: {'handler': logging.FileHandler('adal.log')}
    '''
    logger = logging.getLogger(ADAL_LOGGER_NAME)

    int_level = LEVEL_PY_MAP[LOGGING_LEVEL.ERROR]
    if options.get('level'):
        level = int(options['level'])
        if level > 3 or level < 0:
            raise ValueError("set_logging_options expects the level key to be in the range 0 to 3 inclusive")
        int_level = LEVEL_PY_MAP[level]

    logger.setLevel(int_level)

    handler = options.get('handler')
    if handler:
        handler.setLevel(int_level)
        logger.addHandler(handler)

def get_logging_options():

    logger = logging.getLogger(ADAL_LOGGER_NAME)
    level = logger.getEffectiveLevel()
    for (key, val) in LEVEL_PY_MAP.items():
        if level == val:
            return {'level':key}

class Logger(object):

    def __init__(self, component_name, log_context):

        if not log_context:
            raise AttributeError('Logger: log_context is a required parameter')

        self._component_name = component_name
        self.log_context = log_context
        self._logging = logging.getLogger(ADAL_LOGGER_NAME)

    def log_message(self, level, message, error=None):

        correlation_id = self.log_context.get("correlation_id", "<no correlation id>")

        formatted = "{0} - {1}: {2} {3}".format(correlation_id, self._component_name, LEVEL_STRING_MAP[level], message)
        if error:
            formatted += "\nStack:\n{0}".format(traceback.format_stack())

        return formatted

    def error(self, message, error=None):

        message = self.log_message(0, message, error)
        self._logging.error(message)

    def warn(self, message, error=None):

        message = self.log_message(1, message, error)
        self._logging.warning(message)

    def info(self, message, error=None):

        message = self.log_message(2, message, error)
        self._logging.info(message)

    def debug(self, message, error=None):

        message = self.log_message(3, message, error)
        self._logging.debug(message)

    def create_error(self, message, error=None):
        err = Exception(message)
        self.error(err, error)
        return err
