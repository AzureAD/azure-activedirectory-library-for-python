#-------------------------------------------------------------------------
#
# Copyright Microsoft Open Technologies, Inc.
#
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http: *www.apache.org/licenses/LICENSE-2.0
#
# THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
# OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
# ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
# PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
#
# See the Apache License, Version 2.0 for the specific language
# governing permissions and limitations under the License.
#
#--------------------------------------------------------------------------

import logging
import uuid

LEVEL_STRING_MAP = {
    0: 'ERROR:',
    1: 'WARNING:',
    2: 'INFO:',
    3: 'DEBUG:'
    }

class LOGGING_LEVEL:
    ERROR   = 0
    WARN    = 1
    INFO    = 2
    DEBUG   = 3

LEVEL_PY_MAP = {
    LOGGING_LEVEL.ERROR  : 40,
    LOGGING_LEVEL.WARN   : 30,
    LOGGING_LEVEL.INFO   : 20,
    LOGGING_LEVEL.DEBUG  : 10
    }

def create_log_context(correlation_id = None):
    id = correlation_id if correlation_id else str(uuid.uuid4())
    return {'correlation_id':id}

def set_logging_options(options={}):
    logger = logging.getLogger('python_adal')

    if options.get('level'):
        level = int(options['level'])
        if level > 3 or level < 0:
            raise ValueError("set_logging_options expects the level key to be in the range 0 to 3 inclusive")

        logger.setLevel(LEVEL_PY_MAP[level])
    else:
        logger.setLevel(LEVEL_PY_MAP[LOGGING_LEVEL.ERROR])

def get_logging_options():

    logger = logging.getLogger('python_adal')
    level = logger.getEffectiveLevel()
    for (key, val) in LEVEL_PY_MAP.items():
        if level == val:
            return {'level':key}

class Logger(object):

    def __init__(self, component_name, log_context):

        if not log_context:
            raise AttributeError('Logger: log_context is a required parameter')

        self._component_name = component_name
        self._log_context = log_context
        self._logging = logging.getLogger('python_adal')

    @property
    def context(self):
        return self._log_context

    def log_message(self, level, message, error=None):

        correlation_id = self._log_context.get("correlation_id", "<no correlation id>")

        formatted = "{0} - {1}: {2} {3}".format(correlation_id, self._component_name, LEVEL_STRING_MAP[level], message)
        if error:
            formatted += "\nStack:\n{0}".format("Stack trace goes here") #TODO

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
