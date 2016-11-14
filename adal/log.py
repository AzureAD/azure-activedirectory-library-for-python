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

def create_log_context(correlation_id=None):
    return {'correlation_id' : correlation_id or str(uuid.uuid4())}

def set_logging_options(options=None):
    '''Configure adal logger, including level and handler spec'd by python
    logging module.

    Basic Usages::
        >>>adal.set_logging_options({
        >>>  'level': 'DEBUG'
        >>>  'handler': logging.FileHandler('adal.log')
        >>>})
    '''
    if options is None:
        options = {}
    logger = logging.getLogger(ADAL_LOGGER_NAME)

    logger.setLevel(options.get('level', logging.ERROR))

    handler = options.get('handler')
    if handler:
        handler.setLevel(logger.level)
        logger.addHandler(handler)

def get_logging_options():
    '''Get logging options

    :returns: a dict, with a key of 'level' for logging level.
    '''
    logger = logging.getLogger(ADAL_LOGGER_NAME)
    level = logger.getEffectiveLevel()
    return { 
        'level': logging.getLevelName(level) 
        }

class Logger(object):
    '''wrapper around python built-in logging to log correlation_id, and stack
    trace through keyword argument of 'log_stack_trace'
    '''
    def __init__(self, component_name, log_context):

        if not log_context:
            raise AttributeError('Logger: log_context is a required parameter')

        self._component_name = component_name
        self.log_context = log_context
        self._logging = logging.getLogger(ADAL_LOGGER_NAME)

    def _log_message(self, msg, log_stack_trace=None):
        correlation_id = self.log_context.get("correlation_id", 
                                              "<no correlation id>")
        
        formatted = "{} - {}:{}".format(
            correlation_id, 
            self._component_name,
            msg)
        if log_stack_trace:
            formatted += "\nStack:\n{}".format(traceback.format_stack())

        return formatted

    def warn(self, msg, *args, **kwargs):
        log_stack_trace = kwargs.pop('log_stack_trace', None)
        msg = self._log_message(msg, log_stack_trace)
        self._logging.warning(msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        log_stack_trace = kwargs.pop('log_stack_trace', None)
        msg = self._log_message(msg, log_stack_trace)
        self._logging.info(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        log_stack_trace = kwargs.pop('log_stack_trace', None)
        msg = self._log_message(msg, log_stack_trace)
        self._logging.debug(msg, *args, **kwargs)
