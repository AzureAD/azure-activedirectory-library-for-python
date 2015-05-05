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

import sys
import os

if sys.version_info[:2] < (2, 7, ):
    try:
        import unittest2
        from unittest2 import TestLoader, TextTestRunner

    except ImportError:
        raise ImportError("The BatchApps Python Client test suite requires "
                          "the unittest2 package to run on Python 2.6 and "
                          "below.\nPlease install this package to continue.")
else:
    import unittest
    from unittest import TestLoader, TextTestRunner

if sys.version_info[:2] >= (3, 3, ):
    from unittest import mock
else:
    try:
        import mock

    except ImportError:
        raise ImportError("The BatchApps Python Client test suite requires "
                          "the mock package to run on Python 3.2 and below.\n"
                          "Please install this package to continue.")


if __name__ == '__main__':

    runner = TextTestRunner(verbosity=2)

    test_dir = os.path.dirname(__file__)
    top_dir = os.path.dirname(os.path.dirname(test_dir))
    test_loader = TestLoader()
    suite = test_loader.discover(test_dir,
                                 pattern="unittest_*.py",
                                 top_level_dir=top_dir)
    runner.run(suite)
