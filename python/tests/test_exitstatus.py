# These warnings are not useful in unit tests.
# pylint: disable=missing-class-docstring,missing-function-docstring,missing-module-docstring

__copyright__ = "Copyright 2023 the Pacemaker project contributors"
__license__ = "GPLv2+"

import unittest

from pacemaker.exitstatus import ExitStatus

class ExitStatusTestCase(unittest.TestCase):
    def test_min_max(self):
        self.assertEqual(ExitStatus.OK, 0)
        self.assertEqual(ExitStatus.MAX, 255)
