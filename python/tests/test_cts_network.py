# These warnings are not useful in unit tests.
# pylint: disable=missing-class-docstring,missing-function-docstring,missing-module-docstring

__copyright__ = "Copyright 2023 the Pacemaker project contributors"
__license__ = "GPLv2+"

import unittest

from pacemaker._cts.network import next_ip

# next_ip makes a bunch of assumptions that we are not going to test here:
#
# * The env argument actually contains an "IPBase" key with a string in it
# * The string is a properly formatted IPv4 or IPv6 address, with no extra
#   leading or trailing whitespace

class NextIPTestCase(unittest.TestCase):
    def test_ipv4(self):
        # The first time next_ip is called, it will read the IPBase out of
        # the environment.  After that, it just goes off whatever it
        # previously returned, so the environment value doesn't matter.
        self.assertEqual(next_ip("1.1.1.1"), "1.1.1.2")
        self.assertEqual(next_ip(), "1.1.1.3")

        # Passing reset=True will force it to re-read the environment.  Here,
        # we use that to ask it for a value outside of the available range.
        self.assertRaises(ValueError, next_ip, "1.1.1.255", reset=True)

    def test_ipv6(self):
        # Same comments as for the test_ipv4 function, plus we need to reset
        # here because otherwise it will remember what happened in that function.
        self.assertEqual(next_ip("fe80::fc54:ff:fe09:101", reset=True),
                         "fe80::fc54:ff:fe09:102")
        self.assertEqual(next_ip(),
                         "fe80::fc54:ff:fe09:103")

        self.assertRaises(ValueError, next_ip, "fe80::fc54:ff:fe09:ffff", reset=True)
