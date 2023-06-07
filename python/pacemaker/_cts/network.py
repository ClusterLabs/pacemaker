""" Network related utilities for CTS """

__all__ = ["next_ip"]
__copyright__ = "Copyright 2000-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

# pylint: disable=global-statement
CURRENT_IP = None

def next_ip(ip_base=None, reset=False):
    """ Return the next available IP address.

        Arguments:

        ip_base -- The initial IP address to start from.  The first call to next_ip
                   will return the next IP address from this base.  Each subsequent
                   call will return the next address from the previous call, so you
                   can just omit this argument for subsequent calls.
        reset   -- Force next_ip to start from ip_base again.  This requires also
                   passing the ip_base argument.  (Mostly useful for unit testing,
                   but may be useful elsewhere).

        This function only increments the last portion of the IP address.  Once it
        has hit the upper limit, ValueError will be raised.
    """

    global CURRENT_IP

    if CURRENT_IP is None or reset:
        CURRENT_IP = ip_base

    new_ip = None

    # Split the existing IP address up into a tuple of:
    # (everything except the last part of the addr, the separator, the last part of the addr).
    # For instance, "192.168.1.2" becomes ("192.168.1", ".", "2").  Then,
    # increment the last part of the address and paste everything back
    # together.
    if ":" in CURRENT_IP:
        # This is an IPv6 address
        fields = CURRENT_IP.rpartition(":")
        new_ip = int(fields[2], 16) + 1

        if new_ip > 0xffff:
            raise ValueError("No more available IP addresses")

        # hex() puts "0x" at the front of the string, so strip it off.
        new_ip = hex(new_ip)[2:]

    else:
        # This is an IPv4 address
        fields = CURRENT_IP.rpartition(".")
        new_ip = int(fields[2]) + 1

        if new_ip > 255:
            raise ValueError("No more available IP addresses")

    CURRENT_IP = "%s%s%s" % (fields[0], fields[1], new_ip)
    return CURRENT_IP
