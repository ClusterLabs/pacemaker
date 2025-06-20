"""A module providing constants relating to why a process or function exited."""

__all__ = ["ExitStatus"]
__copyright__ = "Copyright 2023-2025 the Pacemaker project contributors"
__license__ = "GNU Lesser General Public License version 2.1 or later (LGPLv2.1+)"

from enum import IntEnum, unique

from pacemaker._library import _libcrmcommon


# These values must be kept in sync with include/crm/common/results.h
@unique
class ExitStatus(IntEnum):
    """
    Exit status codes for a function or process.

    These constants describe both success and failure conditions.
    """

    OK = 0
    ERROR = 1
    INVALID_PARAM = 2
    UNIMPLEMENT_FEATURE = 3
    INSUFFICIENT_PRIV = 4
    NOT_INSTALLED = 5
    NOT_CONFIGURED = 6
    NOT_RUNNING = 7
    PROMOTED = 8
    FAILED_PROMOTED = 9
    USAGE = 64
    DATAERR = 65
    NOINPUT = 66
    NOUSER = 67
    NOHOST = 68
    UNAVAILABLE = 69
    SOFTWARE = 70
    OSERR = 71
    OSFILE = 72
    CANTCREAT = 73
    IOERR = 74
    TEMPFAIL = 75
    PROTOCOL = 76
    NOPERM = 77
    CONFIG = 78
    FATAL = 100
    PANIC = 101
    DISCONNECT = 102
    OLD = 103
    DIGEST = 104
    NOSUCH = 105
    QUORUM = 106
    UNSAFE = 107
    EXISTS = 108
    MULTIPLE = 109
    EXPIRED = 110
    NOT_YET_IN_EFFECT = 111
    INDETERMINATE = 112
    UNSATISFIED = 113
    NO_DC = 114
    TIMEOUT = 124
    DEGRADED = 190
    DEGRADED_PROMOTED = 191
    NONE = 193
    MAX = 255

    def __str__(self):
        """Given an ExitStatus, return the matching error string."""
        return _libcrmcommon.crm_exit_str(self.value).decode()
