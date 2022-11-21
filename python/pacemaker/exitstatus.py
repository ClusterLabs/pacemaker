# Copyright 2004-2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU Lesser General Public License
# version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.

__all__ = ["ExitStatus"]

from enum import IntEnum, unique

# These values must be kept in sync with include/crm/common/results.h
@unique
class ExitStatus(IntEnum):
    OK                   =   0
    ERROR                =   1
    INVALID_PARAM        =   2
    UNIMPLEMENT_FEATURE  =   3
    INSUFFICIENT_PRIV    =   4
    NOT_INSTALLED        =   5
    NOT_CONFIGURED       =   6
    NOT_RUNNING          =   7
    PROMOTED             =   8
    FAILED_PROMOTED      =   9
    USAGE                =  64
    DATAERR              =  65
    NOINPUT              =  66
    NOUSER               =  67
    NOHOST               =  68
    UNAVAILABLE          =  69
    SOFTWARE             =  70
    OSERR                =  71
    OSFILE               =  72
    CANTCREAT            =  73
    IOERR                =  74
    TEMPFAIL             =  75
    PROTOCOL             =  76
    NOPERM               =  77
    CONFIG               =  78
    FATAL                = 100
    PANIC                = 101
    DISCONNECT           = 102
    OLD                  = 103
    DIGEST               = 104
    NOSUCH               = 105
    QUORUM               = 106
    UNSAFE               = 107
    EXISTS               = 108
    MULTIPLE             = 109
    EXPIRED              = 110
    NOT_YET_IN_EFFECT    = 111
    INDETERMINATE        = 112
    UNSATISFIED          = 113
    TIMEOUT              = 124
    DEGRADED             = 190
    DEGRADED_PROMOTED    = 191
    NONE                 = 193
    MAX                  = 255
