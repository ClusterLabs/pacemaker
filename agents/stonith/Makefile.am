#
# Copyright 2003-2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk
include $(top_srcdir)/mk/man.mk

sbin_SCRIPTS	= fence_watchdog

if BUILD_LHA_SUPPORT
sbin_SCRIPTS 	+= fence_legacy
endif

CLEANFILES = $(man7_MANS) $(man8_MANS)
