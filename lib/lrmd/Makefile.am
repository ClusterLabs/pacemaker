#
# Copyright 2012-2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU Lesser General Public License
# version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/mk/common.mk

lib_LTLIBRARIES		= liblrmd.la

liblrmd_la_LDFLAGS	= -version-info 31:0:3

liblrmd_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
liblrmd_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

liblrmd_la_LIBADD = $(top_builddir)/lib/fencing/libstonithd.la
liblrmd_la_LIBADD += $(top_builddir)/lib/services/libcrmservice.la
liblrmd_la_LIBADD += $(top_builddir)/lib/common/libcrmcommon.la

## Library sources (*must* use += format for bumplibs)
liblrmd_la_SOURCES	= lrmd_alerts.c 
liblrmd_la_SOURCES	+= lrmd_client.c
liblrmd_la_SOURCES	+= lrmd_output.c
liblrmd_la_SOURCES	+= proxy_common.c
