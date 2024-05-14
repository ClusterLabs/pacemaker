#
# Copyright 2004-2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/mk/common.mk

## libraries
lib_LTLIBRARIES		= libcib.la

## Library sources (*must* use += format for bumplibs)
libcib_la_SOURCES	= cib_attrs.c
libcib_la_SOURCES	+= cib_client.c
libcib_la_SOURCES	+= cib_file.c
libcib_la_SOURCES	+= cib_native.c
libcib_la_SOURCES	+= cib_ops.c
libcib_la_SOURCES	+= cib_remote.c
libcib_la_SOURCES	+= cib_utils.c

libcib_la_LDFLAGS	= -version-info 33:0:6
libcib_la_CPPFLAGS	= -I$(top_srcdir) $(AM_CPPFLAGS)

libcib_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libcib_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libcib_la_LIBADD = $(top_builddir)/lib/pengine/libpe_rules.la \
		   $(top_builddir)/lib/common/libcrmcommon.la
