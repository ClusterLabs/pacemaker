#
# Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/Makefile.common

## libraries
lib_LTLIBRARIES		= libcib.la

## SOURCES
libcib_la_SOURCES	= cib_ops.c cib_utils.c cib_client.c cib_native.c cib_attrs.c
libcib_la_SOURCES	+= cib_file.c cib_remote.c

libcib_la_LDFLAGS	= -version-info 27:0:0
libcib_la_CPPFLAGS	= -I$(top_srcdir) $(AM_CPPFLAGS)

libcib_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libcib_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libcib_la_LIBADD	= $(top_builddir)/lib/pengine/libpe_rules.la \
			  $(top_builddir)/lib/common/libcrmcommon.la

clean-generic:
	rm -f *.log *.debug *.xml *~
