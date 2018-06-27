#
# Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/Makefile.common

## libraries
lib_LTLIBRARIES			= libtransitioner.la

## SOURCES

libtransitioner_la_LDFLAGS	= -version-info 25:0:0
libtransitioner_la_CPPFLAGS	= -I$(top_builddir) $(AM_CPPFLAGS)

libtransitioner_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libtransitioner_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libtransitioner_la_LIBADD	= $(top_builddir)/lib/common/libcrmcommon.la
libtransitioner_la_SOURCES	= unpack.c graph.c utils.c

clean-generic:
	rm -f *~
