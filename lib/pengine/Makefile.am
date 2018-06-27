#
# Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/Makefile.common

## libraries
lib_LTLIBRARIES		= libpe_rules.la libpe_status.la

## SOURCES
noinst_HEADERS		= unpack.h variant.h

libpe_rules_la_LDFLAGS	= -version-info 26:0:0

libpe_rules_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libpe_rules_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libpe_rules_la_LIBADD	= $(top_builddir)/lib/common/libcrmcommon.la
libpe_rules_la_SOURCES	= rules.c rules_alerts.c common.c

libpe_status_la_LDFLAGS	= -version-info 27:0:0

libpe_status_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libpe_status_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libpe_status_la_LIBADD	= @CURSESLIBS@ $(top_builddir)/lib/common/libcrmcommon.la
libpe_status_la_SOURCES	= status.c unpack.c utils.c complex.c native.c container.c \
			group.c clone.c rules.c common.c failcounts.c remote.c

clean-generic:
	rm -f *.log *.debug *~
