#
# Copyright 2004-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/mk/common.mk

SUBDIRS = tests

## libraries
lib_LTLIBRARIES		= libpe_rules.la libpe_status.la

## SOURCES
noinst_HEADERS		= variant.h pe_status_private.h

libpe_rules_la_LDFLAGS	= -version-info 29:1:3

libpe_rules_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libpe_rules_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libpe_rules_la_LIBADD	= $(top_builddir)/lib/common/libcrmcommon.la
libpe_rules_la_SOURCES	= rules.c rules_alerts.c common.c

libpe_status_la_LDFLAGS	= -version-info 32:2:4

libpe_status_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libpe_status_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libpe_status_la_LIBADD	= $(top_builddir)/lib/common/libcrmcommon.la
# Use += rather than backlashed continuation lines for parsing by bumplibs
libpe_status_la_SOURCES	=
libpe_status_la_SOURCES	+= bundle.c
libpe_status_la_SOURCES	+= clone.c
libpe_status_la_SOURCES	+= common.c
libpe_status_la_SOURCES	+= complex.c
libpe_status_la_SOURCES	+= failcounts.c
libpe_status_la_SOURCES	+= group.c
libpe_status_la_SOURCES	+= native.c
libpe_status_la_SOURCES	+= pe_digest.c
libpe_status_la_SOURCES	+= remote.c
libpe_status_la_SOURCES	+= rules.c
libpe_status_la_SOURCES	+= status.c
libpe_status_la_SOURCES	+= tags.c
libpe_status_la_SOURCES	+= unpack.c
libpe_status_la_SOURCES	+= utils.c
libpe_status_la_SOURCES	+= pe_output.c

clean-generic:
	rm -f *.log *.debug *~
