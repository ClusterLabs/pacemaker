#
# Copyright 2004-2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/mk/common.mk

# Without "." here, check-recursive will run through the subdirectories first
# and then run "make check" here.  This will fail, because there's things in
# the subdirectories that need check_LTLIBRARIES built first.  Adding "." here
# changes the order so the subdirectories are processed afterwards.
SUBDIRS = . tests

## libraries
lib_LTLIBRARIES		= libpe_rules.la 	\
			  libpe_status.la
check_LTLIBRARIES 	= libpe_status_test.la

noinst_HEADERS		= pe_status_private.h

libpe_rules_la_LDFLAGS	= -version-info 30:2:4

libpe_rules_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libpe_rules_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libpe_rules_la_LIBADD	= $(top_builddir)/lib/common/libcrmcommon.la

## Library sources (*must* use += format for bumplibs)
libpe_rules_la_SOURCES	= rules.c
libpe_rules_la_SOURCES	+= rules_alerts.c

libpe_status_la_LDFLAGS	= -version-info 35:1:7

libpe_status_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libpe_status_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libpe_status_la_LIBADD	= $(top_builddir)/lib/common/libcrmcommon.la

## Library sources (*must* use += format for bumplibs)
libpe_status_la_SOURCES	=
libpe_status_la_SOURCES	+= bundle.c
libpe_status_la_SOURCES	+= clone.c
libpe_status_la_SOURCES	+= complex.c
libpe_status_la_SOURCES	+= failcounts.c
libpe_status_la_SOURCES	+= group.c
libpe_status_la_SOURCES	+= native.c
libpe_status_la_SOURCES	+= pe_actions.c
libpe_status_la_SOURCES	+= pe_health.c
libpe_status_la_SOURCES	+= pe_digest.c
libpe_status_la_SOURCES	+= pe_notif.c
libpe_status_la_SOURCES	+= pe_output.c
libpe_status_la_SOURCES	+= remote.c
libpe_status_la_SOURCES	+= rules.c
libpe_status_la_SOURCES	+= status.c
libpe_status_la_SOURCES	+= tags.c
libpe_status_la_SOURCES	+= unpack.c
libpe_status_la_SOURCES	+= utils.c

#
# libpe_status_test is only used with unit tests, so we can
# mock system calls.  See lib/common/mock.c for details.
#

include $(top_srcdir)/mk/tap.mk

libpe_status_test_la_SOURCES = $(libpe_status_la_SOURCES)
libpe_status_test_la_LDFLAGS = $(libpe_status_la_LDFLAGS) 	\
			       -rpath $(libdir) 		\
			       $(LDFLAGS_WRAP)
# See comments on libcrmcommon_test_la in lib/common/Makefile.am regarding these flags.
libpe_status_test_la_CFLAGS = $(libpe_status_la_CFLAGS) \
			      -DPCMK__UNIT_TESTING 	\
			      -fno-builtin 		\
			      -fno-inline
libpe_status_test_la_LIBADD = $(top_builddir)/lib/common/libcrmcommon_test.la 	\
			      -lcmocka 						\
			      -lm
