#
# Copyright 2004-2026 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/mk/common.mk

## libraries
lib_LTLIBRARIES	= libcrmcommon.la
check_LTLIBRARIES = libcrmcommon_test.la

# Disable -Wcast-qual if used, because we do some hacky casting,
# and because libxml2 has some signatures that should be const but aren't
# for backward compatibility reasons.

# s390 needs -fPIC 
# s390-suse-linux/bin/ld: .libs/ipc.o: relocation R_390_PC32DBL against `__stack_chk_fail@@GLIBC_2.4' can not be used when making a shared object; recompile with -fPIC

CFLAGS		= $(CFLAGS_COPY:-Wcast-qual=) -fPIC

# Without "." here, check-recursive will run through the subdirectories first
# and then run "make check" here.  This will fail, because there's things in
# the subdirectories that need check_LTLIBRARIES built first.  Adding "." here
# changes the order so the subdirectories are processed afterwards.
SUBDIRS = . tests

noinst_HEADERS = crmcommon_private.h
noinst_HEADERS += mock_private.h

libcrmcommon_la_LDFLAGS	= -version-info 69:0:1

libcrmcommon_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libcrmcommon_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

# If configured with --with-profiling or --with-coverage, BUILD_PROFILING will
# be set and -fno-builtin will be added to the CFLAGS.  However, libcrmcommon
# uses the fabs() function which is normally supplied by gcc as one of its
# builtins.  Therefore we need to explicitly link against libm here or the
# tests won't link.
if BUILD_PROFILING
libcrmcommon_la_LIBADD	= -lm
endif

## Library sources (*must* use += format for bumplibs)
libcrmcommon_la_SOURCES	= acl.c
libcrmcommon_la_SOURCES	+= action_relation.c
libcrmcommon_la_SOURCES	+= actions.c
libcrmcommon_la_SOURCES	+= agents.c
libcrmcommon_la_SOURCES	+= alerts.c
libcrmcommon_la_SOURCES	+= attrs.c
libcrmcommon_la_SOURCES	+= cib.c
if BUILD_CIBSECRETS
libcrmcommon_la_SOURCES	+= cib_secrets.c
endif
libcrmcommon_la_SOURCES	+= cmdline.c
libcrmcommon_la_SOURCES	+= digest.c
libcrmcommon_la_SOURCES	+= health.c
libcrmcommon_la_SOURCES	+= io.c
libcrmcommon_la_SOURCES	+= ipc_attrd.c
libcrmcommon_la_SOURCES	+= ipc_client.c
libcrmcommon_la_SOURCES	+= ipc_common.c
libcrmcommon_la_SOURCES	+= ipc_controld.c
libcrmcommon_la_SOURCES	+= ipc_pacemakerd.c
libcrmcommon_la_SOURCES	+= ipc_schedulerd.c
libcrmcommon_la_SOURCES	+= ipc_server.c
libcrmcommon_la_SOURCES	+= iso8601.c
libcrmcommon_la_SOURCES	+= lists.c
libcrmcommon_la_SOURCES	+= location.c
libcrmcommon_la_SOURCES	+= logging.c
libcrmcommon_la_SOURCES	+= mainloop.c
libcrmcommon_la_SOURCES	+= messages.c
libcrmcommon_la_SOURCES	+= nodes.c
libcrmcommon_la_SOURCES	+= nvpair.c
libcrmcommon_la_SOURCES	+= options.c
libcrmcommon_la_SOURCES	+= options_display.c
libcrmcommon_la_SOURCES	+= output.c
libcrmcommon_la_SOURCES	+= output_html.c
libcrmcommon_la_SOURCES	+= output_log.c
libcrmcommon_la_SOURCES	+= output_none.c
libcrmcommon_la_SOURCES	+= output_text.c
libcrmcommon_la_SOURCES	+= output_xml.c
libcrmcommon_la_SOURCES	+= patchset.c
libcrmcommon_la_SOURCES	+= patchset_display.c
libcrmcommon_la_SOURCES	+= pid.c
libcrmcommon_la_SOURCES	+= probes.c
libcrmcommon_la_SOURCES	+= procfs.c
libcrmcommon_la_SOURCES	+= remote.c
libcrmcommon_la_SOURCES	+= resources.c
libcrmcommon_la_SOURCES	+= results.c
libcrmcommon_la_SOURCES	+= roles.c
libcrmcommon_la_SOURCES	+= rules.c
libcrmcommon_la_SOURCES	+= scheduler.c
libcrmcommon_la_SOURCES	+= schemas.c
libcrmcommon_la_SOURCES	+= scores.c
libcrmcommon_la_SOURCES	+= servers.c
libcrmcommon_la_SOURCES	+= strings.c
libcrmcommon_la_SOURCES	+= tls.c
libcrmcommon_la_SOURCES	+= utils.c
libcrmcommon_la_SOURCES	+= watchdog.c
libcrmcommon_la_SOURCES	+= xml.c
libcrmcommon_la_SOURCES	+= xml_attr.c
libcrmcommon_la_SOURCES	+= xml_comment.c
libcrmcommon_la_SOURCES	+= xml_display.c
libcrmcommon_la_SOURCES	+= xml_element.c
libcrmcommon_la_SOURCES	+= xml_idref.c
libcrmcommon_la_SOURCES	+= xml_io.c
libcrmcommon_la_SOURCES	+= xml_tracking.c
libcrmcommon_la_SOURCES	+= xpath.c

#
# libcrmcommon_test is used only with unit tests, so we can mock system calls.
# See mock.c for details.
#

include $(top_srcdir)/mk/tap.mk

libcrmcommon_test_la_SOURCES	= $(libcrmcommon_la_SOURCES)
libcrmcommon_test_la_SOURCES	+= mock.c
libcrmcommon_test_la_SOURCES	+= unittest.c

libcrmcommon_test_la_LDFLAGS = $(libcrmcommon_la_LDFLAGS)
libcrmcommon_test_la_LDFLAGS += -rpath $(libdir)
libcrmcommon_test_la_LDFLAGS += $(LDFLAGS_WRAP)

# If GCC emits a builtin function in place of something we've mocked up, that will
# get used instead of the mocked version which leads to unexpected test results.  So
# disable all builtins.  Older versions of GCC (at least, on RHEL7) will still emit
# replacement code for strdup (and possibly other functions) unless -fno-inline is
# also added.
libcrmcommon_test_la_CFLAGS = $(libcrmcommon_la_CFLAGS)
libcrmcommon_test_la_CFLAGS += -DPCMK__UNIT_TESTING
libcrmcommon_test_la_CFLAGS += -fno-builtin
libcrmcommon_test_la_CFLAGS += -fno-inline

# If -fno-builtin is used, -lm also needs to be added.  See the comment at
# BUILD_PROFILING above.
libcrmcommon_test_la_LIBADD	= $(libcrmcommon_la_LIBADD)
if BUILD_COVERAGE
libcrmcommon_test_la_LIBADD 	+= -lgcov
endif
libcrmcommon_test_la_LIBADD 	+= -lcmocka
libcrmcommon_test_la_LIBADD 	+= -lm

nodist_libcrmcommon_test_la_SOURCES = $(nodist_libcrmcommon_la_SOURCES)
