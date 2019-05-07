#
# Copyright 2004-2019 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/Makefile.common

# everything fetched from CFLAGS_COPY, we don't want to replicate
CFLAGS          =

AM_CPPFLAGS		+= -I$(top_builddir)/lib/gnu -I$(top_srcdir)/lib/gnu -DPCMK_SCHEMAS_EMERGENCY_XSLT=0

## libraries
lib_LTLIBRARIES	= libcrmcommon.la

# Disable -Wcast-qual if used, because we do some hacky casting,
# and because libxml2 has some signatures that should be const but aren't
# for backward compatibility reasons.

# s390 needs -fPIC 
# s390-suse-linux/bin/ld: .libs/ipc.o: relocation R_390_PC32DBL against `__stack_chk_fail@@GLIBC_2.4' can not be used when making a shared object; recompile with -fPIC

noinst_HEADERS		= crmcommon_private.h

libcrmcommon_la_LDFLAGS	= -version-info 36:0:2

libcrmcommon_la_CFLAGS	= $(CFLAGS_HARDENED_LIB) $(CFLAGS_COPY:-Wcast-qual=) -fPIC
libcrmcommon_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libcrmcommon_la_LIBADD	= @LIBADD_DL@ $(GNUTLSLIBS) $(top_builddir)/lib/gnu/libgnu.la
if BUILD_DATE_VERSATILITY
libcrmcommon_la_LIBADD	+= libgnu-parse-datetime.la
endif

# Use += rather than backlashed continuation lines for parsing by bumplibs.sh
libcrmcommon_la_SOURCES	=
libcrmcommon_la_SOURCES	+= acl.c
libcrmcommon_la_SOURCES	+= agents.c
libcrmcommon_la_SOURCES	+= alerts.c
libcrmcommon_la_SOURCES	+= attrd_client.c
if BUILD_CIBSECRETS
libcrmcommon_la_SOURCES	+= cib_secrets.c
endif
libcrmcommon_la_SOURCES	+= compat.c
libcrmcommon_la_SOURCES	+= digest.c
libcrmcommon_la_SOURCES	+= io.c
libcrmcommon_la_SOURCES	+= ipc.c
libcrmcommon_la_SOURCES	+= iso8601.c
libcrmcommon_la_SOURCES	+= logging.c
libcrmcommon_la_SOURCES	+= mainloop.c
libcrmcommon_la_SOURCES	+= nvpair.c
libcrmcommon_la_SOURCES	+= operations.c
libcrmcommon_la_SOURCES	+= output.c
libcrmcommon_la_SOURCES	+= output_text.c
libcrmcommon_la_SOURCES	+= output_xml.c
libcrmcommon_la_SOURCES	+= pid.c
libcrmcommon_la_SOURCES	+= procfs.c
libcrmcommon_la_SOURCES	+= remote.c
libcrmcommon_la_SOURCES	+= results.c
libcrmcommon_la_SOURCES	+= schemas.c
libcrmcommon_la_SOURCES	+= strings.c
libcrmcommon_la_SOURCES	+= utils.c
libcrmcommon_la_SOURCES	+= watchdog.c
libcrmcommon_la_SOURCES	+= xml.c
libcrmcommon_la_SOURCES	+= xpath.c

noinst_LTLIBRARIES =
EXTRA_DIST =

if BUILD_DATE_VERSATILITY
noinst_LTLIBRARIES += libgnu-parse-datetime.la
# Gnulib doesn't care much about some warning classes
libgnu_parse_datetime_la_CFLAGS	= $(CFLAGS_COPY)
libgnu_parse_datetime_la_CFLAGS	+= -Wno-declaration-after-statement
libgnu_parse_datetime_la_CFLAGS	+= -Wno-missing-prototypes
libgnu_parse_datetime_la_CFLAGS	+= -Wno-missing-declarations
libgnu_parse_datetime_la_CFLAGS	+= -Wno-format-nonliteral
# XXX following one seems necessary only for FreeBSD/*86
# /parse-datetime.y:436:23: error: format '%ld' expects argument of type
# 'long int', but argument 5 has type 'time_t' {aka 'int'} [-Werror=format=]
libgnu_parse_datetime_la_CFLAGS	+= -Wno-format-security -Wno-format
EXTRA_DIST += $(top_srcdir)/lib/gnu/parse-datetime.h
EXTRA_DIST += $(top_srcdir)/lib/gnu/parse-datetime.y
nodist_libgnu_parse_datetime_la_SOURCES = parse-datetime.c
 
parse-datetime.c: %.c: $(top_srcdir)/lib/gnu/%.y
	$(YACC) -o $@ $<
endif

clean-generic:
	rm -f $(nodist_libgnu_la_SOURCES) *.log *.debug *.xml *~
