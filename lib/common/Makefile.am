#
# Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/Makefile.common

AM_CPPFLAGS		+= -I$(top_builddir)/lib/gnu -I$(top_srcdir)/lib/gnu -DPCMK_SCHEMAS_EMERGENCY_XSLT=0

## libraries
lib_LTLIBRARIES	= libcrmcommon.la

# Can't use -Wcast-qual here because glib insists on pretending things are const  
# when they're not and thus we need the crm_element_value_const() hack

# s390 needs -fPIC 
# s390-suse-linux/bin/ld: .libs/ipc.o: relocation R_390_PC32DBL against `__stack_chk_fail@@GLIBC_2.4' can not be used when making a shared object; recompile with -fPIC

CFLAGS		= $(CFLAGS_COPY:-Wcast-qual=) -fPIC

libcrmcommon_la_LDFLAGS	= -version-info 14:0:1

libcrmcommon_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libcrmcommon_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libcrmcommon_la_LIBADD	= @LIBADD_DL@ $(GNUTLSLIBS)

libcrmcommon_la_SOURCES	= compat.c digest.c ipc.c io.c procfs.c utils.c xml.c	\
			  iso8601.c remote.c mainloop.c logging.c watchdog.c	\
			  schemas.c strings.c xpath.c attrd_client.c alerts.c	\
			  operations.c pid.c results.c
if BUILD_CIBSECRETS
libcrmcommon_la_SOURCES	+= cib_secrets.c
endif
#libcrmcommon_la_SOURCES	+= $(top_builddir)/lib/gnu/md5.c
libcrmcommon_la_SOURCES	+= ../gnu/md5.c

clean-generic:
	rm -f *.log *.debug *.xml *~
