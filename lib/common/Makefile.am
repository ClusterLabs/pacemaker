#
# Copyright 2004-2019 Andrew Beekhof <andrew@beekhof.net>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
include $(top_srcdir)/Makefile.common

AM_CPPFLAGS		+= -I$(top_builddir)/lib/gnu -I$(top_srcdir)/lib/gnu

MOSTLYCLEANFILES	= md5.c

## libraries
lib_LTLIBRARIES	= libcrmcommon.la

# Can't use -Wcast-qual here because glib insists on pretending things are const  
# when they're not and thus we need the crm_element_value_const() hack

# s390 needs -fPIC 
# s390-suse-linux/bin/ld: .libs/ipc.o: relocation R_390_PC32DBL against `__stack_chk_fail@@GLIBC_2.4' can not be used when making a shared object; recompile with -fPIC

CFLAGS		= $(CFLAGS_COPY:-Wcast-qual=) -fPIC

noinst_HEADERS		= crmcommon_private.h

libcrmcommon_la_LDFLAGS	= -version-info 15:0:12

libcrmcommon_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libcrmcommon_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libcrmcommon_la_LIBADD	= @LIBADD_DL@ $(GNUTLSLIBS)

# Use += rather than backlashed continuation lines for parsing by bumplibs.sh
libcrmcommon_la_SOURCES        =
libcrmcommon_la_SOURCES        += acl.c
libcrmcommon_la_SOURCES        += agents.c
libcrmcommon_la_SOURCES        += alerts.c
libcrmcommon_la_SOURCES        += attrd_client.c
if BUILD_CIBSECRETS
libcrmcommon_la_SOURCES	+= cib_secrets.c
endif
libcrmcommon_la_SOURCES        += compat.c
libcrmcommon_la_SOURCES        += digest.c
libcrmcommon_la_SOURCES        += io.c
libcrmcommon_la_SOURCES        += ipc.c
libcrmcommon_la_SOURCES        += iso8601.c
libcrmcommon_la_SOURCES        += logging.c
libcrmcommon_la_SOURCES        += mainloop.c
libcrmcommon_la_SOURCES        += nvpair.c
libcrmcommon_la_SOURCES        += operations.c
libcrmcommon_la_SOURCES        += procfs.c
libcrmcommon_la_SOURCES        += remote.c
libcrmcommon_la_SOURCES        += schemas.c
libcrmcommon_la_SOURCES        += strings.c
libcrmcommon_la_SOURCES        += utils.c
libcrmcommon_la_SOURCES        += watchdog.c
libcrmcommon_la_SOURCES        += xml.c
libcrmcommon_la_SOURCES        += xpath.c

# It's possible to build the library adding ../gnu/md5.c directly to SOURCES,
# but distclean chokes on that because it tries to include the source's .Plo
# file, which may have already been cleaned.
nodist_libcrmcommon_la_SOURCES	= md5.c

md5.c: ../gnu/md5.c
	cp "$<" "$@"

clean-generic:
	rm -f *.log *.debug *.xml *~
