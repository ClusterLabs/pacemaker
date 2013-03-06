#
# Copyright (C) 2004 Andrew Beekhof
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
MAINTAINERCLEANFILES    = Makefile.in

INCLUDES       	= -I$(top_builddir)/include  -I$(top_srcdir)/include   \
		  -I$(top_builddir)/libltdl  -I$(top_srcdir)/libltdl   \
		  -I$(top_builddir)/lib/gnu  -I$(top_srcdir)/lib/gnu

## libraries
lib_LTLIBRARIES	= libcrmcommon.la

# Can't use -Wcast-qual here because glib insists on pretending things are const  
# when they're not and thus we need the crm_element_value_const() hack

# s390 needs -fPIC 
# s390-suse-linux/bin/ld: .libs/ipc.o: relocation R_390_PC32DBL against `__stack_chk_fail@@GLIBC_2.4' can not be used when making a shared object; recompile with -fPIC

CFLAGS		= $(CFLAGS_COPY:-Wcast-qual=) -fPIC

libcrmcommon_la_SOURCES	= ipc.c utils.c xml.c iso8601.c remote.c mainloop.c logging.c
if BUILD_CIBSECRETS
libcrmcommon_la_SOURCES	+= cib_secrets.c
endif

libcrmcommon_la_LDFLAGS	= -version-info 4:0:1
libcrmcommon_la_LIBADD  = -ldl $(GNUTLSLIBS)
libcrmcommon_la_SOURCES += $(top_builddir)/lib/gnu/md5.c

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:

uninstall-local:
