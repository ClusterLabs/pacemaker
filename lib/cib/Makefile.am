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

INCLUDES        = -I$(top_builddir)/include  -I$(top_srcdir)/include  \
		  -I$(top_builddir)/libltdl  -I$(top_srcdir)/libltdl

## libraries
lib_LTLIBRARIES	= libcib.la

## SOURCES
noinst_HEADERS		= 
libcib_la_SOURCES	= cib_ops.c cib_utils.c cib_client.c cib_native.c cib_attrs.c
libcib_la_SOURCES      += cib_file.c cib_remote.c

if ENABLE_ACL
libcib_la_SOURCES       += cib_acl.c
endif

libcib_la_LDFLAGS	= -version-info 2:1:0 $(top_builddir)/lib/common/libcrmcommon.la $(CRYPTOLIB) \
			$(top_builddir)/lib/pengine/libpe_rules.la

libcib_la_CFLAGS	= -I$(top_srcdir)

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:

uninstall-local:
