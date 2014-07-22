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

AM_CPPFLAGS        = -I$(top_builddir)/include -I$(top_srcdir)/include	\
		-I$(top_builddir)/libltdl   -I$(top_srcdir)/libltdl

## libraries
lib_LTLIBRARIES	= libpe_rules.la libpe_status.la

## SOURCES
noinst_HEADERS	= unpack.h variant.h

libpe_rules_la_LDFLAGS	= -version-info 2:3:0
libpe_rules_la_SOURCES	= rules.c common.c
libpe_rules_la_LIBADD	= $(top_builddir)/lib/common/libcrmcommon.la

libpe_status_la_LDFLAGS	= -version-info 7:0:3
libpe_status_la_SOURCES	=  status.c unpack.c utils.c complex.c native.c group.c clone.c rules.c common.c
libpe_status_la_LIBADD	=  @CURSESLIBS@ $(top_builddir)/lib/common/libcrmcommon.la

clean-generic:
	rm -f *.log *.debug *~

install-exec-local:

uninstall-local:
