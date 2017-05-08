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
include $(top_srcdir)/Makefile.common

## libraries
lib_LTLIBRARIES			= libtransitioner.la

## SOURCES

libtransitioner_la_LDFLAGS	= -version-info 2:7:0
libtransitioner_la_CPPFLAGS	= -I$(top_builddir) $(AM_CPPFLAGS)

libtransitioner_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libtransitioner_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libtransitioner_la_LIBADD	= $(top_builddir)/lib/common/libcrmcommon.la
libtransitioner_la_SOURCES	= unpack.c graph.c utils.c

clean-generic:
	rm -f *~
