# Copyright (c) 2012 David Vossel <dvossel@redhat.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
#

MAINTAINERCLEANFILES = Makefile.in

AM_CPPFLAGS         = -I$(top_builddir)/include  -I$(top_srcdir)/include     \
                   -I$(top_builddir)/libltdl  -I$(top_srcdir)/libltdl     \
		   -I$(top_builddir)          -I$(top_srcdir)

lib_LTLIBRARIES = liblrmd.la

liblrmd_la_SOURCES = lrmd_client.c
liblrmd_la_LDFLAGS = -version-info 2:2:1
liblrmd_la_LIBADD = $(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/services/libcrmservice.la \
			$(top_builddir)/lib/fencing/libstonithd.la


AM_CFLAGS = $(AM_CPPFLAGS)
