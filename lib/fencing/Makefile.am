#  File: Makefile.am
#  Author: Sun Jiang Dong <sunjd@cn.ibm.com>
#  Copyright (c) 2004 International Business Machines
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
MAINTAINERCLEANFILES = Makefile.in

INCLUDES         = -I$(top_builddir)/include  -I$(top_srcdir)/include     \
                   -I$(top_builddir)/libltdl  -I$(top_srcdir)/libltdl     \
		   -I$(top_builddir)          -I$(top_srcdir)

lib_LTLIBRARIES = libstonithd.la

libstonithd_la_SOURCES = st_client.c
libstonithd_la_LDFLAGS = -version-info 2:0:0
libstonithd_la_LIBADD = $(top_builddir)/lib/common/libcrmcommon.la

AM_CFLAGS = $(INCLUDES)
