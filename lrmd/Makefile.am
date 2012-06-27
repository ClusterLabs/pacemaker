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

MAINTAINERCLEANFILES = Makefile.in

testdir			= $(testdir)/lrmd
test_PYTHON		= regression.py

lrmdlibdir	= $(CRM_DAEMON_DIR)

## binary progs
lrmdlib_PROGRAMS = lrmd lrmd_test

lrmd_SOURCES	= main.c lrmd.c
lrmd_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/services/libcrmservice.la \
			$(top_builddir)/lib/lrmd/liblrmd.la  \
			$(top_builddir)/lib/fencing/libstonithd.la

lrmd_test_SOURCES	= test.c
lrmd_test_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/lrmd/liblrmd.la  \
			$(top_builddir)/lib/cib/libcib.la   \
			$(top_builddir)/lib/services/libcrmservice.la \
			$(top_builddir)/lib/pengine/libpe_status.la \
			$(top_builddir)/pengine/libpengine.la
