# Author: Sun Jiang Dong <sunjd@cn.ibm.com>
# Copyright (c) 2004 International Business Machines
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

SUBDIRS = 

## binary progs
halibdir	= $(CRM_DAEMON_DIR)
halib_PROGRAMS	= stonithd stonith-test

sbin_PROGRAMS  = stonith_admin
sbin_SCRIPTS   = fence_legacy

stonith_test_SOURCES	= test.c

stonith_test_LDADD	= $(CRYPTOLIB) $(CLUSTERLIBS)			\
			$(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/common/libcrmcluster.la	\
			$(top_builddir)/lib/fencing/libstonithd.la

stonith_admin_SOURCES	= admin.c

stonith_admin_LDADD	= $(CRYPTOLIB) $(CLUSTERLIBS)			\
			$(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/common/libcrmcluster.la	\
			$(top_builddir)/lib/fencing/libstonithd.la

stonithd_SOURCES	= main.c commands.c remote.c

stonithd_LDADD		= $(CRYPTOLIB) $(CLUSTERLIBS)			\
			$(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/common/libcrmcluster.la	\
			$(top_builddir)/lib/fencing/libstonithd.la
