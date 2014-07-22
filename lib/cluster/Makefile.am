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

AM_CPPFLAGS       	= -I$(top_builddir)/include  -I$(top_srcdir)/include   \
		  -I$(top_builddir)/libltdl  -I$(top_srcdir)/libltdl

headerdir=$(pkgincludedir)/crm/cluster

header_HEADERS = 

## libraries
lib_LTLIBRARIES	= libcrmcluster.la 

libcrmcluster_la_SOURCES = election.c cluster.c membership.c
libcrmcluster_la_LDFLAGS = -version-info 4:1:0 $(CLUSTERLIBS) 
libcrmcluster_la_LIBADD  = $(top_builddir)/lib/common/libcrmcommon.la $(top_builddir)/lib/fencing/libstonithd.la
libcrmcluster_la_DEPENDENCIES = $(top_builddir)/lib/common/libcrmcommon.la $(top_builddir)/lib/fencing/libstonithd.la 

if BUILD_CS_SUPPORT
libcrmcluster_la_SOURCES += cpg.c
if BUILD_CS_PLUGIN
libcrmcluster_la_SOURCES += legacy.c
else
libcrmcluster_la_SOURCES += corosync.c
endif
endif

if BUILD_HEARTBEAT_SUPPORT
libcrmcluster_la_SOURCES += heartbeat.c
#libcrmcluster_la_LIBADD  += -ldl
endif

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:

uninstall-local:
