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
		  -I$(AISPREFIX)/include/openais


## libraries
lib_LTLIBRARIES	= libcrmcommon.la libcrmcluster.la

libcrmcluster_la_SOURCES = cluster.c membership.c

if BUILD_AIS_SUPPORT
libcrmcluster_la_SOURCES += ais.c
endif

if BUILD_HEARTBEAT_SUPPORT
libcrmcluster_la_SOURCES += heartbeat.c
endif


libcrmcluster_la_LDFLAGS = -version-info 1:0:0

libcrmcommon_la_SOURCES	= ipc.c utils.c xml.c ctrl.c iso8601.c \
			iso8601_fields.c

libcrmcommon_la_LDFLAGS	= -version-info 2:0:0

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:

uninstall-local:
