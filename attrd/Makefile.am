#
# Copyright (C) 2004-2009 Andrew Beekhof
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

AM_CPPFLAGS                = -I$(top_builddir)/include -I$(top_srcdir)/include   \
			  -I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl

halibdir		= $(CRM_DAEMON_DIR)
halib_PROGRAMS		= attrd
## SOURCES

noinst_HEADERS		=

attrd_SOURCES		=
attrd_LDADD	= $(top_builddir)/lib/cluster/libcrmcluster.la 		\
		$(top_builddir)/lib/common/libcrmcommon.la		\
		$(top_builddir)/lib/cib/libcib.la			\
		$(CLUSTERLIBS)

if BUILD_ATOMIC_ATTRD
attrd_SOURCES	+= main.c commands.c
else
attrd_SOURCES	+= legacy.c
endif

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:

uninstall-local:

.PHONY: install-exec-hook
