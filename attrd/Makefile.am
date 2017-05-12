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
include $(top_srcdir)/Makefile.common

halibdir	= $(CRM_DAEMON_DIR)
halib_PROGRAMS	= attrd
## SOURCES

noinst_HEADERS  = internal.h attrd_common.h

attrd_CFLAGS	= $(CFLAGS_HARDENED_EXE)
attrd_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

attrd_LDADD	= $(top_builddir)/lib/cluster/libcrmcluster.la	\
                $(top_builddir)/lib/pengine/libpe_rules.la      \
		$(top_builddir)/lib/common/libcrmcommon.la	\
		$(top_builddir)/lib/cib/libcib.la		\
                $(top_builddir)/lib/lrmd/liblrmd.la             \
		$(CLUSTERLIBS)

attrd_SOURCES	=
if BUILD_ATOMIC_ATTRD
attrd_SOURCES	+= main.c commands.c attrd_common.c attrd_alerts.c
else
attrd_SOURCES	+= legacy.c attrd_common.c
endif

clean-generic:
	rm -f *.log *.debug *.xml *~
