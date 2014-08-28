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

if BUILD_CS_SUPPORT

initdir			= $(INITDIR)
init_SCRIPTS		= pacemaker
sbin_PROGRAMS		= pacemakerd

if BUILD_SYSTEMD
systemdunit_DATA = pacemaker.service
endif

## SOURCES

noinst_HEADERS		= pacemaker.h

pacemakerd_SOURCES	= pacemaker.c corosync.c 
pacemakerd_LDADD	= $(top_builddir)/lib/cluster/libcrmcluster.la $(top_builddir)/lib/common/libcrmcommon.la
pacemakerd_LDFLAGS	= $(CLUSTERLIBS)

clean-generic:
	rm -f *.log *.debug *.xml *~
endif
