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

EXTRA_DIST	= cib.pam

hadir		= $(sysconfdir)/ha.d
halibdir	= $(CRM_DAEMON_DIR)
commmoddir	= $(halibdir)/modules/comm

COMMONLIBS	= $(top_builddir)/lib/common/libcrmcommon.la	\
		  $(top_builddir)/lib/cib/libcib.la

## binary progs
halib_PROGRAMS	= cib cibmon

## SOURCES
noinst_HEADERS          = callbacks.h cibio.h cibmessages.h common.h notify.h

cib_SOURCES		= io.c messages.c notify.c	\
			callbacks.c main.c remote.c common.c

cib_LDADD		= $(top_builddir)/lib/cluster/libcrmcluster.la \
			  $(COMMONLIBS) $(CRYPTOLIB) $(CLUSTERLIBS)

cibmon_SOURCES		= cibmon.c
cibmon_LDADD		= $(COMMONLIBS)

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:
#	cp -f $(top_srcdir)/crm/cib/cib.pam $(DESTDIR)/etc/pam.d/cib

uninstall-local:
