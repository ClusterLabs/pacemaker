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

if BUILD_INITDIR

if BUILD_SYSTEMD
init_DATA		= pacemaker.service
else
if BUILD_UPSTART
upstartjob		= pacemaker pacemaker.combined
init_DATA		= $(upstartjob:=.upstart)
else
init_SCRIPTS		= pacemaker
endif  # BUILD_UPSTART
endif  # BUILD_SYSTEMD
endif  # BUILD_INITDIR

sbin_PROGRAMS		= pacemakerd

## SOURCES

noinst_HEADERS		= pacemaker.h

pacemakerd_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemakerd_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

pacemakerd_LDADD	= $(top_builddir)/lib/cluster/libcrmcluster.la $(top_builddir)/lib/common/libcrmcommon.la
pacemakerd_LDADD	+= $(CLUSTERLIBS)
pacemakerd_SOURCES	= pacemaker.c corosync.c

install-data-hook:
if BUILD_INITDIR
if BUILD_UPSTART
	for f in $(upstartjob); do \
	  mv "$(DESTDIR)$(initdir)/$${f}.upstart" \
	    "$(DESTDIR)$(initdir)/$${f}.conf"; \
	done
endif  # BUILD_UPSTART
endif  # BUILD_INITDIR

endif  # BUILD_CS_SUPPORT

CLEANFILES = $(man8_MANS)
