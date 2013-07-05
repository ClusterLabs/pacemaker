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

if BUILD_CS_SUPPORT
INCLUDES                = -I$(top_builddir)/include -I$(top_srcdir)/include   \
			  -I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl

initdir			= $(INITDIR)
init_SCRIPTS		= pacemaker
sbin_PROGRAMS		= pacemakerd

if BUILD_HELP
man8_MANS =	$(sbin_PROGRAMS:%=%.8)
endif

if BUILD_SYSTEMD
systemdunit_DATA = pacemaker.service pacemaker.combined.service
endif

## SOURCES

noinst_HEADERS		=

pacemakerd_SOURCES	= pacemaker.c corosync.c
pacemakerd_LDADD	= $(top_builddir)/lib/cluster/libcrmcluster.la $(top_builddir)/lib/common/libcrmcommon.la
pacemakerd_LDFLAGS	= $(CLUSTERLIBS)

%.8:	%
	echo Creating $@
	chmod a+x $(top_builddir)/mcp/$<
	$(top_builddir)/mcp/$< --help
	$(HELP2MAN) --output $@ --no-info --section 8 --name "Part of the Pacemaker cluster resource manager" $(top_builddir)/mcp/$<

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:

uninstall-local:

.PHONY: install-exec-hook
endif
