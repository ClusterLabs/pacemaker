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

INCLUDES                = -I$(top_builddir)/include -I$(top_srcdir)/include   \
			  -I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl

COMMONLIBS	= 							\
		$(top_builddir)/lib/common/libcrmcommon.la		\
		$(top_builddir)/lib/cib/libcib.la			\
		$(CURSESLIBS) $(CLUSTERLIBS)

headerdir               = $(pkgincludedir)/crm
header_HEADERS		=


halibdir		= $(CRM_DAEMON_DIR)
halib_PROGRAMS		= attrd attrd-ng
## SOURCES

noinst_HEADERS		=

# The original implementation
attrd_SOURCES	= legacy.c
attrd_LDADD	= $(top_builddir)/lib/cluster/libcrmcluster.la $(COMMONLIBS)

attrd_ng_SOURCES	= main.c commands.c
attrd_ng_LDADD		= $(top_builddir)/lib/cluster/libcrmcluster.la $(COMMONLIBS)

%.8:	% crm_attribute
	echo Creating $@
	chmod a+x $(top_builddir)/tools/$<
	$(top_builddir)/tools/$< --help
	PATH=$(top_builddir)/tools:$$PATH $(HELP2MAN) --output $@ --no-info --section 8 --name "Part of the Pacemaker cluster resource manager" $(top_builddir)/tools/$<

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:

uninstall-local:

.PHONY: install-exec-hook
