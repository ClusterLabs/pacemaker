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

man8_MANS      = 

if BUILD_XML_HELP
man8_MANS +=	stonithd.8
stonithd.xml:	stonithd
	$(top_builddir)/fencing/$< metadata | $(XSLTPROC) --nonet --novalid --stringparam man.name $< $(top_srcdir)/xml/ocf-meta2man.xsl - > $(top_builddir)/fencing/$@

stonithd.8:	stonithd.xml
	$(XSLTPROC) $(MANPAGE_XSLT) $(top_builddir)/fencing/$<
endif

if BUILD_HELP
man8_MANS +=	$(sbin_PROGRAMS:%=%.8) fence_legacy.8
%.8:	%
	echo Creating $@
	chmod a+x $<
	help2man --output $@ --no-info --section 8 --name "Part of the Pacemaker cluster resource manager" $(top_builddir)/fencing/$<
endif

stonith_test_SOURCES	= test.c

stonith_test_LDADD	= $(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/common/libcrmcluster.la	\
			$(top_builddir)/lib/fencing/libstonithd.la	\
			$(CRYPTOLIB) $(CLUSTERLIBS)

stonith_admin_SOURCES	= admin.c

stonith_admin_LDADD	= $(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/cib/libcib.la		\
			$(top_builddir)/lib/pengine/libpe_status.la	\
			$(top_builddir)/lib/common/libcrmcluster.la	\
			$(top_builddir)/lib/fencing/libstonithd.la	\
			$(CRYPTOLIB) $(CLUSTERLIBS)

stonithd_SOURCES	= main.c commands.c remote.c

stonithd_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/common/libcrmcluster.la	\
			$(top_builddir)/lib/fencing/libstonithd.la	\
			$(CRYPTOLIB) $(CLUSTERLIBS)
