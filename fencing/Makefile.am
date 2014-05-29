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
include $(top_srcdir)/Makefile.common

SUBDIRS =

## binary progs
testdir			= $(datadir)/$(PACKAGE)/tests/fencing
test_SCRIPTS		= regression.py

halibdir	= $(CRM_DAEMON_DIR)
halib_PROGRAMS	= stonithd stonith-test

sbin_PROGRAMS  = stonith_admin
sbin_SCRIPTS   = fence_legacy fence_pcmk

noinst_HEADERS = internal.h

if BUILD_XML_HELP
man7_MANS =	stonithd.7
endif

stonith_test_SOURCES	= test.c

stonith_test_LDADD	= $(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/cluster/libcrmcluster.la	\
			$(top_builddir)/lib/fencing/libstonithd.la	\
			$(CRYPTOLIB) $(CLUSTERLIBS)

stonith_admin_SOURCES	= admin.c

stonith_admin_LDADD	= $(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/cib/libcib.la		\
			$(top_builddir)/lib/pengine/libpe_status.la	\
			$(top_builddir)/lib/cluster/libcrmcluster.la	\
			$(top_builddir)/lib/fencing/libstonithd.la	\
			$(CRYPTOLIB) $(CLUSTERLIBS)

stonithd_CFLAGS		= -I$(top_srcdir)/pengine
stonithd_SOURCES	= main.c commands.c remote.c
if BUILD_STONITH_CONFIG
BUILT_SOURCES 		= standalone_config.h

stonithd_SOURCES	+= standalone_config.c config.y config.l
stonithd_AM_LFLAGS 	= -o$(LEX_OUTPUT_ROOT).c

# lex/yacc issues:

endif
stonithd_YFLAGS 	= -d

stonithd_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/cluster/libcrmcluster.la	\
			$(top_builddir)/lib/fencing/libstonithd.la	\
			$(top_builddir)/lib/pengine/libpe_status.la	\
			$(top_builddir)/pengine/libpengine.la	\
			$(CRYPTOLIB) $(CLUSTERLIBS)

CFLAGS			= $(CFLAGS_COPY:-Werror=)
