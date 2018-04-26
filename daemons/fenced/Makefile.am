#
# Copyright 2004-2018 International Business Machines
# Author: Sun Jiang Dong <sunjd@cn.ibm.com>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/Makefile.common

## binary progs
halibdir	= $(CRM_DAEMON_DIR)
halib_PROGRAMS	= pacemaker-fenced stonith-test

sbin_PROGRAMS	= stonith_admin
sbin_SCRIPTS	= fence_legacy

noinst_HEADERS	= internal.h

if BUILD_XML_HELP
man7_MANS	= pacemaker-fenced.7
endif

stonith_test_SOURCES	= test.c

stonith_test_LDADD	= $(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/fencing/libstonithd.la

stonith_admin_SOURCES	= admin.c

stonith_admin_LDADD	= $(top_builddir)/lib/common/libcrmcommon.la	\
			$(top_builddir)/lib/cib/libcib.la		\
			$(top_builddir)/lib/pengine/libpe_status.la	\
			$(top_builddir)/lib/cluster/libcrmcluster.la	\
			$(top_builddir)/lib/fencing/libstonithd.la	\
			$(CLUSTERLIBS)

pacemaker_fenced_CPPFLAGS	= -I$(top_srcdir)/daemons/schedulerd $(AM_CPPFLAGS)
pacemaker_fenced_YFLAGS		= -d
pacemaker_fenced_CFLAGS		= $(CFLAGS_HARDENED_EXE)
pacemaker_fenced_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)
pacemaker_fenced_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la		\
				  $(top_builddir)/lib/cluster/libcrmcluster.la		\
				  $(top_builddir)/lib/fencing/libstonithd.la		\
				  $(top_builddir)/lib/pengine/libpe_status.la		\
				  $(top_builddir)/daemons/schedulerd/libpengine.la	\
				  $(CLUSTERLIBS)
pacemaker_fenced_SOURCES	= main.c commands.c remote.c

CLEANFILES = $(man7_MANS) $(man8_MANS)
