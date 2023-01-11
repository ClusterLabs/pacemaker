#
# Original Author: Sun Jiang Dong <sunjd@cn.ibm.com>
# Copyright 2004 International Business Machines
#
# with later changes copyright 2004-2023 the Pacemaker project contributors.
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk
include $(top_srcdir)/mk/man.mk

halibdir	= $(CRM_DAEMON_DIR)

halib_PROGRAMS	= pacemaker-fenced cts-fence-helper

sbin_SCRIPTS	= fence_watchdog

if BUILD_LHA_SUPPORT
sbin_SCRIPTS 	+= fence_legacy
endif

noinst_HEADERS	= pacemaker-fenced.h

if BUILD_XML_HELP
man7_MANS	= pacemaker-fenced.7
endif

EXTRA_DIST	= README.md

cts_fence_helper_SOURCES	= cts-fence-helper.c
cts_fence_helper_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la	\
				  $(top_builddir)/lib/fencing/libstonithd.la

pacemaker_fenced_YFLAGS		= -d
pacemaker_fenced_CFLAGS		= $(CFLAGS_HARDENED_EXE)
pacemaker_fenced_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)
pacemaker_fenced_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la		\
				  $(top_builddir)/lib/cib/libcib.la		\
				  $(top_builddir)/lib/cluster/libcrmcluster.la		\
				  $(top_builddir)/lib/fencing/libstonithd.la		\
				  $(top_builddir)/lib/pengine/libpe_status.la		\
				  $(top_builddir)/lib/pacemaker/libpacemaker.la	\
				  $(CLUSTERLIBS)
pacemaker_fenced_SOURCES	= pacemaker-fenced.c \
				  fenced_commands.c \
				  fenced_remote.c \
				  fenced_history.c

CLEANFILES = $(man7_MANS) $(man8_MANS)

if BUILD_LEGACY_LINKS
install-exec-hook:
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f stonithd && $(LN_S) pacemaker-fenced stonithd

uninstall-hook:
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f stonithd
endif
