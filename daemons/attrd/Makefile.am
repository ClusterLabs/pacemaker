#
# Copyright 2004-2026 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk

halibdir	= $(CRM_DAEMON_DIR)

halib_PROGRAMS	= pacemaker-attrd

noinst_HEADERS  = pacemaker-attrd.h

pacemaker_attrd_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemaker_attrd_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

pacemaker_attrd_LDADD = $(top_builddir)/lib/cluster/libcrmcluster.la
pacemaker_attrd_LDADD += $(top_builddir)/lib/cib/libcib.la
pacemaker_attrd_LDADD += $(top_builddir)/lib/lrmd/liblrmd.la
pacemaker_attrd_LDADD += $(top_builddir)/lib/common/libcrmcommon.la
pacemaker_attrd_LDADD += $(CLUSTERLIBS)

pacemaker_attrd_SOURCES = attrd_alerts.c
pacemaker_attrd_SOURCES += attrd_attributes.c
pacemaker_attrd_SOURCES += attrd_cib.c
pacemaker_attrd_SOURCES += attrd_corosync.c
pacemaker_attrd_SOURCES += attrd_elections.c
pacemaker_attrd_SOURCES += attrd_ipc.c
pacemaker_attrd_SOURCES += attrd_messages.c
pacemaker_attrd_SOURCES += attrd_nodes.c
pacemaker_attrd_SOURCES += attrd_sync.c
pacemaker_attrd_SOURCES += attrd_utils.c
pacemaker_attrd_SOURCES += pacemaker-attrd.c
