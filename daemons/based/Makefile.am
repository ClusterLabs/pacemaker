#
# Copyright 2004-2026 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk
include $(top_srcdir)/mk/man.mk

halibdir	= $(CRM_DAEMON_DIR)

halib_PROGRAMS	= pacemaker-based

noinst_HEADERS = based_callbacks.h
noinst_HEADERS += based_corosync.h
noinst_HEADERS += based_io.h
noinst_HEADERS += based_ipc.h
noinst_HEADERS += based_messages.h
noinst_HEADERS += based_notify.h
noinst_HEADERS += based_operation.h
noinst_HEADERS += based_remote.h
noinst_HEADERS += based_transaction.h
noinst_HEADERS += pacemaker-based.h

pacemaker_based_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemaker_based_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

pacemaker_based_LDADD = $(top_builddir)/lib/cluster/libcrmcluster.la
pacemaker_based_LDADD += $(top_builddir)/lib/cib/libcib.la
pacemaker_based_LDADD += $(top_builddir)/lib/common/libcrmcommon.la
pacemaker_based_LDADD += $(CLUSTERLIBS) $(PAM_LIBS)

pacemaker_based_SOURCES = pacemaker-based.c
pacemaker_based_SOURCES += based_callbacks.c
pacemaker_based_SOURCES += based_corosync.c
pacemaker_based_SOURCES += based_io.c
pacemaker_based_SOURCES += based_ipc.c
pacemaker_based_SOURCES += based_messages.c
pacemaker_based_SOURCES += based_notify.c
pacemaker_based_SOURCES += based_operation.c
pacemaker_based_SOURCES += based_remote.c
pacemaker_based_SOURCES += based_transaction.c

if BUILD_XML_HELP
man7_MANS 	= pacemaker-based.7
endif

CLEANFILES = $(man7_MANS)
