#
# Copyright 2018-2026 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk
include $(top_srcdir)/mk/man.mk

halibdir	= $(CRM_DAEMON_DIR)

halib_PROGRAMS	= pacemaker-controld

noinst_HEADERS	= $(wildcard *.h)

pacemaker_controld_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemaker_controld_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

pacemaker_controld_LDADD = $(top_builddir)/lib/pacemaker/libpacemaker.la
pacemaker_controld_LDADD += $(top_builddir)/lib/cib/libcib.la
pacemaker_controld_LDADD += $(top_builddir)/lib/fencing/libstonithd.la
pacemaker_controld_LDADD += $(top_builddir)/lib/cluster/libcrmcluster.la
pacemaker_controld_LDADD += $(top_builddir)/lib/lrmd/liblrmd.la
pacemaker_controld_LDADD += $(top_builddir)/lib/services/libcrmservice.la
pacemaker_controld_LDADD += $(top_builddir)/lib/common/libcrmcommon.la
pacemaker_controld_LDADD += $(CLUSTERLIBS)

pacemaker_controld_SOURCES = pacemaker-controld.c
pacemaker_controld_SOURCES += controld_alerts.c
pacemaker_controld_SOURCES += controld_attrd.c
pacemaker_controld_SOURCES += controld_callbacks.c
pacemaker_controld_SOURCES += controld_cib.c
pacemaker_controld_SOURCES += controld_control.c
pacemaker_controld_SOURCES += controld_corosync.c
pacemaker_controld_SOURCES += controld_election.c
pacemaker_controld_SOURCES += controld_execd.c
pacemaker_controld_SOURCES += controld_execd_state.c
pacemaker_controld_SOURCES += controld_fencing.c
pacemaker_controld_SOURCES += controld_fsa.c
pacemaker_controld_SOURCES += controld_join_client.c
pacemaker_controld_SOURCES += controld_join_dc.c
pacemaker_controld_SOURCES += controld_matrix.c
pacemaker_controld_SOURCES += controld_membership.c
pacemaker_controld_SOURCES += controld_messages.c
pacemaker_controld_SOURCES += controld_metadata.c
pacemaker_controld_SOURCES += controld_remote_ra.c
pacemaker_controld_SOURCES += controld_schedulerd.c
pacemaker_controld_SOURCES += controld_te_actions.c
pacemaker_controld_SOURCES += controld_te_callbacks.c
pacemaker_controld_SOURCES += controld_te_events.c
pacemaker_controld_SOURCES += controld_te_utils.c
pacemaker_controld_SOURCES += controld_throttle.c
pacemaker_controld_SOURCES += controld_timers.c
pacemaker_controld_SOURCES += controld_transition.c
pacemaker_controld_SOURCES += controld_utils.c

if BUILD_XML_HELP
man7_MANS 	= pacemaker-controld.7
endif

CLEANFILES = $(man7_MANS)
