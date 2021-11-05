#
# Copyright 2018-2021 the Pacemaker project contributors
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

noinst_HEADERS	= controld_alerts.h		\
		  controld_callbacks.h		\
		  controld_fencing.h		\
		  controld_fsa.h		\
		  controld_lrm.h		\
		  controld_matrix.h		\
		  controld_membership.h		\
		  controld_messages.h		\
		  controld_metadata.h		\
		  controld_throttle.h		\
		  controld_timers.h		\
		  controld_transition.h		\
		  controld_utils.h		\
		  pacemaker-controld.h

pacemaker_controld_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemaker_controld_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

pacemaker_controld_LDADD = $(top_builddir)/lib/fencing/libstonithd.la		\
			   $(top_builddir)/lib/pacemaker/libpacemaker.la \
			   $(top_builddir)/lib/pengine/libpe_rules.la		\
			   $(top_builddir)/lib/cib/libcib.la			\
			   $(top_builddir)/lib/cluster/libcrmcluster.la		\
			   $(top_builddir)/lib/common/libcrmcommon.la		\
			   $(top_builddir)/lib/services/libcrmservice.la	\
			   $(top_builddir)/lib/lrmd/liblrmd.la			\
			   $(CLUSTERLIBS)

pacemaker_controld_SOURCES = pacemaker-controld.c	\
			     controld_attrd.c		\
			     controld_callbacks.c	\
			     controld_based.c		\
			     controld_control.c		\
			     controld_corosync.c	\
			     controld_election.c	\
			     controld_execd.c		\
			     controld_execd_state.c	\
			     controld_fencing.c		\
			     controld_fsa.c		\
			     controld_join_client.c	\
			     controld_join_dc.c		\
			     controld_membership.c	\
			     controld_messages.c	\
			     controld_metadata.c	\
			     controld_remote_ra.c	\
			     controld_schedulerd.c	\
			     controld_te_actions.c	\
			     controld_te_callbacks.c	\
			     controld_te_events.c	\
			     controld_te_utils.c	\
			     controld_throttle.c	\
			     controld_timers.c		\
			     controld_transition.c	\
			     controld_utils.c

if BUILD_XML_HELP
man7_MANS 	= pacemaker-controld.7
endif

CLEANFILES = $(man7_MANS)

if BUILD_LEGACY_LINKS
install-exec-hook:
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f crmd && $(LN_S) pacemaker-controld crmd

uninstall-hook:
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f crmd
endif
