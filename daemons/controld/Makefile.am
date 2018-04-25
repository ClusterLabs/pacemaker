#
# Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/Makefile.common

halibdir	= $(CRM_DAEMON_DIR)

## binary progs
halib_PROGRAMS	= pacemaker-controld

## SOURCES

noinst_HEADERS	= controld_alerts.h		\
		  controld_callbacks.h		\
		  controld_fsa.h		\
		  controld_lrm.h		\
		  controld_matrix.h		\
		  controld_membership.h		\
		  controld_messages.h		\
		  controld_metadata.h		\
		  controld_utils.h		\
		  pacemaker-controld.h		\
		te_callbacks.h \
		tengine.h throttle.h

pacemaker_controld_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemaker_controld_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

pacemaker_controld_LDADD = $(top_builddir)/lib/fencing/libstonithd.la		\
			   $(top_builddir)/lib/transition/libtransitioner.la	\
			   $(top_builddir)/lib/pengine/libpe_rules.la		\
			   $(top_builddir)/lib/cib/libcib.la			\
			   $(top_builddir)/lib/cluster/libcrmcluster.la		\
			   $(top_builddir)/lib/common/libcrmcommon.la		\
			   $(top_builddir)/lib/services/libcrmservice.la	\
			   $(top_builddir)/lib/lrmd/liblrmd.la			\
			   $(CLUSTERLIBS)

pacemaker_controld_SOURCES = main.c corosync.c crmd_metadata.c			\
			     fsa.c control.c messages.c membership.c callbacks.c attrd.c	\
			     election.c join_client.c join_dc.c throttle.c			\
			     cib.c pengine.c tengine.c lrm.c lrm_state.c remote_ra.c		\
			     utils.c misc.c te_events.c te_actions.c te_utils.c te_callbacks.c

if BUILD_XML_HELP
man7_MANS 	= pacemaker-controld.7
endif

CLEANFILES = $(man7_MANS)
