#
# Copyright 2004-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk

AM_CPPFLAGS	+= -I$(top_builddir) -I$(top_srcdir)

## libraries
lib_LTLIBRARIES	= libpacemaker.la

## SOURCES

libpacemaker_la_LDFLAGS	= -version-info 3:1:2

libpacemaker_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libpacemaker_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libpacemaker_la_LIBADD	= $(top_builddir)/lib/pengine/libpe_status.la \
			$(top_builddir)/lib/cib/libcib.la \
			$(top_builddir)/lib/lrmd/liblrmd.la \
			$(top_builddir)/lib/common/libcrmcommon.la
# -L$(top_builddir)/lib/pils -lpils -export-dynamic -module -avoid-version
# Use += rather than backlashed continuation lines for parsing by bumplibs
libpacemaker_la_SOURCES	=
libpacemaker_la_SOURCES += pcmk_cluster_queries.c
libpacemaker_la_SOURCES += pcmk_fence.c
libpacemaker_la_SOURCES += pcmk_graph_consumer.c
libpacemaker_la_SOURCES += pcmk_graph_logging.c
libpacemaker_la_SOURCES += pcmk_graph_producer.c
libpacemaker_la_SOURCES += pcmk_output.c
libpacemaker_la_SOURCES += pcmk_output_utils.c
libpacemaker_la_SOURCES += pcmk_resource.c
libpacemaker_la_SOURCES	+= pcmk_sched_allocate.c
libpacemaker_la_SOURCES += pcmk_sched_bundle.c
libpacemaker_la_SOURCES += pcmk_sched_clone.c
libpacemaker_la_SOURCES += pcmk_sched_constraints.c
libpacemaker_la_SOURCES += pcmk_sched_fencing.c
libpacemaker_la_SOURCES += pcmk_sched_group.c
libpacemaker_la_SOURCES += pcmk_sched_messages.c
libpacemaker_la_SOURCES += pcmk_sched_native.c
libpacemaker_la_SOURCES += pcmk_sched_notif.c
libpacemaker_la_SOURCES += pcmk_sched_promotable.c
libpacemaker_la_SOURCES += pcmk_sched_transition.c
libpacemaker_la_SOURCES += pcmk_sched_utilization.c
libpacemaker_la_SOURCES += pcmk_sched_utils.c
libpacemaker_la_SOURCES += pcmk_simulate.c
