#
# Copyright 2004-2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk

SUBDIRS = tests

noinst_HEADERS  = libpacemaker_private.h

## libraries
lib_LTLIBRARIES	= libpacemaker.la

libpacemaker_la_LDFLAGS	= -version-info 30:0:0

libpacemaker_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libpacemaker_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libpacemaker_la_LIBADD = $(top_builddir)/lib/pengine/libpe_status.la
libpacemaker_la_LIBADD += $(top_builddir)/lib/cib/libcib.la
libpacemaker_la_LIBADD += $(top_builddir)/lib/lrmd/liblrmd.la
libpacemaker_la_LIBADD += $(top_builddir)/lib/fencing/libstonithd.la
libpacemaker_la_LIBADD += $(top_builddir)/lib/services/libcrmservice.la
libpacemaker_la_LIBADD += $(top_builddir)/lib/common/libcrmcommon.la

# -L$(top_builddir)/lib/pils -lpils -export-dynamic -module -avoid-version

## Library sources (*must* use += format for bumplibs)
libpacemaker_la_SOURCES	=
libpacemaker_la_SOURCES += pcmk_acl.c
libpacemaker_la_SOURCES += pcmk_agents.c
libpacemaker_la_SOURCES += pcmk_cluster_queries.c
libpacemaker_la_SOURCES += pcmk_fence.c
libpacemaker_la_SOURCES += pcmk_graph_consumer.c
libpacemaker_la_SOURCES += pcmk_graph_logging.c
libpacemaker_la_SOURCES += pcmk_graph_producer.c
libpacemaker_la_SOURCES += pcmk_injections.c
libpacemaker_la_SOURCES += pcmk_options.c
libpacemaker_la_SOURCES += pcmk_output.c
libpacemaker_la_SOURCES += pcmk_resource.c
libpacemaker_la_SOURCES += pcmk_result_code.c
libpacemaker_la_SOURCES += pcmk_rule.c
libpacemaker_la_SOURCES	+= pcmk_sched_actions.c
libpacemaker_la_SOURCES += pcmk_sched_bundle.c
libpacemaker_la_SOURCES += pcmk_sched_clone.c
libpacemaker_la_SOURCES += pcmk_sched_colocation.c
libpacemaker_la_SOURCES += pcmk_sched_constraints.c
libpacemaker_la_SOURCES += pcmk_sched_fencing.c
libpacemaker_la_SOURCES += pcmk_sched_group.c
libpacemaker_la_SOURCES += pcmk_sched_instances.c
libpacemaker_la_SOURCES += pcmk_sched_location.c
libpacemaker_la_SOURCES += pcmk_sched_migration.c
libpacemaker_la_SOURCES += pcmk_sched_nodes.c
libpacemaker_la_SOURCES += pcmk_sched_ordering.c
libpacemaker_la_SOURCES += pcmk_sched_primitive.c
libpacemaker_la_SOURCES += pcmk_sched_probes.c
libpacemaker_la_SOURCES += pcmk_sched_promotable.c
libpacemaker_la_SOURCES += pcmk_sched_recurring.c
libpacemaker_la_SOURCES += pcmk_sched_remote.c
libpacemaker_la_SOURCES += pcmk_sched_resource.c
libpacemaker_la_SOURCES += pcmk_sched_tickets.c
libpacemaker_la_SOURCES += pcmk_sched_utilization.c
libpacemaker_la_SOURCES	+= pcmk_scheduler.c
libpacemaker_la_SOURCES += pcmk_setup.c
libpacemaker_la_SOURCES += pcmk_simulate.c
libpacemaker_la_SOURCES += pcmk_status.c
libpacemaker_la_SOURCES += pcmk_ticket.c
libpacemaker_la_SOURCES += pcmk_verify.c
