#
# Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/Makefile.common

AM_CPPFLAGS	+= -I$(top_builddir) -I$(top_srcdir)

## libraries
lib_LTLIBRARIES	= libpacemaker-internal.la

## SOURCES

libpacemaker_internal_la_LDFLAGS	= -version-info 1:0:0

libpacemaker_internal_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libpacemaker_internal_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libpacemaker_internal_la_LIBADD	= $(top_builddir)/lib/pengine/libpe_status.la \
			$(top_builddir)/lib/cib/libcib.la
# -L$(top_builddir)/lib/pils -lpils -export-dynamic -module -avoid-version
libpacemaker_internal_la_SOURCES	= pcmki_sched_allocate.c \
			  pcmki_sched_bundle.c \
			  pcmki_sched_clone.c \
			  pcmki_sched_constraints.c \
			  pcmki_sched_graph.c \
			  pcmki_sched_group.c \
			  pcmki_sched_messages.c \
			  pcmki_sched_native.c \
			  pcmki_sched_notif.c \
			  pcmki_sched_promotable.c \
			  pcmki_sched_utilization.c \
			  pcmki_sched_utils.c
