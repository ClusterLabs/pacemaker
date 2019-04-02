#
# Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/Makefile.common

AM_CPPFLAGS	+= -I$(top_builddir) -I$(top_srcdir)

## libraries
lib_LTLIBRARIES	= libpacemaker.la

## SOURCES

libpacemaker_la_LDFLAGS	= -version-info 1:0:0

libpacemaker_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libpacemaker_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libpacemaker_la_LIBADD	= $(top_builddir)/lib/pengine/libpe_status.la \
			$(top_builddir)/lib/cib/libcib.la \
			$(top_builddir)/lib/transition/libtransitioner.la \
			$(top_builddir)/lib/lrmd/liblrmd.la
# -L$(top_builddir)/lib/pils -lpils -export-dynamic -module -avoid-version
libpacemaker_la_SOURCES	= pcmk_sched_allocate.c \
			  pcmk_sched_bundle.c \
			  pcmk_sched_clone.c \
			  pcmk_sched_constraints.c \
			  pcmk_sched_graph.c \
			  pcmk_sched_group.c \
			  pcmk_sched_messages.c \
			  pcmk_sched_native.c \
			  pcmk_sched_notif.c \
			  pcmk_sched_promotable.c \
			  pcmk_sched_transition.c \
			  pcmk_sched_utilization.c \
			  pcmk_sched_utils.c
