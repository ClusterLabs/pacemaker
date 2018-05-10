#
# Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/Makefile.common

AM_CPPFLAGS	+= -I$(top_builddir) -I$(top_srcdir)

halibdir	= $(CRM_DAEMON_DIR)

COMMONLIBS	= $(top_builddir)/lib/common/libcrmcommon.la	\
		$(top_builddir)/lib/pengine/libpe_status.la	\
		libpengine.la

## libraries
lib_LTLIBRARIES	= libpengine.la

## binary progs

halib_PROGRAMS	= pacemaker-schedulerd

if BUILD_XML_HELP
man7_MANS =	pacemaker-schedulerd.7
endif

## SOURCES

noinst_HEADERS	= pacemaker-schedulerd.h \
		  sched_allocate.h \
		  sched_notif.h \
		  sched_utils.h
		  

libpengine_la_LDFLAGS	= -version-info 17:0:0

libpengine_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libpengine_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libpengine_la_LIBADD	= $(top_builddir)/lib/pengine/libpe_status.la \
			$(top_builddir)/lib/cib/libcib.la
# -L$(top_builddir)/lib/pils -lpils -export-dynamic -module -avoid-version
libpengine_la_SOURCES	= sched_allocate.c \
			  sched_bundle.c \
			  sched_clone.c \
			  sched_constraints.c \
			  sched_graph.c \
			  sched_group.c \
			  sched_messages.c \
			  sched_native.c \
			  sched_notif.c \
			  sched_promotable.c \
			  sched_utilization.c \
			  sched_utils.c

pacemaker_schedulerd_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemaker_schedulerd_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)
pacemaker_schedulerd_LDADD	= $(top_builddir)/lib/cib/libcib.la $(COMMONLIBS)
# libcib for get_object_root()
pacemaker_schedulerd_SOURCES	= pacemaker-schedulerd.c

install-exec-local:
	$(mkinstalldirs) $(DESTDIR)/$(PE_STATE_DIR)
	-chown $(CRM_DAEMON_USER) $(DESTDIR)/$(PE_STATE_DIR)
	-chgrp $(CRM_DAEMON_GROUP) $(DESTDIR)/$(PE_STATE_DIR)
	-chmod 750 $(DESTDIR)/$(PE_STATE_DIR)

if BUILD_LEGACY_LINKS
install-exec-hook:
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f pengine && $(LN_S) pacemaker-schedulerd pengine

uninstall-hook:
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f pengine
endif

uninstall-local:

CLEANFILES = $(man7_MANS)
