#
# Copyright 2004-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk
include $(top_srcdir)/mk/man.mk

AM_CPPFLAGS	+= -I$(top_builddir) -I$(top_srcdir)

halibdir	= $(CRM_DAEMON_DIR)

## binary progs

halib_PROGRAMS	= pacemaker-schedulerd

if BUILD_XML_HELP
man7_MANS =	pacemaker-schedulerd.7
endif

## SOURCES

noinst_HEADERS 	= pacemaker-schedulerd.h

pacemaker_schedulerd_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemaker_schedulerd_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)
pacemaker_schedulerd_LDADD	= $(top_builddir)/lib/common/libcrmcommon.la \
							  $(top_builddir)/lib/pengine/libpe_status.la \
							  $(top_builddir)/lib/pacemaker/libpacemaker.la
# libcib for get_object_root()
pacemaker_schedulerd_SOURCES	= pacemaker-schedulerd.c
pacemaker_schedulerd_SOURCES	+= schedulerd_messages.c

install-exec-local:
	$(INSTALL) -d -m 750 $(DESTDIR)/$(PE_STATE_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(PE_STATE_DIR)

if BUILD_LEGACY_LINKS
install-exec-hook:
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f pengine && $(LN_S) pacemaker-schedulerd pengine

uninstall-hook:
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f pengine
endif

uninstall-local:
	-rmdir $(DESTDIR)/$(PE_STATE_DIR)

CLEANFILES = $(man7_MANS)
