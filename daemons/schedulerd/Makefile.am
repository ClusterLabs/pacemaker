#
# Copyright 2004-2025 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk
include $(top_srcdir)/mk/man.mk

halibdir	= $(CRM_DAEMON_DIR)

## binary progs

halib_PROGRAMS	= pacemaker-schedulerd

if BUILD_XML_HELP
man7_MANS =	pacemaker-schedulerd.7
endif

## SOURCES

noinst_HEADERS 	= pacemaker-schedulerd.h

pacemaker_schedulerd_CFLAGS		= $(CFLAGS_HARDENED_EXE)
pacemaker_schedulerd_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)
pacemaker_schedulerd_LDADD = $(top_builddir)/lib/pacemaker/libpacemaker.la
pacemaker_schedulerd_LDADD += $(top_builddir)/lib/pengine/libpe_status.la
pacemaker_schedulerd_LDADD += $(top_builddir)/lib/common/libcrmcommon.la

# libcib for get_object_root()
pacemaker_schedulerd_SOURCES	= pacemaker-schedulerd.c
pacemaker_schedulerd_SOURCES	+= schedulerd_ipc.c
pacemaker_schedulerd_SOURCES	+= schedulerd_messages.c

.PHONY: install-exec-local
install-exec-local:
	$(INSTALL) -d -m 750 $(DESTDIR)/$(PCMK_SCHEDULER_INPUT_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(PCMK_SCHEDULER_INPUT_DIR)

.PHONY: uninstall-local
uninstall-local:
	-rmdir $(DESTDIR)/$(PCMK_SCHEDULER_INPUT_DIR)

CLEANFILES = $(man7_MANS)
