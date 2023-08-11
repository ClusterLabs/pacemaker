#
# Copyright 2004-2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk

EXTRA_DIST	= cib.pam

halibdir	= $(CRM_DAEMON_DIR)

halib_PROGRAMS	= pacemaker-based

noinst_HEADERS	= based_transaction.h \
		  pacemaker-based.h

pacemaker_based_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemaker_based_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

pacemaker_based_LDADD = $(top_builddir)/lib/cluster/libcrmcluster.la
pacemaker_based_LDADD += $(top_builddir)/lib/cib/libcib.la
pacemaker_based_LDADD += $(top_builddir)/lib/common/libcrmcommon.la
pacemaker_based_LDADD += $(CLUSTERLIBS)

pacemaker_based_SOURCES	= pacemaker-based.c \
			  based_callbacks.c \
			  based_io.c \
			  based_messages.c \
			  based_notify.c \
			  based_operation.c \
			  based_remote.c \
			  based_transaction.c

.PHONY: install-exec-hook
install-exec-hook:
if BUILD_LEGACY_LINKS
	$(MKDIR_P) -- $(DESTDIR)$(CRM_DAEMON_DIR)
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f cib && $(LN_S) pacemaker-based cib
endif

.PHONY: uninstall-hook
uninstall-hook:
if BUILD_LEGACY_LINKS
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f cib
endif
