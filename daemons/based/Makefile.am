#
# Copyright 2004-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk

EXTRA_DIST	= cib.pam

halibdir	= $(CRM_DAEMON_DIR)

COMMONLIBS	= $(top_builddir)/lib/common/libcrmcommon.la \
		$(top_builddir)/lib/cib/libcib.la

halib_PROGRAMS	= pacemaker-based

noinst_HEADERS	= based_transaction.h \
		  pacemaker-based.h

pacemaker_based_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemaker_based_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

pacemaker_based_LDADD	= $(top_builddir)/lib/cluster/libcrmcluster.la \
			  $(COMMONLIBS) $(CLUSTERLIBS)

pacemaker_based_SOURCES	= pacemaker-based.c \
			  based_callbacks.c \
			  based_io.c \
			  based_messages.c \
			  based_notify.c \
			  based_operation.c \
			  based_remote.c \
			  based_transaction.c

clean-generic:
	rm -f *.log *.debug *.xml *~

if BUILD_LEGACY_LINKS
install-exec-hook:
	$(MKDIR_P) -- $(DESTDIR)$(CRM_DAEMON_DIR)
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f cib && $(LN_S) pacemaker-based cib

uninstall-hook:
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f cib
endif
