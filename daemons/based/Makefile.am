#
# Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/Makefile.common

EXTRA_DIST	= cib.pam

halibdir	= $(CRM_DAEMON_DIR)

COMMONLIBS	= $(top_builddir)/lib/common/libcrmcommon.la \
		$(top_builddir)/lib/cib/libcib.la

halib_PROGRAMS	= pacemaker-based cibmon

noinst_HEADERS	= pacemaker-based.h

pacemaker_based_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemaker_based_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

pacemaker_based_LDADD	= $(top_builddir)/lib/cluster/libcrmcluster.la \
			  $(COMMONLIBS) $(CLUSTERLIBS)

pacemaker_based_SOURCES	= pacemaker-based.c \
			  based_callbacks.c \
			  based_common.c \
			  based_io.c \
			  based_messages.c \
			  based_notify.c \
			  based_remote.c

cibmon_LDADD	= $(COMMONLIBS)
cibmon_SOURCES	= cibmon.c

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:
#	cp -f $(top_srcdir)/crm/cib/cib.pam $(DESTDIR)/etc/pam.d/cib

if BUILD_LEGACY_LINKS
install-exec-hook:
	$(MKDIR_P) -- $(DESTDIR)$(CRM_DAEMON_DIR)
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f cib && $(LN_S) pacemaker-based cib

uninstall-hook:
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f cib
endif

uninstall-local:
