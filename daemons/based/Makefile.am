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

## binary progs
halib_PROGRAMS	= pacemaker-based cibmon

## SOURCES
noinst_HEADERS	= pacemaker-based.h

pacemaker_based_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemaker_based_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

pacemaker_based_LDADD	= $(top_builddir)/lib/cluster/libcrmcluster.la \
			  $(COMMONLIBS) $(CLUSTERLIBS)

pacemaker_based_SOURCES	= io.c messages.c notify.c \
		callbacks.c main.c remote.c common.c

cibmon_LDADD	= $(COMMONLIBS)
cibmon_SOURCES	= cibmon.c

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:
#	cp -f $(top_srcdir)/crm/cib/cib.pam $(DESTDIR)/etc/pam.d/cib

uninstall-local:
