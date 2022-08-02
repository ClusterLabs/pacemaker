#
# Copyright 2004-2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk

halibdir	= $(CRM_DAEMON_DIR)

halib_PROGRAMS	= pacemaker-attrd

noinst_HEADERS  = pacemaker-attrd.h

pacemaker_attrd_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemaker_attrd_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

pacemaker_attrd_LDADD	= $(top_builddir)/lib/cluster/libcrmcluster.la	\
			  $(top_builddir)/lib/pengine/libpe_rules.la	\
			  $(top_builddir)/lib/common/libcrmcommon.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/lrmd/liblrmd.la		\
			  $(CLUSTERLIBS)

pacemaker_attrd_SOURCES	= attrd_alerts.c 	\
						  attrd_attributes.c \
						  attrd_cib.c 		\
						  attrd_corosync.c 	\
						  attrd_elections.c \
						  attrd_ipc.c 		\
						  attrd_utils.c 	\
						  pacemaker-attrd.c

clean-generic:
	rm -f *.log *.debug *.xml *~

if BUILD_LEGACY_LINKS
install-exec-hook:
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f attrd && $(LN_S) pacemaker-attrd attrd

uninstall-hook:
	cd $(DESTDIR)$(CRM_DAEMON_DIR) && rm -f attrd
endif
