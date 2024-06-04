#
# Copyright 2004-2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk
include $(top_srcdir)/mk/man.mk

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

pacemaker_based_SOURCES	= pacemaker-based.c 	\
			  based_callbacks.c 	\
			  based_io.c 		\
			  based_messages.c 	\
			  based_notify.c 	\
			  based_operation.c 	\
			  based_remote.c 	\
			  based_transaction.c

if BUILD_XML_HELP
man7_MANS 	= pacemaker-based.7
endif

CLEANFILES = $(man7_MANS)
