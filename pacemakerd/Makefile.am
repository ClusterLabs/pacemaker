#
# Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/Makefile.common

if BUILD_CS_SUPPORT

initdir			= $(INITDIR)
init_SCRIPTS		= pacemaker
sbin_PROGRAMS		= pacemakerd

if BUILD_SYSTEMD
systemdunit_DATA	= pacemaker.service
endif

## SOURCES

noinst_HEADERS		= pacemaker.h

pacemakerd_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemakerd_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

pacemakerd_LDADD	= $(top_builddir)/lib/cluster/libcrmcluster.la $(top_builddir)/lib/common/libcrmcommon.la
pacemakerd_LDADD	+= $(CLUSTERLIBS)
pacemakerd_SOURCES	= pacemaker.c corosync.c

endif

CLEANFILES = $(man8_MANS)
