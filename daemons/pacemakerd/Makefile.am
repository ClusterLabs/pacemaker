#
# Copyright 2004-2020 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk

initdir			= $(INITDIR)
init_SCRIPTS		= pacemaker
sbin_PROGRAMS		= pacemakerd

if BUILD_SYSTEMD
systemdsystemunit_DATA	= pacemaker.service
endif

EXTRA_DIST		= pacemaker.sysconfig

## SOURCES

noinst_HEADERS		= pacemakerd.h

pacemakerd_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pacemakerd_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)

pacemakerd_LDADD	= $(top_builddir)/lib/cluster/libcrmcluster.la $(top_builddir)/lib/common/libcrmcommon.la
pacemakerd_LDADD	+= $(CLUSTERLIBS)
pacemakerd_SOURCES	= pacemakerd.c
if BUILD_CS_SUPPORT
pacemakerd_SOURCES	+= pcmkd_corosync.c
endif

CLEANFILES = $(man8_MANS)
