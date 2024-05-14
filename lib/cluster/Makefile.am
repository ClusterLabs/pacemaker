#
# Copyright 2004-2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/mk/common.mk

SUBDIRS	= tests

noinst_HEADERS	= crmcluster_private.h

## libraries
lib_LTLIBRARIES	= libcrmcluster.la 

libcrmcluster_la_LDFLAGS = -version-info 32:0:3

libcrmcluster_la_CFLAGS  = $(CFLAGS_HARDENED_LIB)
libcrmcluster_la_LDFLAGS += $(LDFLAGS_HARDENED_LIB)

libcrmcluster_la_LIBADD = $(top_builddir)/lib/fencing/libstonithd.la
libcrmcluster_la_LIBADD += $(top_builddir)/lib/common/libcrmcommon.la
libcrmcluster_la_LIBADD += $(CLUSTERLIBS)

## Library sources (*must* use += format for bumplibs)
libcrmcluster_la_SOURCES = cluster.c
libcrmcluster_la_SOURCES += election.c
libcrmcluster_la_SOURCES += membership.c
if BUILD_CS_SUPPORT
libcrmcluster_la_SOURCES += corosync.c
libcrmcluster_la_SOURCES += cpg.c
endif
