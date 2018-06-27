#
# Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/Makefile.common

## libraries
lib_LTLIBRARIES	= libcrmcluster.la 

libcrmcluster_la_LDFLAGS = -version-info 29:0:0

libcrmcluster_la_CFLAGS  = $(CFLAGS_HARDENED_LIB)
libcrmcluster_la_LDFLAGS += $(LDFLAGS_HARDENED_LIB)

libcrmcluster_la_LIBADD  = $(top_builddir)/lib/common/libcrmcommon.la $(top_builddir)/lib/fencing/libstonithd.la $(CLUSTERLIBS)

libcrmcluster_la_SOURCES = election.c cluster.c membership.c
if BUILD_CS_SUPPORT
libcrmcluster_la_SOURCES += cpg.c corosync.c
endif

clean-generic:
	rm -f *.log *.debug *.xml *~
