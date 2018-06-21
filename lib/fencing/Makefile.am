#
# Copyright 2004-2018 International Business Machines
# Author: Sun Jiang Dong <sunjd@cn.ibm.com>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/Makefile.common

lib_LTLIBRARIES		= libstonithd.la

libstonithd_la_LDFLAGS	= -version-info 5:0:3

libstonithd_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libstonithd_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libstonithd_la_LIBADD	= $(top_builddir)/lib/common/libcrmcommon.la

libstonithd_la_SOURCES	= st_client.c st_rhcs.c
if BUILD_LHA_SUPPORT
libstonithd_la_SOURCES	+= st_lha.c
endif
