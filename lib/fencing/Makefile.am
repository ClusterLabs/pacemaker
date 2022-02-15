#
# Original Author: Sun Jiang Dong <sunjd@cn.ibm.com>
# Copyright 2004 International Business Machines
#
# with later changes copyright 2004-2022 the Pacemaker project contributors.
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/mk/common.mk

noinst_HEADERS		= fencing_private.h

lib_LTLIBRARIES		= libstonithd.la

libstonithd_la_LDFLAGS	= -version-info 34:0:8

libstonithd_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libstonithd_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libstonithd_la_LIBADD	= $(top_builddir)/lib/common/libcrmcommon.la
libstonithd_la_LIBADD   += $(top_builddir)/lib/services/libcrmservice.la

libstonithd_la_SOURCES	= st_actions.c st_client.c st_output.c st_rhcs.c
if BUILD_LHA_SUPPORT
libstonithd_la_SOURCES	+= st_lha.c
endif
