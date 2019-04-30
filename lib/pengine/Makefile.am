#
# Copyright (C) 2004 Andrew Beekhof
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
include $(top_srcdir)/Makefile.common

## libraries
lib_LTLIBRARIES		= libpe_rules.la libpe_status.la

## SOURCES
noinst_HEADERS		= unpack.h variant.h pe_status_private.h

libpe_rules_la_LDFLAGS	= -version-info 5:2:3

libpe_rules_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libpe_rules_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libpe_rules_la_LIBADD	= $(top_builddir)/lib/common/libcrmcommon.la
libpe_rules_la_SOURCES	= rules.c rules_alerts.c common.c

libpe_status_la_LDFLAGS	= -version-info 16:0:0

libpe_status_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libpe_status_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libpe_status_la_LIBADD	= @CURSESLIBS@ $(top_builddir)/lib/common/libcrmcommon.la
# Use += rather than backlashed continuation lines for parsing by bumplibs.sh
libpe_status_la_SOURCES        =
libpe_status_la_SOURCES        += container.c
libpe_status_la_SOURCES        += clone.c
libpe_status_la_SOURCES        += common.c
libpe_status_la_SOURCES        += complex.c
libpe_status_la_SOURCES        += failcounts.c
libpe_status_la_SOURCES        += group.c
libpe_status_la_SOURCES        += native.c
libpe_status_la_SOURCES        += remote.c
libpe_status_la_SOURCES        += rules.c
libpe_status_la_SOURCES        += status.c
libpe_status_la_SOURCES        += unpack.c
libpe_status_la_SOURCES        += utils.c

clean-generic:
	rm -f *.log *.debug *~
