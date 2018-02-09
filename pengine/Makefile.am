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

AM_CPPFLAGS	+= -I$(top_builddir) -I$(top_srcdir)

halibdir	= $(CRM_DAEMON_DIR)

COMMONLIBS	= $(top_builddir)/lib/common/libcrmcommon.la	\
		$(top_builddir)/lib/pengine/libpe_status.la	\
		libpengine.la

## libraries
lib_LTLIBRARIES	= libpengine.la

## binary progs
halib_PROGRAMS	= pengine

if BUILD_XML_HELP
man7_MANS =	pengine.7
endif

## SOURCES

noinst_HEADERS	= allocate.h notif.h utils.h pengine.h

libpengine_la_LDFLAGS	= -version-info 14:0:4

libpengine_la_CFLAGS	= $(CFLAGS_HARDENED_LIB)
libpengine_la_LDFLAGS	+= $(LDFLAGS_HARDENED_LIB)

libpengine_la_LIBADD	= $(top_builddir)/lib/pengine/libpe_status.la \
			$(top_builddir)/lib/cib/libcib.la
# -L$(top_builddir)/lib/pils -lpils -export-dynamic -module -avoid-version
libpengine_la_SOURCES	= pengine.c allocate.c notif.c utils.c constraints.c \
			native.c group.c clone.c pe_promotable.c graph.c \
			utilization.c container.c

pengine_CFLAGS	= $(CFLAGS_HARDENED_EXE)
pengine_LDFLAGS	= $(LDFLAGS_HARDENED_EXE)
pengine_LDADD	= $(top_builddir)/lib/cib/libcib.la $(COMMONLIBS)
# libcib for get_object_root()
pengine_SOURCES	= main.c

install-exec-local:
	$(mkinstalldirs) $(DESTDIR)/$(PE_STATE_DIR)
	-chown $(CRM_DAEMON_USER) $(DESTDIR)/$(PE_STATE_DIR)
	-chgrp $(CRM_DAEMON_GROUP) $(DESTDIR)/$(PE_STATE_DIR)
	-chmod 750 $(DESTDIR)/$(PE_STATE_DIR)

uninstall-local:

CLEANFILES = $(man7_MANS)
