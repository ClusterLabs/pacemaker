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
MAINTAINERCLEANFILES    = Makefile.in

INCLUDES        = -I$(top_builddir)/include -I$(top_srcdir)/include	\
		-I$(top_builddir)/libltdl   -I$(top_srcdir)/libltdl	\
		-I$(top_builddir)/linux-ha  -I$(top_srcdir)/linux-ha 	\
		-I$(top_builddir)           -I$(top_srcdir)

hadir		= $(sysconfdir)/ha.d
hasbindir	= $(sbindir)
halibdir	= $(libdir)/@HB_PKG@
commmoddir	= $(halibdir)/modules/comm
havarlibdir	= $(localstatedir)/lib/@HB_PKG@
pe_varlibdir	= $(HA_VARLIBDIR)/$(HB_PKG)/pengine

# sockets with path
crmdir		= $(havarlibdir)/crm
apigid		= @HA_APIGID@
crmuid		= @HA_CCMUID@


COMMONLIBS	= 					\
		$(top_builddir)/lib/clplumbing/libplumb.la		\
		$(top_builddir)/lib/crm/common/libcrmcommon.la		\
		$(top_builddir)/lib/crm/pengine/libpe_status.la		\
		libpengine.la						\
		$(GLIBLIB)						\
		$(CURSESLIBS)						\
		$(AISLIBS)						\
		$(LIBRT)

LIBRT 		= @LIBRT@
AM_CFLAGS	= @CFLAGS@ $(CRM_DEBUG_FLAGS)

## libraries
lib_LTLIBRARIES	= libpengine.la

## binary progs
halib_PROGRAMS	= pengine
hasbin_PROGRAMS	= ptest

## SOURCES
noinst_HEADERS	= allocate.h utils.h pengine.h
#utils.h pengine.h

libpengine_la_LDFLAGS	= -version-info 3:0:0
# -L$(top_builddir)/lib/pils -lpils -export-dynamic -module -avoid-version 
libpengine_la_SOURCES	= pengine.c allocate.c utils.c constraints.c \
			native.c group.c clone.c master.c graph.c

pengine_SOURCES	= main.c
pengine_LDADD	= $(COMMONLIBS)	$(top_builddir)/lib/crm/cib/libcib.la
# libcib for get_object_root()
#		$(top_builddir)/lib/hbclient/libhbclient.la

ptest_SOURCES	= ptest.c 
ptest_LDADD	= $(COMMONLIBS)						\
		$(top_builddir)/lib/crm/cib/libcib.la			\
		$(top_builddir)/lib/crm/transition/libtransitioner.la

clean-generic:
	rm -f *.log *.debug *~ .gres.* testcases/.gres.*

install-exec-local:
	$(mkinstalldirs) $(DESTDIR)/$(pe_varlibdir)
	-chown $(HA_CCMUSER) $(DESTDIR)/$(pe_varlibdir)
	-chgrp $(HA_APIGROUP) $(DESTDIR)/$(pe_varlibdir)
	-chmod 750 $(DESTDIR)/$(pe_varlibdir)

uninstall-local:
