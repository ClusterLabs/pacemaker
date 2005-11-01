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
		-I$(top_builddir)/linux-ha  -I$(top_srcdir)/linux-ha \
		-I$(top_builddir)           -I$(top_srcdir)

hadir		= $(sysconfdir)/ha.d
halibdir	= $(libdir)/@HB_PKG@
commmoddir	= $(halibdir)/modules/comm
havarlibdir	= $(localstatedir)/lib/@HB_PKG@

# sockets with path
crmdir		= $(havarlibdir)/crm
apigid		= @HA_APIGID@
crmuid		= @HA_CCMUID@

COMMONLIBS	= $(CRM_DEBUG_LIBS)					\
		$(top_builddir)/lib/clplumbing/libplumb.la		\
		$(top_builddir)/lib/pils/libpils.la			\
		$(top_builddir)/lib/crm/common/libcrmcommon.la		\
		libpengine.la						\
		$(top_builddir)/lib/crm/cib/libcib.la			\
		$(top_builddir)/lib/apphb/libapphb.la			\
		$(GLIBLIB)						\
		$(CURSESLIBS)						\
		$(LIBRT)

LIBRT 		= @LIBRT@
AM_CFLAGS	= @CFLAGS@ $(CRM_DEBUG_FLAGS)

## libraries
lib_LTLIBRARIES	= libpengine.la

## binary progs
halib_PROGRAMS	= ptest pengine

## SOURCES

libpengine_la_SOURCES	= color.c unpack.c graph.c rules.c pengine.c \
			utils.c complex.c native.c stages.c \
			group.c incarnation.c master.c

libpengine_la_LDFLAGS	= -version-info 1:0:0

noinst_HEADERS	= pe_utils.h pengine.h complex.h pe_rules.h

ptest_SOURCES	= ptest.c

ptest_CFLAGS	= -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
ptest_LDFLAGS	= 
ptest_LDADD	= $(COMMONLIBS) 

pengine_SOURCES	= main.c

pengine_CFLAGS	= -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
pengine_LDFLAGS	= 
pengine_LDADD	= $(COMMONLIBS) \
		$(top_builddir)/lib/hbclient/libhbclient.la

#

clean-generic:
	rm -f *.log *.debug *~

install-exec-local:

uninstall-local:
