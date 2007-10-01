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

INCLUDES        = -I$(top_builddir)/include  -I$(top_srcdir)/include  \
		  -I$(top_builddir)/libltdl  -I$(top_srcdir)/libltdl  \
		  -I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha \
		  -I$(top_builddir)          -I$(top_srcdir)


hadir		= $(sysconfdir)/ha.d
halibdir	= $(libdir)/@HB_PKG@
commmoddir	= $(halibdir)/modules/comm
havarlibdir	= $(localstatedir)/lib/@HB_PKG@
crmdir		= $(havarlibdir)/crm
XML_FLAGS	= `xml2-config --cflags`
XML_LIBS	= `xml2-config --libs`

# sockets with path
apigid		= @HA_APIGID@
crmuid		= @HA_CCMUID@

LIBRT 		= @LIBRT@
AM_CFLAGS	= @CFLAGS@ $(CRM_DEBUG_FLAGS)

## libraries
lib_LTLIBRARIES	= libcib.la

## SOURCES
noinst_HEADERS		= cib_private.h
libcib_la_SOURCES	= cib_client.c cib_native.c cib_attrs.c \
			cib_version.c

libcib_la_LDFLAGS	= -version-info 1:1:0
libcib_la_CFLAGS	= -I$(top_builddir)

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:

uninstall-local:
