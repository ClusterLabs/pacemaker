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
XML_FLAGS	= `xml2-config --cflags`
XML_LIBS	= `xml2-config --libs`

# sockets with path
crmdir		= $(havarlibdir)/crm
apigid		= @HA_APIGID@
crmuid		= @HA_CCMUID@
crmreqsocket	= $(havarlibdir)/api/crm.req
crmressocket	= $(havarlibdir)/api/crm.rsp

COMMONLIBS	= $(CRM_DEBUG_LIBS)					\
		  $(top_builddir)/lib/clplumbing/libplumb.la		\
		  $(top_builddir)/lib/pils/libpils.la			\
		  $(top_builddir)/lib/crm/common/libcrmcommon.la	\
		  $(top_builddir)/lib/apphb/libapphb.la		\
		  $(top_builddir)/lib/hbclient/libhbclient.la		\
		  $(top_builddir)/lib/crm/cib/libcib.la		\
		  $(GLIBLIB)						\
		  $(LIBRT)

LIBRT 		= @LIBRT@
AM_CFLAGS	= @CFLAGS@ $(CRM_DEBUG_FLAGS)

## binary progs
halib_PROGRAMS	= cib cibmon


## SOURCES
#noinst_HEADERS		= config.h control.h crmd.h
noinst_HEADERS		= cibio.h cibmessages.h cibprimatives.h notify.h \
			callbacks.h

cib_SOURCES		= io.c primatives.c messages.c cib.c notify.c \
			callbacks.c main.c
cib_CFLAGS		= $(XML_FLAGS) -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
cib_LDFLAGS		= $(XML_LIBS)
cib_LDADD		= $(COMMONLIBS) \
			$(top_builddir)/membership/ccm/libccmclient.la  


cibmon_SOURCES		= cibmon.c
cibmon_CFLAGS		= $(XML_FLAGS) -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
cibmon_LDFLAGS		= $(XML_LIBS)
cibmon_LDADD		= $(COMMONLIBS) 				

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:

uninstall-local:
