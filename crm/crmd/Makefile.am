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

INCLUDES                = -I$(top_builddir)/include -I$(top_srcdir)/include \
			-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl \
			-I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha

hadir			= $(sysconfdir)/ha.d
halibdir		= $(libdir)/@HB_PKG@
commmoddir		= $(halibdir)/modules/comm
havarlibdir		= $(localstatedir)/lib/@HB_PKG@
PIDFILE			= $(localstatedir)/run/crmd.pid
XML_FLAGS		= `xml2-config --cflags`
XML_LIBS		= `xml2-config --libs`

# fifos with path
crmdir			= $(havarlibdir)/crm
apigid			= @HA_APIGID@
crmuid			= @HA_CCMUID@
crmreqfifo		= $(havarlibdir)/api/crm.req
crmresfifo		= $(havarlibdir)/api/crm.rsp


COMMONLIBS		= $(top_builddir)/lib/clplumbing/libplumb.la	\
			$(top_builddir)/$(CRM_DIR)/common/libcrmcommon.la	\
			$(top_builddir)/$(CRM_DIR)/cib/libcib.la	\
			$(top_builddir)/lib/apphb/libapphb.la		\
			$(top_builddir)/heartbeat/libhbclient.la  	\
			$(GLIBLIB)					\
			$(LIBRT)

LIBRT 			= @LIBRT@
AM_CFLAGS		= @CFLAGS@	\
			-DPIDFILE='"$(PIDFILE)"'

## libraries
lib_LTLIBRARIES		= 


## binary progs
halib_PROGRAMS		= crmd


## SOURCES

#noinst_HEADERS		= config.h control.h crmd.h
noinst_HEADERS		= 

crmd_SOURCES		= crmdmain.c crmd.c
crmd_CFLAGS		= $(XML_FLAGS) -I$(top_builddir) -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
crmd_LDFLAGS		= $(XML_LIBS)
crmd_LDADD		= $(COMMONLIBS) 				\
			$(top_builddir)/libltdl/libltdlc.la 		\
			$(top_builddir)/replace/libreplace.la		\
			$(top_builddir)/membership/ccm/libccmclient.la  

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:

uninstall-local:
