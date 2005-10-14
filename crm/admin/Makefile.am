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



INCLUDES        = -I$(top_builddir)/include -I$(top_srcdir)/include  \
		-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl 	\
		-I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha  \
		-I$(top_builddir) -I$(top_srcdir)

hadir			= $(sysconfdir)/ha.d
halibdir		= $(libdir)/@HB_PKG@
commmoddir		= $(halibdir)/modules/comm
havarlibdir		= $(localstatedir)/lib/@HB_PKG@

# sockets with path
crmdir			= $(havarlibdir)/crm
apigid			= @HA_APIGID@
crmuid			= @HA_CCMUID@

COMMONLIBS	= $(CRM_DEBUG_LIBS)					\
		$(top_builddir)/lib/clplumbing/libplumb.la		\
	  	$(top_builddir)/lib/pils/libpils.la			\
		$(top_builddir)/lib/crm/common/libcrmcommon.la	\
		$(top_builddir)/lib/crm/cib/libcib.la		\
		$(top_builddir)/lib/apphb/libapphb.la			\
		$(top_builddir)/lib/hbclient/libhbclient.la  		\
		$(GLIBLIB)						\
		$(CURSESLIBS)						\
		$(LIBRT)

LIBRT 			= @LIBRT@
AM_CFLAGS		= @CFLAGS@					\
			$(CRM_DEBUG_FLAGS)

## libraries
lib_LTLIBRARIES		= 

## binary progs
halib_PROGRAMS		= crmadmin cibadmin ccm_tool crm_diff crm_mon iso8601 \
			crm_master crm_standby crm_attribute crm_resource \
			crm_verify

## SOURCES

#noinst_HEADERS		= config.h control.h crmd.h
noinst_HEADERS		= 

crmadmin_SOURCES	= crmadmin.c
crmadmin_CFLAGS		= -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
crmadmin_LDADD		= $(COMMONLIBS) \
			$(top_builddir)/crm/pengine/libpengine.la

cibadmin_SOURCES	= cibadmin.c
cibadmin_CFLAGS		= -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
cibadmin_LDADD		= $(COMMONLIBS)

ccm_tool_SOURCES	= ccm_epoche.c
ccm_tool_CFLAGS		= -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
ccm_tool_LDADD		= $(COMMONLIBS) \
			  $(top_builddir)/membership/ccm/libccmclient.la

crm_diff_SOURCES	= xml_diff.c
crm_diff_CFLAGS		= -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
crm_diff_LDADD		= $(COMMONLIBS)

crm_mon_SOURCES		= crm_mon.c
crm_mon_CFLAGS		= -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
crm_mon_LDADD		= $(COMMONLIBS) \
			$(top_builddir)/crm/pengine/libpengine.la

crm_verify_SOURCES	= crm_verify.c
crm_verify_CFLAGS	= -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
crm_verify_LDADD	= $(COMMONLIBS) \
			$(top_builddir)/crm/pengine/libpengine.la

crm_master_SOURCES	= crm_attribute.c
crm_master_CFLAGS	= -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
crm_master_LDADD	= $(COMMONLIBS)

crm_standby_SOURCES	= crm_attribute.c
crm_standby_CFLAGS	= -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
crm_standby_LDADD	= $(COMMONLIBS)

crm_attribute_SOURCES	= crm_attribute.c
crm_attribute_CFLAGS	= -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
crm_attribute_LDADD	= $(COMMONLIBS)

crm_resource_SOURCES	= crm_resource.c
crm_resource_CFLAGS	= -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
crm_resource_LDADD	= $(COMMONLIBS) \
			$(top_builddir)/crm/pengine/libpengine.la

iso8601_SOURCES		= test.iso8601.c
iso8601_CFLAGS		= -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
iso8601_LDADD		= $(COMMONLIBS) 

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:

uninstall-local:
