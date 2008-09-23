#
# heartbeat: Linux-HA heartbeat code
#
# Copyright (C) 2001 Michael Moerz
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
MAINTAINERCLEANFILES    = Makefile.in ccdv

INCLUDES                = -I$(top_builddir)/include -I$(top_srcdir)/include   \
			  -I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl   \
			  -I$(AISPREFIX)/include/openais

COMMONLIBS	= 							\
		$(top_builddir)/lib/common/libcrmcommon.la		\
		$(top_builddir)/lib/cib/libcib.la			\
		-lplumb					  		\
		$(GLIBLIB) $(CURSESLIBS) $(LIBRT)			\
		$(CLUSTERLIBS) 

EXTRA_DIST		= ccdv.c attrd.h

halibdir		= $(libdir)/@HB_PKG@
halib_SCRIPTS		= haresources2cib.py hb2openais.sh
halib_PROGRAMS		= attrd pingd
halib_PYTHON		= crm_primitive.py

sbin_PROGRAMS		= crmadmin cibadmin ccm_tool crm_diff crm_mon iso8601 	\
			crm_master crm_standby crm_failcount crm_attribute 	\
			crm_resource crm_verify crm_uuid crm_shadow attrd_updater

sbin_SCRIPTS		= crm

## SOURCES
ccdv: 	$(top_srcdir)/tools/ccdv.c
	gcc $(AM_CFLAGS) $(CFLAGS) -o ccdv $(top_srcdir)/tools/ccdv.c

## SOURCES

#noinst_HEADERS		= config.h control.h crmd.h
noinst_HEADERS		= 

crmadmin_SOURCES	= crmadmin.c
crmadmin_LDADD		= $(COMMONLIBS) $(CLUSTERLIBS) \
			$(top_builddir)/lib/pengine/libpe_status.la

crm_uuid_SOURCES	= crm_uuid.c
crm_uuid_LDADD		= $(GLIBLIB)

cibadmin_SOURCES	= cibadmin.c
cibadmin_LDADD		= $(COMMONLIBS) 

crm_shadow_SOURCES	= cib_shadow.c
crm_shadow_LDADD	= $(COMMONLIBS) 

ccm_tool_SOURCES	= ccm_epoche.c
ccm_tool_LDADD		= $(COMMONLIBS) $(CLUSTERLIBS) \
			$(top_builddir)/lib/common/libcrmcluster.la

crm_diff_SOURCES	= xml_diff.c
crm_diff_LDADD		= $(COMMONLIBS)

crm_mon_SOURCES		= crm_mon.c
crm_mon_LDADD		= $(COMMONLIBS) -llrm \
			$(top_builddir)/lib/pengine/libpe_status.la

# Arguments could be made that this should live in crm/pengine
crm_verify_SOURCES	= crm_verify.c
crm_verify_LDADD	= $(COMMONLIBS) \
			$(top_builddir)/lib/pengine/libpe_status.la \
			$(top_builddir)/pengine/libpengine.la

crm_master_SOURCES	= crm_attribute.c
crm_master_LDADD	= $(COMMONLIBS)

crm_standby_SOURCES	= crm_attribute.c
crm_standby_LDADD	= $(COMMONLIBS)

crm_attribute_SOURCES	= crm_attribute.c
crm_attribute_LDADD	= $(COMMONLIBS)

crm_failcount_SOURCES	= crm_attribute.c
crm_failcount_LDADD	= $(COMMONLIBS)

crm_resource_SOURCES	= crm_resource.c
crm_resource_LDADD	= $(COMMONLIBS) \
			$(top_builddir)/lib/pengine/libpe_rules.la \
			$(top_builddir)/lib/pengine/libpe_status.la

iso8601_SOURCES		= test.iso8601.c
iso8601_LDADD		= $(COMMONLIBS) 

# A little trick. Now ccdv can be auto-built but not auto-cleaned.
attrd_DEPENDENCIES	= ccdv
attrd_SOURCES		= attrd.c
attrd_LDADD		= $(COMMONLIBS) $(top_builddir)/lib/common/libcrmcluster.la

pingd_SOURCES		= pingd.c
pingd_LDADD		= $(COMMONLIBS)

attrd_updater_SOURCES	= attrd_updater.c
attrd_updater_LDADD	= $(COMMONLIBS)

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:

uninstall-local:

.PHONY: install-exec-hook
