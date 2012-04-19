#
# Copyright (C) 2004-2009 Andrew Beekhof
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

INCLUDES                = -I$(top_builddir)/include -I$(top_srcdir)/include   \
			  -I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl

COMMONLIBS	= 							\
		$(top_builddir)/lib/common/libcrmcommon.la		\
		$(top_builddir)/lib/cib/libcib.la			\
		$(CURSESLIBS) $(CLUSTERLIBS) 

headerdir               = $(pkgincludedir)/crm
header_HEADERS		= attrd.h

pcmkdir			= $(datadir)/$(PACKAGE)
pcmk_DATA		= report.common report.collector

sbin_SCRIPTS		= crm_report crm_standby crm_master crm_failcount
EXTRA_DIST		= $(sbin_SCRIPTS)

halibdir		= $(CRM_DAEMON_DIR)
halib_SCRIPTS		= hb2openais.sh
halib_PROGRAMS		= attrd
halib_PYTHON		= crm_primitive.py hb2openais-helper.py

sbin_PROGRAMS		= crm_simulate crmadmin cibadmin crm_node crm_attribute crm_resource crm_verify \
			 crm_uuid crm_shadow attrd_updater crm_diff crm_mon iso8601 crm_ticket

testdir			= $(datadir)/$(PACKAGE)/tests
test_SCRIPTS		= coverage.sh

clidir			= $(testdir)/cli
cli_SCRIPTS		= regression.sh
cli_DATA		= regression.exp cli.supp

if BUILD_SERVICELOG
sbin_PROGRAMS		+= notifyServicelogEvent
endif
if BUILD_OPENIPMI_SERVICELOG
sbin_PROGRAMS		+= ipmiservicelogd
endif

if BUILD_HELP
man8_MANS =		$(sbin_PROGRAMS:%=%.8) $(sbin_SCRIPTS:%=%.8)
endif

## SOURCES

noinst_HEADERS		= 

crmadmin_SOURCES	= crmadmin.c
crmadmin_LDADD		= $(top_builddir)/lib/pengine/libpe_status.la \
			  $(COMMONLIBS) $(CLUSTERLIBS)

crm_uuid_SOURCES	= crm_uuid.c
crm_uuid_LDADD		= $(COMMONLIBS) $(top_builddir)/lib/cluster/libcrmcluster.la

cibadmin_SOURCES	= cibadmin.c
cibadmin_LDADD		= $(COMMONLIBS) 

crm_shadow_SOURCES	= cib_shadow.c
crm_shadow_LDADD	= $(COMMONLIBS) 

crm_node_SOURCES	= crm_node.c
crm_node_LDADD		= $(top_builddir)/lib/cluster/libcrmcluster.la \
			  $(COMMONLIBS) $(CLUSTERLIBS)

crm_simulate_SOURCES	= crm_inject.c
crm_simulate_CFLAGS	= -I$(top_srcdir)/pengine

crm_simulate_LDADD	= $(top_builddir)/lib/pengine/libpe_status.la		\
			$(top_builddir)/pengine/libpengine.la 			\
			$(top_builddir)/lib/cib/libcib.la			\
			$(top_builddir)/lib/transition/libtransitioner.la	\
			$(COMMONLIBS)

crm_diff_SOURCES	= xml_diff.c
crm_diff_LDADD		= $(COMMONLIBS)

crm_mon_SOURCES		= crm_mon.c
crm_mon_LDADD		= $(top_builddir)/lib/pengine/libpe_status.la		\
			  $(top_builddir)/pengine/libpengine.la \
			  $(COMMONLIBS) $(SNMPLIBS) $(ESMTPLIBS) -llrm

# Arguments could be made that this should live in crm/pengine
crm_verify_SOURCES	= crm_verify.c
crm_verify_LDADD	= $(top_builddir)/lib/pengine/libpe_status.la 	\
			$(top_builddir)/pengine/libpengine.la		\
			$(COMMONLIBS)

crm_attribute_SOURCES	= crm_attribute.c
crm_attribute_LDADD	= $(COMMONLIBS)

crm_resource_SOURCES	= crm_resource.c
crm_resource_LDADD	= $(top_builddir)/lib/pengine/libpe_rules.la  \
			$(top_builddir)/lib/pengine/libpe_status.la \
			$(top_builddir)/pengine/libpengine.la \
			$(COMMONLIBS)

iso8601_SOURCES		= test.iso8601.c
iso8601_LDADD		= $(COMMONLIBS) 

attrd_SOURCES		= attrd.c
attrd_LDADD		= $(top_builddir)/lib/cluster/libcrmcluster.la $(COMMONLIBS)

#pingd_SOURCES		= pingd.c
#pingd_LDADD		= $(COMMONLIBS)

attrd_updater_SOURCES	= attrd_updater.c
attrd_updater_LDADD	= $(COMMONLIBS)

crm_ticket_SOURCES	= crm_ticket.c
crm_ticket_LDADD	= $(top_builddir)/lib/pengine/libpe_rules.la  \
			$(top_builddir)/lib/pengine/libpe_status.la \
			$(top_builddir)/pengine/libpengine.la \
			$(COMMONLIBS)

if BUILD_SERVICELOG
notifyServicelogEvent_SOURCES	= notifyServicelogEvent.c
notifyServicelogEvent_CFLAGS	= $(SERVICELOG_CFLAGS)
notifyServicelogEvent_LDADD	= $(top_builddir)/lib/common/libcrmcommon.la $(SERVICELOG_LIBS)
endif

if BUILD_OPENIPMI_SERVICELOG
ipmiservicelogd_SOURCES	= ipmiservicelogd.c
ipmiservicelogd_CFLAGS	= $(OPENIPMI_SERVICELOG_CFLAGS) $(SERVICELOG_CFLAGS) 
ipmiservicelogd_LDFLAGS	= $(top_builddir)/lib/common/libcrmcommon.la $(OPENIPMI_SERVICELOG_LIBS) $(SERVICELOG_LIBS)
endif

%.8:	% crm_attribute
	echo Creating $@
	chmod a+x $(top_builddir)/tools/$<
	PATH=$(top_builddir)/tools:$$PATH $(HELP2MAN) --output $@ --no-info --section 8 --name "Part of the Pacemaker cluster resource manager" $(top_builddir)/tools/$<

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:

uninstall-local:

.PHONY: install-exec-hook
