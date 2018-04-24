#
# Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/Makefile.common

if BUILD_SYSTEMD
systemdunit_DATA = crm_mon.service
endif

noinst_HEADERS		= crm_resource.h fake_transition.h

pcmkdir			= $(datadir)/$(PACKAGE)
pcmk_DATA		= report.common report.collector

sbin_SCRIPTS		= crm_report crm_standby crm_master crm_failcount
if BUILD_CIBSECRETS
sbin_SCRIPTS		+= cibsecret
endif
EXTRA_DIST		= $(sbin_SCRIPTS)

sbin_PROGRAMS		= crm_simulate crmadmin cibadmin crm_node crm_attribute crm_resource crm_verify \
			 crm_shadow attrd_updater crm_diff crm_mon iso8601 crm_ticket crm_error

if BUILD_SERVICELOG
sbin_PROGRAMS		+= notifyServicelogEvent
endif
if BUILD_OPENIPMI_SERVICELOG
sbin_PROGRAMS		+= ipmiservicelogd
endif

## SOURCES

MAN8DEPS		= crm_attribute crm_node

crmadmin_SOURCES	= crmadmin.c
crmadmin_LDADD		= $(top_builddir)/lib/pengine/libpe_status.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la	\
			  $(CLUSTERLIBS)

crm_error_SOURCES	= crm_error.c
crm_error_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la

cibadmin_SOURCES	= cibadmin.c
cibadmin_LDADD		= $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la

crm_shadow_SOURCES	= cib_shadow.c
crm_shadow_LDADD	= $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la

crm_node_SOURCES	= crm_node.c
crm_node_LDADD		= $(top_builddir)/lib/cluster/libcrmcluster.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la	\
			  $(CLUSTERLIBS)

crm_simulate_SOURCES	= crm_simulate.c fake_transition.c
crm_simulate_CFLAGS	= -I$(top_srcdir)/daemons/schedulerd

crm_simulate_LDADD	= $(top_builddir)/lib/pengine/libpe_status.la	\
			  $(top_builddir)/daemons/schedulerd/libpengine.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/lrmd/liblrmd.la		\
			  $(top_builddir)/lib/transition/libtransitioner.la \
			  $(top_builddir)/lib/common/libcrmcommon.la

crm_diff_SOURCES	= crm_diff.c
crm_diff_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la

crm_mon_SOURCES		= crm_mon.c
crm_mon_CFLAGS		= -I$(top_srcdir)/daemons/schedulerd
crm_mon_LDADD		= $(top_builddir)/lib/pengine/libpe_status.la	\
			  $(top_builddir)/lib/fencing/libstonithd.la	\
			  $(top_builddir)/daemons/schedulerd/libpengine.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la	\
			  $(CURSESLIBS)

# Arguments could be made that this should live in crm/pengine
crm_verify_SOURCES	= crm_verify.c
crm_verify_LDADD	= $(top_builddir)/lib/pengine/libpe_status.la 	\
			  $(top_builddir)/daemons/schedulerd/libpengine.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la

crm_attribute_SOURCES	= crm_attribute.c
crm_attribute_LDADD	= $(top_builddir)/lib/cluster/libcrmcluster.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la

crm_resource_SOURCES	= crm_resource.c crm_resource_ban.c crm_resource_runtime.c crm_resource_print.c fake_transition.c
crm_resource_CFLAGS	= -I$(top_srcdir)/daemons/schedulerd
crm_resource_LDADD	= $(top_builddir)/lib/pengine/libpe_rules.la  	\
			  $(top_builddir)/lib/lrmd/liblrmd.la 		\
			  $(top_builddir)/lib/services/libcrmservice.la \
			  $(top_builddir)/lib/pengine/libpe_status.la 	\
			  $(top_builddir)/daemons/schedulerd/libpengine.la	\
			  $(top_builddir)/lib/transition/libtransitioner.la \
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la

iso8601_SOURCES		= test.iso8601.c
iso8601_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la

attrd_updater_SOURCES	= attrd_updater.c
attrd_updater_LDADD	= $(top_builddir)/lib/common/libcrmcommon.la

crm_ticket_SOURCES	= crm_ticket.c
crm_ticket_CFLAGS	= -I$(top_srcdir)/daemons/schedulerd
crm_ticket_LDADD	= $(top_builddir)/lib/pengine/libpe_rules.la	\
			  $(top_builddir)/lib/pengine/libpe_status.la	\
			  $(top_builddir)/daemons/schedulerd/libpengine.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la

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

CLEANFILES = $(man8_MANS)
