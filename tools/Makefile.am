#
# Copyright 2004-2026 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/mk/common.mk
include $(top_srcdir)/mk/man.mk

if BUILD_SYSTEMD
systemdsystemunit_DATA	= crm_mon.service
endif

noinst_HEADERS = crm_mon.h
noinst_HEADERS += crm_resource.h

pcmkdir			= $(datadir)/$(PACKAGE)
pcmk_DATA = report.common
pcmk_DATA += report.collector

sbin_SCRIPTS = crm_report
sbin_SCRIPTS += crm_standby
sbin_SCRIPTS += crm_master
sbin_SCRIPTS += crm_failcount

noinst_SCRIPTS		= pcmk_simtimes

EXTRA_DIST = $(wildcard *.inc)
EXTRA_DIST += fix-manpages

sbin_PROGRAMS = attrd_updater
sbin_PROGRAMS += cibadmin
sbin_PROGRAMS += crmadmin
sbin_PROGRAMS += crm_simulate
sbin_PROGRAMS += crm_attribute
sbin_PROGRAMS += crm_diff
sbin_PROGRAMS += crm_error
sbin_PROGRAMS += crm_mon
sbin_PROGRAMS += crm_node
sbin_PROGRAMS += crm_resource
sbin_PROGRAMS += crm_rule
sbin_PROGRAMS += crm_shadow
sbin_PROGRAMS += crm_verify
sbin_PROGRAMS += crm_ticket
sbin_PROGRAMS += iso8601
sbin_PROGRAMS += stonith_admin

if BUILD_CIBSECRETS
sbin_PROGRAMS 		+= cibsecret
endif

## SOURCES

crmadmin_SOURCES	= crmadmin.c
crmadmin_LDADD = $(top_builddir)/lib/pacemaker/libpacemaker.la
crmadmin_LDADD += $(top_builddir)/lib/pengine/libpe_status.la
crmadmin_LDADD += $(top_builddir)/lib/cib/libcib.la
crmadmin_LDADD += $(top_builddir)/lib/common/libcrmcommon.la

crm_error_SOURCES	= crm_error.c
crm_error_LDADD = $(top_builddir)/lib/pacemaker/libpacemaker.la
crm_error_LDADD += $(top_builddir)/lib/common/libcrmcommon.la

cibadmin_SOURCES	= cibadmin.c
cibadmin_LDADD = $(top_builddir)/lib/pacemaker/libpacemaker.la
cibadmin_LDADD += $(top_builddir)/lib/cib/libcib.la
cibadmin_LDADD += $(top_builddir)/lib/common/libcrmcommon.la

if BUILD_CIBSECRETS
cibsecret_SOURCES	= cibsecret.c
cibsecret_LDADD = $(top_builddir)/lib/pacemaker/libpacemaker.la
cibsecret_LDADD += $(top_builddir)/lib/cib/libcib.la
cibsecret_LDADD += $(top_builddir)/lib/common/libcrmcommon.la
endif

crm_shadow_SOURCES	= crm_shadow.c
crm_shadow_LDADD = $(top_builddir)/lib/cib/libcib.la
crm_shadow_LDADD += $(top_builddir)/lib/common/libcrmcommon.la

crm_node_SOURCES	= crm_node.c
crm_node_LDADD = $(top_builddir)/lib/pacemaker/libpacemaker.la
crm_node_LDADD += $(top_builddir)/lib/cib/libcib.la
crm_node_LDADD += $(top_builddir)/lib/common/libcrmcommon.la

crm_simulate_SOURCES	= crm_simulate.c
crm_simulate_LDADD = $(top_builddir)/lib/pacemaker/libpacemaker.la
crm_simulate_LDADD += $(top_builddir)/lib/pengine/libpe_status.la
crm_simulate_LDADD += $(top_builddir)/lib/cib/libcib.la
crm_simulate_LDADD += $(top_builddir)/lib/common/libcrmcommon.la

crm_diff_SOURCES	= crm_diff.c
crm_diff_LDADD = $(top_builddir)/lib/common/libcrmcommon.la

crm_mon_SOURCES		= crm_mon.c crm_mon_curses.c
crm_mon_LDADD = $(top_builddir)/lib/pacemaker/libpacemaker.la
crm_mon_LDADD += $(top_builddir)/lib/pengine/libpe_status.la
crm_mon_LDADD += $(top_builddir)/lib/fencing/libstonithd.la
crm_mon_LDADD += $(top_builddir)/lib/cib/libcib.la
crm_mon_LDADD += $(top_builddir)/lib/common/libcrmcommon.la
crm_mon_LDADD += $(CURSES_LIBS)

crm_verify_SOURCES	= crm_verify.c
crm_verify_LDADD = $(top_builddir)/lib/pacemaker/libpacemaker.la
crm_verify_LDADD += $(top_builddir)/lib/pengine/libpe_status.la
crm_verify_LDADD += $(top_builddir)/lib/cib/libcib.la
crm_verify_LDADD += $(top_builddir)/lib/common/libcrmcommon.la

crm_attribute_SOURCES	= crm_attribute.c
crm_attribute_LDADD	= $(top_builddir)/lib/pacemaker/libpacemaker.la
crm_attribute_LDADD += $(top_builddir)/lib/cib/libcib.la
crm_attribute_LDADD += $(top_builddir)/lib/common/libcrmcommon.la

crm_resource_SOURCES = crm_resource.c
crm_resource_SOURCES += crm_resource_ban.c
crm_resource_SOURCES += crm_resource_print.c
crm_resource_SOURCES += crm_resource_runtime.c
crm_resource_LDADD = $(top_builddir)/lib/pacemaker/libpacemaker.la
crm_resource_LDADD += $(top_builddir)/lib/pengine/libpe_status.la
crm_resource_LDADD += $(top_builddir)/lib/cib/libcib.la
crm_resource_LDADD += $(top_builddir)/lib/lrmd/liblrmd.la
crm_resource_LDADD += $(top_builddir)/lib/fencing/libstonithd.la
crm_resource_LDADD += $(top_builddir)/lib/services/libcrmservice.la
crm_resource_LDADD += $(top_builddir)/lib/common/libcrmcommon.la

crm_rule_SOURCES 	= crm_rule.c
crm_rule_LDADD = $(top_builddir)/lib/pacemaker/libpacemaker.la
crm_rule_LDADD += $(top_builddir)/lib/pengine/libpe_status.la
crm_rule_LDADD += $(top_builddir)/lib/cib/libcib.la
crm_rule_LDADD += $(top_builddir)/lib/common/libcrmcommon.la

iso8601_SOURCES		= iso8601.c
iso8601_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la

attrd_updater_SOURCES	= attrd_updater.c
attrd_updater_LDADD = $(top_builddir)/lib/pacemaker/libpacemaker.la
attrd_updater_LDADD += $(top_builddir)/lib/common/libcrmcommon.la

crm_ticket_SOURCES	= crm_ticket.c
crm_ticket_LDADD = $(top_builddir)/lib/pacemaker/libpacemaker.la
crm_ticket_LDADD += $(top_builddir)/lib/pengine/libpe_status.la
crm_ticket_LDADD += $(top_builddir)/lib/cib/libcib.la
crm_ticket_LDADD += $(top_builddir)/lib/common/libcrmcommon.la

stonith_admin_SOURCES	= stonith_admin.c
stonith_admin_LDADD = $(top_builddir)/lib/pacemaker/libpacemaker.la
stonith_admin_LDADD += $(top_builddir)/lib/pengine/libpe_status.la
stonith_admin_LDADD += $(top_builddir)/lib/cib/libcib.la
stonith_admin_LDADD += $(top_builddir)/lib/fencing/libstonithd.la
stonith_admin_LDADD += $(top_builddir)/lib/common/libcrmcommon.la

CLEANFILES = $(man8_MANS)
