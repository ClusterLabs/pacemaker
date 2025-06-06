#
# Copyright 2004-2023 the Pacemaker project contributors
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

noinst_HEADERS		= crm_mon.h 		\
			  crm_resource.h

pcmkdir			= $(datadir)/$(PACKAGE)
pcmk_DATA		= report.common 	\
			  report.collector

sbin_SCRIPTS		= crm_report 	\
			  crm_standby 	\
			  crm_master 	\
			  crm_failcount
if BUILD_CIBSECRETS
sbin_SCRIPTS		+= cibsecret
endif
noinst_SCRIPTS		= cluster-clean		\
			  cluster-helper	\
			  pcmk_simtimes

EXTRA_DIST		= $(wildcard *.inc) 	\
			  fix-manpages

sbin_PROGRAMS		= attrd_updater \
			  cibadmin 	\
			  crmadmin 	\
			  crm_simulate 	\
			  crm_attribute \
			  crm_diff 	\
			  crm_error 	\
			  crm_mon 	\
			  crm_node 	\
			  crm_resource 	\
			  crm_rule 	\
			  crm_shadow 	\
			  crm_verify 	\
			  crm_ticket 	\
			  iso8601 	\
			  stonith_admin

## SOURCES

# A few tools are just thin wrappers around crm_attribute.
# This makes their help get updated when crm_attribute changes
# (see mk/common.mk).
MAN8DEPS		= crm_attribute

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

crm_resource_SOURCES	= crm_resource.c		\
			  crm_resource_ban.c		\
			  crm_resource_print.c		\
			  crm_resource_runtime.c
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
