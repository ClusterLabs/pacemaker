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

noinst_HEADERS		= crm_mon.h crm_resource.h

pcmkdir			= $(datadir)/$(PACKAGE)
pcmk_DATA		= report.common report.collector

sbin_SCRIPTS		= crm_report crm_standby crm_master crm_failcount
if BUILD_CIBSECRETS
sbin_SCRIPTS		+= cibsecret
endif
noinst_SCRIPTS		= cluster-clean		\
			  cluster-init		\
			  cluster-helper	\
			  pcmk_simtimes

EXTRA_DIST		= attrd_updater.8.inc \
			  cibadmin.8.inc \
				  crm_attribute.8.inc \
				  crm_diff.8.inc \
				  crm_error.8.inc \
			  crm_mon.8.inc			\
			  crm_node.8.inc \
			  crm_resource.8.inc \
			  crm_rule.8.inc \
			  crm_shadow.8.inc \
			  crm_simulate.8.inc \
			  crm_ticket.8.inc \
			  crm_verify.8.inc \
			  crmadmin.8.inc \
			  fix-manpages \
			  iso8601.8.inc \
			  stonith_admin.8.inc

sbin_PROGRAMS		= attrd_updater \
			  cibadmin \
			  crmadmin \
			  crm_simulate \
			  crm_attribute \
			  crm_diff \
			  crm_error \
			  crm_mon \
			  crm_node \
			  crm_resource \
			  crm_rule \
			  crm_shadow \
			  crm_verify \
			  crm_ticket \
			  iso8601 \
			  stonith_admin

## SOURCES

# A few tools are just thin wrappers around crm_attribute.
# This makes their help get updated when crm_attribute changes
# (see mk/common.mk).
MAN8DEPS		= crm_attribute

crmadmin_SOURCES	= crmadmin.c
crmadmin_LDADD		= $(top_builddir)/lib/pengine/libpe_status.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la	\
			  $(top_builddir)/lib/pacemaker/libpacemaker.la
crmadmin_CFLOW_INPUT = $(crmadmin_SOURCES) $(foreach f,$(crmadmin_LDADD),$(dir $(f))*[ch])

crm_error_SOURCES	= crm_error.c
crm_error_LDADD		= $(top_builddir)/lib/pacemaker/libpacemaker.la	\
			  $(top_builddir)/lib/common/libcrmcommon.la
crm_error_CFLOW_INPUT = $(crm_error_SOURCES) $(foreach f,$(crm_error_LDADD),$(dir $(f))*[ch])

cibadmin_SOURCES	= cibadmin.c
cibadmin_LDADD		= $(top_builddir)/lib/pacemaker/libpacemaker.la		\
			  	$(top_builddir)/lib/cib/libcib.la		\
				$(top_builddir)/lib/common/libcrmcommon.la
cibadmin_CFLOW_INPUT = $(cibadmin_SOURCES) $(foreach f,$(cibadmin_LDADD),$(dir $(f))*[ch])

crm_shadow_SOURCES	= crm_shadow.c
crm_shadow_LDADD	= $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la
crm_shadow_CFLOW_INPUT = $(crm_shadow_SOURCES) $(foreach f,$(crm_shadow_LDADD),$(dir $(f))*[ch])

crm_node_SOURCES	= crm_node.c
crm_node_LDADD	= $(top_builddir)/lib/pacemaker/libpacemaker.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la
crm_node_CFLOW_INPUT = $(crm_node_SOURCES) $(foreach f,$(crm_node_LDADD),$(dir $(f))*[ch])

crm_simulate_SOURCES	= crm_simulate.c
crm_simulate_LDADD	= $(top_builddir)/lib/pengine/libpe_status.la	\
			  $(top_builddir)/lib/pacemaker/libpacemaker.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la
crm_simulate_CFLOW_INPUT = $(crm_simulate_SOURCES) $(foreach f,$(crm_simulate_LDADD),$(dir $(f))*[ch])

crm_diff_SOURCES	= crm_diff.c
crm_diff_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la
crm_diff_CFLOW_INPUT = $(crm_diff_SOURCES) $(foreach f,$(crm_diff_LDADD),$(dir $(f))*[ch])

crm_mon_SOURCES		= crm_mon.c crm_mon_curses.c
crm_mon_LDADD		= $(top_builddir)/lib/pengine/libpe_status.la	\
			  $(top_builddir)/lib/fencing/libstonithd.la	\
			  $(top_builddir)/lib/pacemaker/libpacemaker.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la	\
			  $(CURSESLIBS)
crm_mon_CFLOW_INPUT = $(crm_mon_SOURCES) $(foreach f,$(crm_mon_LDADD),$(dir $(f))*[ch])

crm_verify_SOURCES	= crm_verify.c
crm_verify_LDADD	= $(top_builddir)/lib/pengine/libpe_status.la 	\
			  $(top_builddir)/lib/pacemaker/libpacemaker.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la
crm_verify_CFLOW_INPUT = $(crm_verify_SOURCES) $(foreach f,$(crm_verify_LDADD),$(dir $(f))*[ch])

crm_attribute_SOURCES	= crm_attribute.c
crm_attribute_LDADD	= $(top_builddir)/lib/pacemaker/libpacemaker.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la
crm_attribute_CFLOW_INPUT = $(crm_attribute_SOURCES) $(foreach f,$(crm_attribute_LDADD),$(dir $(f))*[ch])

crm_resource_SOURCES	= crm_resource.c		\
			  crm_resource_ban.c		\
			  crm_resource_print.c		\
			  crm_resource_runtime.c
crm_resource_LDADD	= $(top_builddir)/lib/pengine/libpe_rules.la  	\
			  $(top_builddir)/lib/fencing/libstonithd.la	\
			  $(top_builddir)/lib/lrmd/liblrmd.la 		\
			  $(top_builddir)/lib/services/libcrmservice.la \
			  $(top_builddir)/lib/pengine/libpe_status.la 	\
			  $(top_builddir)/lib/pacemaker/libpacemaker.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la
crm_resource_CFLOW_INPUT = $(crm_resource_SOURCES) $(foreach f,$(crm_resource_LDADD),$(dir $(f))*[ch])

crm_rule_SOURCES 	= crm_rule.c
crm_rule_LDADD		= $(top_builddir)/lib/pacemaker/libpacemaker.la \
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/pengine/libpe_rules.la   \
			  $(top_builddir)/lib/pengine/libpe_status.la   \
			  $(top_builddir)/lib/common/libcrmcommon.la
crm_rule_CFLOW_INPUT = $(crm_rule_SOURCES) $(foreach f,$(crm_rule_LDADD),$(dir $(f))*[ch])

iso8601_SOURCES		= iso8601.c
iso8601_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la
iso8601_CFLOW_INPUT = $(iso8601_SOURCES) $(foreach f,$(iso8601_LDADD),$(dir $(f))*[ch])

attrd_updater_SOURCES	= attrd_updater.c
attrd_updater_LDADD	= $(top_builddir)/lib/pacemaker/libpacemaker.la	\
			  $(top_builddir)/lib/common/libcrmcommon.la
attrd_updater_CFLOW_INPUT = $(attrd_updater_SOURCES) $(foreach f,$(attrd_updater_LDADD),$(dir $(f))*[ch])

crm_ticket_SOURCES	= crm_ticket.c
crm_ticket_LDADD	= $(top_builddir)/lib/pengine/libpe_rules.la	\
			  $(top_builddir)/lib/pengine/libpe_status.la	\
			  $(top_builddir)/lib/pacemaker/libpacemaker.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/common/libcrmcommon.la
crm_ticket_CFLOW_INPUT = $(crm_ticket_SOURCES) $(foreach f,$(crm_ticket_LDADD),$(dir $(f))*[ch])

stonith_admin_SOURCES	= stonith_admin.c
stonith_admin_LDADD	= $(top_builddir)/lib/pacemaker/libpacemaker.la	\
			  $(top_builddir)/lib/cib/libcib.la		\
			  $(top_builddir)/lib/pengine/libpe_status.la	\
			  $(top_builddir)/lib/fencing/libstonithd.la \
			  $(top_builddir)/lib/common/libcrmcommon.la
stonith_admin_CFLOW_INPUT = $(stonith_admin_SOURCES) $(foreach f,$(stonith_admin_LDADD),$(dir $(f))*[ch])

CFLOW_FILES = $(foreach f,$(sbin_PROGRAMS),$(f).cflow)

.SECONDEXPANSION:
%.cflow: $$($$(basename $$@)_CFLOW_INPUT)
	cflow -o$@ -T --omit-symbol-names --omit-arguments $(CFLOW_FLAGS) $^

cflow: $(CFLOW_FILES)

CLEANFILES = $(man8_MANS) $(CFLOW_FILES)
