#
# Copyright 2001-2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

MAINTAINERCLEANFILES    = Makefile.in

# Test commands and globally applicable test files should be in $(testdir),
# and command-specific test data should be in a command-specific subdirectory.
testdir			= $(datadir)/$(PACKAGE)/tests
test_SCRIPTS		= cts-attrd \
			  cts-cli		\
			  cts-exec		\
			  cts-fencing		\
			  cts-lab 		\
			  cts-regression	\
			  cts-scheduler
dist_test_DATA		= README.md			\
			  valgrind-pcmk.suppressions

clidir		= $(testdir)/cli
dist_cli_DATA	= cli/constraints.xml 				\
		  cli/crmadmin-cluster-remote-guest-nodes.xml	\
		  cli/crm_diff_new.xml				\
		  cli/crm_diff_old.xml				\
		  cli/crm_mon.xml				\
		  cli/crm_mon-feature_set.xml			\
		  cli/crm_mon-partial.xml			\
		  cli/crm_mon-rsc-maint.xml			\
		  cli/crm_mon-T180.xml				\
		  cli/crm_mon-unmanaged.xml			\
		  cli/crm_resource_digests.xml			\
		  cli/regression.acls.exp			\
		  cli/regression.crm_mon.exp			\
		  cli/regression.daemons.exp			\
		  cli/regression.dates.exp			\
		  cli/regression.error_codes.exp		\
		  cli/regression.feature_set.exp		\
		  cli/regression.rules.exp			\
		  cli/regression.tools.exp			\
		  cli/regression.upgrade.exp			\
		  cli/regression.validity.exp			\
		  cli/regression.access_render.exp

ctsdir			= $(datadir)/$(PACKAGE)/tests/cts
cts_SCRIPTS		= cts

# Commands intended to be run only via other commands
halibdir		= $(CRM_DAEMON_DIR)
dist_halib_SCRIPTS	= cts-log-watcher

noinst_SCRIPTS		= cluster_test

.PHONY: scheduler-list
scheduler-list:
	@for T in "$(srcdir)"/scheduler/xml/*.xml; do       \
		echo $$(basename $$T .xml);             \
	done

CLEANFILES	= $(builddir)/.regression.failed.diff

.PHONY: clean-local
clean-local:
	rm -f scheduler/*/*.pe

SUBDIRS	= benchmark scheduler support

.PHONY: cts-support-install
cts-support-install:
	$(MAKE) $(AM_MAKEFLAGS) -C support cts-support
	$(builddir)/support/cts-support install

.PHONY: cts-support-uninstall
cts-support-uninstall:
	$(MAKE) $(AM_MAKEFLAGS) -C support cts-support
	$(builddir)/support/cts-support uninstall

# Everything listed here is a python script, typically generated from a .in file
# (though that is not a requirement).  We want to run pylint on all of these
# things after they've been built.
python_files = cts-attrd \
			   cts-exec \
			   cts-fencing \
			   cts-lab \
			   cts-log-watcher \
			   cts-regression \
			   cts-scheduler

.PHONY: pylint
pylint: $(python_files)
	PYTHONPATH=$(top_builddir)/python pylint --rcfile $(top_srcdir)/python/pylintrc $(python_files)
