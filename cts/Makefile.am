#
# Copyright 2001-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

MAINTAINERCLEANFILES    = Makefile.in

noinst_SCRIPTS		= cluster_test		\
			  OCFIPraTest.py

# Commands intended to be run only via other commands
halibdir		= $(CRM_DAEMON_DIR)
dist_halib_SCRIPTS	= cts-log-watcher

# Test commands and globally applicable test files should be in $(testdir),
# and command-specific test data should be in a command-specific subdirectory.
testdir			= $(datadir)/$(PACKAGE)/tests
test_SCRIPTS		= cts-cli		\
			  cts-coverage		\
			  cts-exec		\
			  cts-fencing		\
			  cts-regression	\
			  cts-scheduler
dist_test_DATA		= README.md			\
			  valgrind-pcmk.suppressions

ctslibdir		= $(pythondir)/cts
ctslib_PYTHON		= __init__.py		\
			  CIB.py		\
			  cib_xml.py		\
			  CM_common.py		\
			  CM_corosync.py	\
			  CTSaudits.py		\
			  CTSscenarios.py	\
			  CTStests.py		\
			  environment.py	\
			  logging.py		\
			  patterns.py		\
			  remote.py		\
			  watcher.py
nodist_ctslib_PYTHON	= CTS.py		\
			  CTSvars.py

ctsdir		= 	$(testdir)/cts
cts_SCRIPTS		= CTSlab.py		\
			  cts			\
			  lxc_autogen.sh

clidir		= $(testdir)/cli
dist_cli_DATA	= cli/constraints.xml \
		  cli/crmadmin-cluster-remote-guest-nodes.xml \
		  cli/crm_diff_new.xml		\
		  cli/crm_diff_old.xml		\
		  cli/crm_mon.xml		\
		  cli/crm_mon-partial.xml	\
		  cli/crm_resource_digests.xml	\
		  cli/regression.acls.exp	\
		  cli/regression.crm_mon.exp	\
		  cli/regression.dates.exp	\
		  cli/regression.rules.exp	\
		  cli/regression.tools.exp	\
		  cli/regression.upgrade.exp	\
		  cli/regression.validity.exp

scheduler-list:
	@for T in "$(srcdir)"/scheduler/xml/*.xml; do       \
		echo $$(basename $$T .xml);             \
	done

CLEANFILES	= $(builddir)/.regression.failed.diff

clean-local:
	rm -f scheduler/*/*.pe

SUBDIRS	= benchmark scheduler support

cts-support-install:
	$(MAKE) $(AM_MAKEFLAGS) -C support cts-support
	$(builddir)/support/cts-support install

cts-support-uninstall:
	$(MAKE) $(AM_MAKEFLAGS) -C support cts-support
	$(builddir)/support/cts-support uninstall
