#
# Copyright 2001-2019 the Pacemaker project contributors
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
dist_halib_SCRIPTS	= cts-log-watcher \
			  cts-support

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
cts_DATA	=	pacemaker-cts-dummyd@.service
dist_cts_DATA	=	cts.conf
if BUILD_UPSTART
dist_cts_DATA	+=	pacemaker-cts-dummyd.conf
endif
cts_SCRIPTS		= CTSlab.py		\
			  cts			\
			  fence_dummy		\
			  LSBDummy		\
			  lxc_autogen.sh	\
			  pacemaker-cts-dummyd

clidir		= $(testdir)/cli
dist_cli_DATA	= cli/crm_diff_new.xml		\
		  cli/crm_diff_old.xml		\
		  cli/regression.acls.exp	\
		  cli/regression.dates.exp	\
		  cli/regression.rules.exp	\
		  cli/regression.tools.exp	\
		  cli/regression.upgrade.exp	\
		  cli/regression.validity.exp

PE_TESTS	= $(wildcard scheduler/*.scores)
pedir		= $(testdir)/scheduler
dist_pe_DATA	= $(PE_TESTS) \
		  $(PE_TESTS:%.scores=%.xml) \
		  $(PE_TESTS:%.scores=%.exp) \
		  $(PE_TESTS:%.scores=%.dot) \
		  $(PE_TESTS:%.scores=%.summary) \
		  $(wildcard scheduler/*.stderr)

scheduler-list:
	@for T in "$(srcdir)"/scheduler/*.xml; do       \
		echo $$(basename $$T .xml);             \
	done

CLEANFILES	= $(builddir)/.regression.failed.diff

clean-local:
	rm -f scheduler/*.pe.*

SUBDIRS	= benchmark

cts-support-install: cts-support
	./cts-support install

cts-support-uninstall: cts-support
	./cts-support uninstall
