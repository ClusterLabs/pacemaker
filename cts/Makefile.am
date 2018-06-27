#
# Copyright 2001-2018 Michael Moerz
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

MAINTAINERCLEANFILES    = Makefile.in

EXTRA_DIST      = $(cts_SCRIPTS) $(cts_DATA)

halibdir	= $(CRM_DAEMON_DIR)
halib_SCRIPTS	= cts-log-watcher cts-support

#
# Test commands and globally applicable test files should be in $(testdir),
# and command-specific test data should be in a command-specific subdirectory.
#
testdir		= $(datadir)/$(PACKAGE)/tests
test_SCRIPTS	= cts-coverage cts-regression cts-cli cts-exec cts-scheduler \
		  cts-fencing
test_DATA	= README.md valgrind-pcmk.suppressions

ctslibdir	= $(pythondir)/cts
ctslib_PYTHON	=	__init__.py		\
			CTSvars.py		\
			CM_common.py		\
			CM_corosync.py		\
			CTS.py			\
			CTSaudits.py		\
			CTStests.py		\
			CTSscenarios.py		\
			CIB.py			\
			cib_xml.py		\
			environment.py		\
			logging.py		\
			patterns.py		\
			remote.py		\
			watcher.py

ctsdir		= 	$(testdir)/cts
cts_DATA	=	pacemaker-cts-dummyd@.service

if BUILD_UPSTART
cts_DATA	+=	pacemaker-cts-dummyd.conf
endif

cts_SCRIPTS	=	cts			\
			CTSlab.py		\
			lxc_autogen.sh		\
			LSBDummy		\
			fence_dummy		\
			pacemaker-cts-dummyd

clidir		= $(testdir)/cli
cli_DATA	= cli/regression.dates.exp cli/regression.tools.exp \
		  cli/regression.acls.exp cli/regression.validity.exp \
		  cli/regression.upgrade.exp

PE_TESTS	= $(wildcard scheduler/*.scores)
pedir		= $(testdir)/scheduler
pe_DATA		= $(PE_TESTS) \
		  $(PE_TESTS:%.scores=%.xml) \
		  $(PE_TESTS:%.scores=%.exp) \
		  $(PE_TESTS:%.scores=%.dot) \
		  $(PE_TESTS:%.scores=%.summary) \
		  $(wildcard scheduler/*.stderr)

# For "make check", run a single scheduler test
TESTS = scheduler/bug-rh-1097457.xml
TEST_EXTENSIONS = .xml
XML_LOG_COMPILER = ./cts-scheduler
AM_XML_LOG_FLAGS = -V --run

scheduler-list:
	echo $(shell ls -1 scheduler/*.xml)

clean-local:
	rm -f scheduler/*.pe.*

SUBDIRS	= benchmark

cts-support-install: cts-support
	./cts-support install

cts-support-uninstall: cts-support
	./cts-support uninstall
