#
# Copyright 2001-2018 Michael Moerz
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

MAINTAINERCLEANFILES    = Makefile.in

CLEANFILES      = CTSlab.py LSBDummy OCFIPraTest.py fence_dummy

EXTRA_DIST      = $(cts_SCRIPTS) $(cts_DATA)

#
# Test commands and globally applicable test files should be in $(testdir),
# and command-specific test data should be in a command-specific subdirectory.
#
testdir		= $(datadir)/$(PACKAGE)/tests
test_SCRIPTS	= cts-coverage cts-regression cts-cli cts-lrmd cts-pengine \
		  cts-stonithd
test_DATA	= valgrind-pcmk.suppressions

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
cts_DATA	=	README.md cts.supp
cts_SCRIPTS	=	cts		\
			CTSlab.py		\
			lxc_autogen.sh	\
			LSBDummy		\
			fence_dummy

if BUILD_SYSTEMD
daemondir	=	$(CRM_DAEMON_DIR)
daemon_SCRIPTS	=	pacemaker-cts-dummyd

systemdunit_DATA	= pacemaker-cts-dummyd@.service
endif

clidir		= $(testdir)/cli
cli_DATA	= cli/regression.dates.exp cli/regression.tools.exp \
		  cli/regression.acls.exp cli/regression.validity.exp

PE_TESTS	= $(wildcard pengine/*.scores)
pedir		= $(testdir)/pengine
pe_DATA		= $(PE_TESTS) \
		  $(PE_TESTS:%.scores=%.xml) \
		  $(PE_TESTS:%.scores=%.exp) \
		  $(PE_TESTS:%.scores=%.dot) \
		  $(PE_TESTS:%.scores=%.summary) \
		  $(wildcard pengine/*.stderr)

# For "make check", run a single pengine test
TESTS = pengine/bug-rh-1097457.xml
TEST_EXTENSIONS = .xml
XML_LOG_COMPILER = ./cts-pengine
AM_XML_LOG_FLAGS = -V --run

pe-list:
	echo $(shell ls -1 pengine/*.xml)

clean-local:
	rm -f pengine/*.pe.*

SUBDIRS	= benchmark
