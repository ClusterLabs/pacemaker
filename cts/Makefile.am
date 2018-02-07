#
# Copyright (C) 2001 Michael Moerz
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

CLEANFILES      = CTSlab.py LSBDummy OCFIPraTest.py fence_dummy

EXTRA_DIST      = $(cts_SCRIPTS) $(cts_DATA)

#
# Test commands and globally applicable test files should be in $(testdir),
# and command-specific test data should be in a command-specific subdirectory.
#
testdir		= $(datadir)/$(PACKAGE)/tests
test_SCRIPTS	= cts-coverage cts-regression cts-cli cts-lrmd cts-stonithd
test_DATA	= valgrind-pcmk.suppressions

ctslibdir	= $(pyexecdir)/cts
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

# For "make test", run a single pengine test
TESTS = pengine/bug-rh-1097457.xml
TEST_EXTENSIONS = .xml

pe-list:
	echo $(shell ls -1 pengine/*.xml)

clean-local:
	rm -f pengine/*.pe.*

SUBDIRS	= benchmark
