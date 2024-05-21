#
# Copyright 2001-2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/python.mk

MAINTAINERCLEANFILES    = Makefile.in

# Test commands and globally applicable test files should be in $(testdir),
# and command-specific test data should be in a command-specific subdirectory.
testdir			= $(datadir)/$(PACKAGE)/tests
test_SCRIPTS		= cts-attrd 		\
			  cts-cli		\
			  cts-exec		\
			  cts-fencing		\
			  cts-lab 		\
			  cts-regression	\
			  cts-scheduler
dist_test_DATA		= README.md			\
			  valgrind-pcmk.suppressions

clidir		= $(testdir)/cli
dist_cli_DATA	= $(wildcard cli/*.xml cli/*.exp)

ctsdir			= $(datadir)/$(PACKAGE)/tests/cts
cts_SCRIPTS		= cts

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

SUBDIRS	= benchmark 	\
	  scheduler 	\
	  support

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
python_files = cts-attrd       \
	       cts-exec         \
	       cts-fencing      \
	       cts-lab          \
	       cts-regression   \
	       cts-scheduler

PYCHECKFILES ?= $(python_files)
