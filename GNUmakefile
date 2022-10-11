#
# Copyright 2008-2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

default: build
.PHONY: default

# The toplevel "clean" targets are generated from Makefile.am, not this file.
# We can't use autotools' CLEANFILES, clean-local, etc. here. Instead, we
# define this target, which Makefile.am can use as a dependency of clean-local.
EXTRA_CLEAN_TARGETS	= ancillary-clean

-include Makefile

# The main purpose of this GNUmakefile is that its targets can be invoked
# without having to call autogen.sh and configure first. That means automake
# variables may or may not be defined. Here, we use the current working
# directory if a relevant variable hasn't been defined.
abs_srcdir	?= $(shell pwd)

# Define release-related variables
include $(abs_srcdir)/mk/release.mk

GLIB_CFLAGS	?= $(pkg-config --cflags glib-2.0)

PACKAGE		?= pacemaker

.PHONY: init
init:
	test -e configure && test -e libltdl || ./autogen.sh
	test -e Makefile || ./configure

.PHONY: build
build: init
	$(MAKE) $(AM_MAKEFLAGS) core

## RPM-related targets (deprecated; use targets in rpm subdirectory instead)

# Pass option depending on whether automake has been run or not
USE_FILE = $(shell test -e rpm/Makefile || echo "-f Makefile.am")

.PHONY: $(PACKAGE).spec chroot dirty export mock rc release rpm rpmlint srpm
$(PACKAGE).spec chroot dirty export mock rc release rpm rpmlint srpm:
	$(MAKE) $(AM_MAKEFLAGS) -C rpm $(USE_FILE) "$@"

.PHONY: mock-% rpm-% spec-% srpm-%
mock-% rpm-% spec-% srpm-%:
	$(MAKE) $(AM_MAKEFLAGS) -C rpm $(USE_FILE) "$@"

## Targets that moved to devel subdirectory

COVLEVEL        ?= low

.PHONY: clang cppcheck indent
.PHONY: coverity coverity-analyze coverity-clean coverity-corp
clang coverity coverity-analyze coverity-clean coverity-corp cppcheck indent:
	@echo 'Deprecated: Use "make -C devel $@" instead'
	$(MAKE) $(AM_MAKEFLAGS)				\
		CLANG_checkers=$(CLANG_checkers)	\
		COVLEVEL=$(COVLEVEL)			\
		CPPCHECK_ARGS=$(CPPCHECK_ARGS)		\
		-C devel "$@"


## Coverage/profiling

.PHONY: coverage
coverage: core
	-find . -name "*.gcda" -exec rm -f \{\} \;
	-rm -rf coverage
	lcov --no-external --exclude='*_test.c' -c -i -d . -o pacemaker_base.info
	$(MAKE) $(AM_MAKEFLAGS) check
	lcov --no-external --exclude='*_test.c' -c -d . -o pacemaker_test.info
	lcov -a pacemaker_base.info -a pacemaker_test.info -o pacemaker_total.info
	genhtml pacemaker_total.info -o coverage -s

.PHONY: coverage-cts
coverage-cts: core
	-find . -name "*.gcda" -exec rm -f \{\} \;
	-rm -rf coverage
	lcov --no-external -c -i -d tools -o pacemaker_base.info
	cts/cts-cli
	lcov --no-external -c -d tools -o pacemaker_test.info
	lcov -a pacemaker_base.info -a pacemaker_test.info -o pacemaker_total.info
	genhtml pacemaker_total.info -o coverage -s

# This target removes all coverage-related files.  It is only to be run when
# done with coverage analysis and you are ready to go back to normal development,
# starting with re-running ./configure.  It is not to be run in between
# "make coverage" runs.
#
# In particular, the *.gcno files are generated when the source is built.
# Removing those files will break "make coverage" until the whole source tree
# has been built and the *.gcno files generated again.
.PHONY: coverage-clean
coverage-clean:
	-rm -f pacemaker_*.info
	-rm -rf coverage
	-find . \( -name "*.gcno" -o -name "*.gcda" \) -exec rm -f \{\} \;

ancillary-clean: coverage-clean
