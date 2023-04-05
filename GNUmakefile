#
# Copyright 2008-2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

default: build
.PHONY: default

-include Makefile

# The main purpose of this GNUmakefile is that its targets can be invoked
# without having to call autogen.sh and configure first. That means automake
# variables may or may not be defined. Here, we use the current working
# directory if a relevant variable hasn't been defined.
abs_srcdir	?= $(shell pwd)

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

## Development-related targets
## (deprecated; use targets in devel subdirectory instead)

COVLEVEL        	?= low
COVERAGE_TARGETS	= coverage coverage-cts coverage-clean
COVERITY_TARGETS	= coverity coverity-analyze coverity-clean coverity-corp

.PHONY: clang $(COVERAGE_TARGETS) $(COVERITY_TARGETS) cppcheck indent
clang $(COVERAGE_TARGETS) $(COVERITY_TARGETS) cppcheck indent:
	@echo 'Deprecated: Use "make -C devel $@" instead'
	$(MAKE) $(AM_MAKEFLAGS)				\
		CLANG_checkers=$(CLANG_checkers)	\
		COVLEVEL=$(COVLEVEL)			\
		CPPCHECK_ARGS=$(CPPCHECK_ARGS)		\
		-C devel "$@"
