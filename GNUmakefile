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
#
# The idea is to keep generated artifacts in the build tree, in case a VPATH
# build is in use, but in practice it would be difficult to make the targets
# here usable from a different location than the source tree.
abs_srcdir	?= $(shell pwd)
abs_builddir	?= $(shell pwd)

# Define release-related variables
include $(abs_srcdir)/mk/release.mk

GLIB_CFLAGS	?= $(pkg-config --cflags glib-2.0)

PACKAGE		?= pacemaker

.PHONY: init
init:
	test -e $(top_srcdir)/configure || ./autogen.sh
	test -e $(abs_builddir)/Makefile || $(abs_builddir)/configure

.PHONY: build
build: init
	$(MAKE) $(AM_MAKEFLAGS) core

## RPM-related targets (deprecated; use targets in rpm subdirectory instead)

# Pass option depending on whether automake has been run or not
USE_FILE	= $(shell test -z "$(srcdir)" && echo "-f Makefile.am")

.PHONY: $(PACKAGE).spec chroot dirty export mock rc release rpm rpmlint srpm
$(PACKAGE).spec chroot dirty export mock rc release rpm rpmlint srpm:
	$(MAKE) $(AM_MAKEFLAGS) -C rpm $(USE_FILE) "$@"

.PHONY: mock-% rpm-% spec-% srpm-%
mock-% rpm-% spec-% srpm-%:
	$(MAKE) $(AM_MAKEFLAGS) -C rpm $(USE_FILE) "$@"

## indent-related targets (deprecated; use targets in devel subdir instead)

.PHONY: indent
indent:
	@echo 'Deprecated: Use "make -C devel $@" instead'
	$(MAKE) $(AM_MAKEFLAGS) -C devel "$@"

## Static analysis via coverity

# Aggressiveness (low, medium, or high)
COVLEVEL	?= low

# Generated outputs
COVERITY_DIR	= $(abs_builddir)/coverity-$(TAG)
COVTAR		= $(abs_builddir)/$(PACKAGE)-coverity-$(TAG).tgz
COVEMACS	= $(abs_builddir)/$(TAG).coverity
COVHTML		= $(COVERITY_DIR)/output/errors

# Coverity outputs are phony so they get rebuilt every invocation

.PHONY: $(COVERITY_DIR)
$(COVERITY_DIR): init core-clean coverity-clean
	$(AM_V_GEN)cov-build --dir "$@" $(MAKE) $(AM_MAKEFLAGS) core

# Public coverity instance

.PHONY: $(COVTAR)
$(COVTAR): $(COVERITY_DIR)
	$(AM_V_GEN)tar czf "$@" --transform="s@.*$(TAG)@cov-int@" "$<"

.PHONY: coverity
coverity: $(COVTAR)
	@echo "Now go to https://scan.coverity.com/users/sign_in and upload:"
	@echo "  $(COVTAR)"
	@echo "then make core-clean coverity-clean"

# Licensed coverity instance
#
# The prerequisites are a little hacky; rather than actually required, some
# of them are designed so that things execute in the proper order (which is
# not the same as GNU make's order-only prerequisites).

.PHONY: coverity-analyze
coverity-analyze: $(COVERITY_DIR)
	@echo ""
	@echo "Analyzing (waiting for coverity license if necessary) ..."
	cov-analyze --dir "$<" --wait-for-license --security		\
		--aggressiveness-level "$(COVLEVEL)"

.PHONY: $(COVEMACS)
$(COVEMACS): coverity-analyze
	$(AM_V_GEN)cov-format-errors --dir "$(COVERITY_DIR)" --emacs-style > "$@"

.PHONY: $(COVHTML)
$(COVHTML): $(COVEMACS)
	$(AM_V_GEN)cov-format-errors --dir "$(COVERITY_DIR)" --html-output "$@"

.PHONY: coverity-corp
coverity-corp: $(COVHTML)
	$(MAKE) $(AM_MAKEFLAGS) core-clean
	@echo "Done. See:"
	@echo "  file://$(COVHTML)/index.html"
	@echo "When no longer needed, make coverity-clean"

# Remove all outputs regardless of tag
.PHONY: coverity-clean
coverity-clean:
	-rm -rf "$(abs_builddir)"/coverity-*			\
		"$(abs_builddir)"/$(PACKAGE)-coverity-*.tgz	\
		"$(abs_builddir)"/*.coverity


## Change log generation

summary:
	@printf "\n* `date +"%a %b %d %Y"` `git config user.name` <`git config user.email`> $(NEXT_RELEASE)"
	@printf "\n- Changesets: `git log --pretty=oneline --no-merges $(LAST_RELEASE)..HEAD | wc -l`"
	@printf "\n- Diff:\n"
	@git diff $(LAST_RELEASE)..HEAD --shortstat include lib daemons tools xml

rc-changes:
	@$(MAKE) $(AM_MAKEFLAGS) NEXT_RELEASE=$(shell echo $(LAST_RC) | sed s:-rc.*::) LAST_RELEASE=$(LAST_RC) changes

changes: summary
	@printf "\n- Features added since $(LAST_RELEASE)\n"
	@git log --pretty=format:'%s' --no-merges --abbrev-commit $(LAST_RELEASE)..HEAD \
		| sed -n -e 's/^ *Feature: */  + /p' | sort -uf
	@printf "\n- Fixes since $(LAST_RELEASE)\n"
	@git log --pretty=format:'%s' --no-merges --abbrev-commit $(LAST_RELEASE)..HEAD \
		| sed -n -e 's/^ *\(Fix\|High\|Bug\): */  + /p' | sed			\
			-e 's@\(cib\|pacemaker-based\|based\):@CIB:@' \
			-e 's@\(crmd\|pacemaker-controld\|controld\):@controller:@' \
			-e 's@\(lrmd\|pacemaker-execd\|execd\):@executor:@' \
			-e 's@\(Fencing\|stonithd\|stonith\|pacemaker-fenced\|fenced\):@fencing:@' \
			-e 's@\(PE\|pengine\|pacemaker-schedulerd\|schedulerd\):@scheduler:@' \
		| sort -uf
	@printf "\n- Public API changes since $(LAST_RELEASE)\n"
	@git log --pretty=format:'%s' --no-merges --abbrev-commit $(LAST_RELEASE)..HEAD \
		| sed -n -e 's/^ *API: */  + /p' | sort -uf

authors:
	git log $(LAST_RELEASE)..$(COMMIT) --format='%an' | sort -u

changelog:
	@$(MAKE) $(AM_MAKEFLAGS) changes > ChangeLog
	@printf "\n">> ChangeLog
	git show $(LAST_RELEASE):ChangeLog >> ChangeLog

rel-tags: tags
	find . -name TAGS -exec sed -i 's:\(.*\)/\(.*\)/TAGS:\2/TAGS:g' \{\} \;

CLANG_checkers = 

# Use CPPCHECK_ARGS to pass extra cppcheck options, e.g.:
# --enable={warning,style,performance,portability,information,all}
# --inconclusive --std=posix
CPPCHECK_ARGS ?=
BASE_CPPCHECK_ARGS = -I include --max-configs=30 --library=posix --library=gnu \
					 --library=gtk $(GLIB_CFLAGS) -D__GNUC__ --inline-suppr -q
cppcheck-all:
	cppcheck $(CPPCHECK_ARGS) $(BASE_CPPCHECK_ARGS) -DBUILD_PUBLIC_LIBPACEMAKER \
		-DDEFAULT_CONCURRENT_FENCING_TRUE replace lib daemons tools

cppcheck:
	cppcheck $(CPPCHECK_ARGS) $(BASE_CPPCHECK_ARGS) replace lib daemons tools

clang:
	OUT=$$(scan-build $(CLANG_checkers:%=-enable-checker %)		\
		$(MAKE) $(AM_MAKEFLAGS) CFLAGS="-std=c99 $(CFLAGS)"	\
		clean all 2>&1);					\
	REPORT=$$(echo "$$OUT"						\
		| sed -n -e "s/.*'scan-view \(.*\)'.*/\1/p");		\
	[ -z "$$REPORT" ] && echo "$$OUT" || scan-view "$$REPORT"

# V3	= scandir unsetenv alphasort xalloc
# V2	= setenv strerror strchrnul strndup
# https://www.gnu.org/software/gnulib/manual/html_node/Initial-import.html#Initial-import
# previously, this was crypto/md5, but got spoiled with streams/kernel crypto
GNU_MODS	= crypto/md5-buffer
# stdint appears to be surrogate only for C99-lacking environments
GNU_MODS_AVOID	= stdint
# only for plain crypto/md5: we make do without kernel-assisted crypto
# GNU_MODS_AVOID	+= crypto/af_alg
.PHONY: gnulib-update
gnulib-update:
	-test -e maint/gnulib \
	  || git clone https://git.savannah.gnu.org/git/gnulib.git maint/gnulib
	cd maint/gnulib && git pull
	maint/gnulib/gnulib-tool --libtool \
	  --source-base=lib/gnu --lgpl=2 --no-vc-files --no-conditional-dependencies \
	  $(GNU_MODS_AVOID:%=--avoid %) --import $(GNU_MODS)
	sed -i -e "s/bundled(gnulib).*/bundled(gnulib) = $(date +'%Y%m%d')/"	\
		rpm/pacemaker.spec.in
	sed -i -e "s/_GL_EXTERN_INLINE/_GL_INLINE/" \
		lib/gnu/md5.c

## Coverage/profiling

.PHONY: coverage
coverage: core
	-find . -name "*.gcda" -exec rm -f \{\} \;
	lcov --no-external --exclude='*_test.c' -c -i -d . -o pacemaker_base.info
	$(MAKE) $(AM_MAKEFLAGS) check
	lcov --no-external --exclude='*_test.c' -c -d . -o pacemaker_test.info
	lcov -a pacemaker_base.info -a pacemaker_test.info -o pacemaker_total.info
	genhtml pacemaker_total.info -o coverage -s

.PHONY: coverage-clean
coverage-clean:
	-rm -f pacemaker_*.info
	-rm -rf coverage
	-find . \( -name "*.gcno" -o -name "*.gcda" \) -exec rm -f \{\} \;

ancillary-clean: mock-clean coverity-clean coverage-clean
