#
# Copyright 2008-2021 the Pacemaker project contributors
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

# SPEC_COMMIT is identical to TAG for DIST and tagged releases, otherwise it is
# the short commit ID (which must be used in order for "make export" to use the
# same archive name as "make dist")
SPEC_COMMIT	?= $(shell						\
		case $(TAG) in						\
		    Pacemaker-*|DIST$(rparen)				\
		        echo '$(TAG)' ;;				\
		    *$(rparen)						\
		        git log --pretty=format:%h -n 1 '$(TAG)';;	\
		esac)$(shell						\
		if [ x$(DIRTY) != x ]; then echo ".mod"; fi)
SPEC_ABBREV	= $(shell printf %s '$(SPEC_COMMIT)' | wc -c)
SPEC_RELEASE	= $(shell case "$(WITH)" in 				\
		  *pre_release*$(rparen)				\
			[ "$(LAST_RELEASE)" = "$(TAG)" ]		\
				&& echo "$(LAST_RELEASE)"		\
				|| echo "$(NEXT_RELEASE)" ;;		\
		  *$(rparen)						\
			echo "$(LAST_RELEASE)" ;;			\
		  esac)
SPEC_RELEASE_NO	= $(shell echo $(SPEC_RELEASE) | sed -e s:Pacemaker-:: -e s:-.*::)

# indent target: Limit indent to these directories
INDENT_DIRS	?= .

# indent target: Extra options to pass to indent
INDENT_OPTS	?=

distdir		= $(top_distdir)
TARFILE		= $(abs_builddir)/$(distdir).tar.gz

.PHONY: init
init:
	test -e $(top_srcdir)/configure || ./autogen.sh
	test -e $(abs_builddir)/Makefile || $(abs_builddir)/configure

.PHONY: build
build: init
	$(MAKE) $(AM_MAKEFLAGS) core

export:
	if [ ! -f "$(TARFILE)" ]; then						\
	    if [ x$(DIRTY) != x ]; then 					\
		git commit -m "DO-NOT-PUSH" -a;					\
		git archive --prefix=$(distdir)/ -o "$(TARFILE)" HEAD^{tree};	\
		git reset --mixed HEAD^;					\
	    else								\
		git archive --prefix=$(distdir)/ -o "$(TARFILE)" $(TAG)^{tree};	\
	    fi;									\
	    echo "`date`: Rebuilt $(TARFILE)";					\
	else									\
	    echo "`date`: Using existing tarball: $(TARFILE)";			\
	fi

## RPM-related targets

# Where to put RPM artifacts; possible values:
#
# - subtree (default): RPM sources (i.e. TARFILE) in top-level build directory,
#   everything else in dedicated "rpm" subdirectory of build tree
#
# - toplevel (deprecated): RPM sources, spec, and source rpm in top-level build
#   directory, everything else uses the usual rpmbuild defaults
RPMDEST         	?= subtree

RPM_SPEC_DIR_toplevel	= $(abs_builddir)
RPM_SRCRPM_DIR_toplevel	= $(abs_builddir)
RPM_OPTS_toplevel	= --define "_sourcedir $(abs_builddir)" 		\
			  --define "_specdir   $(RPM_SPEC_DIR_toplevel)"	\
			  --define "_srcrpmdir $(RPM_SRCRPM_DIR_toplevel)"
RPM_CLEAN_toplevel	=

RPM_SPEC_DIR_subtree	= $(abs_builddir)/rpm/SPECS
RPM_SRCRPM_DIR_subtree	= $(abs_builddir)/rpm/SRPMS
RPM_OPTS_subtree	= --define "_sourcedir $(abs_builddir)" 		\
			  --define "_topdir $(abs_builddir)/rpm"
RPM_CLEAN_subtree	= "$(abs_builddir)/rpm/BUILD"		\
			  "$(abs_builddir)/rpm/BUILDROOT"	\
			  "$(abs_builddir)/rpm/RPMS"		\
			  "$(abs_builddir)/rpm/SPECS"		\
			  "$(abs_builddir)/rpm/SRPMS"

RPM_SPEC_DIR	= $(RPM_SPEC_DIR_$(RPMDEST))
RPM_SRCRPM_DIR	= $(RPM_SRCRPM_DIR_$(RPMDEST))
RPM_OPTS	= $(RPM_OPTS_$(RPMDEST))
RPM_CLEAN	= $(RPM_CLEAN_$(RPMDEST))

WITH		?= --without doc
BUILD_COUNTER	?= build.counter
LAST_COUNT      = $(shell test ! -e $(BUILD_COUNTER) && echo 0; test -e $(BUILD_COUNTER) && cat $(BUILD_COUNTER))
COUNT           = $(shell expr 1 + $(LAST_COUNT))
SPECVERSION	?= $(COUNT)

MOCK_DIR	= $(abs_builddir)/mock
MOCK_OPTIONS	?= --resultdir=$(MOCK_DIR) --no-cleanup-after

F	?= $(shell test ! -e /etc/fedora-release && echo 0; test -e /etc/fedora-release && rpm --eval %{fedora})
ARCH	?= $(shell test ! -e /etc/fedora-release && uname -m; test -e /etc/fedora-release && rpm --eval %{_arch})
MOCK_CFG	?= $(shell test -e /etc/fedora-release && echo fedora-$(F)-$(ARCH))

# Depend on spec-clean so it gets rebuilt every time
$(RPM_SPEC_DIR)/$(PACKAGE).spec: spec-clean rpm/pacemaker.spec.in
	$(AM_V_at)$(MKDIR_P) $(RPM_SPEC_DIR)	# might not exist in VPATH build
	$(AM_V_GEN)if [ x != x"`git ls-files -m rpm/pacemaker.spec.in 2>/dev/null`" ]; then	\
	    cat $(abs_srcdir)/rpm/pacemaker.spec.in;							\
	elif git cat-file -e $(TAG):rpm/pacemaker.spec.in 2>/dev/null; then		\
	    git show $(TAG):rpm/pacemaker.spec.in;					\
	elif git cat-file -e $(TAG):pacemaker.spec.in 2>/dev/null; then			\
	    git show $(TAG):pacemaker.spec.in;						\
	else 										\
	    cat $(abs_srcdir)/rpm/pacemaker.spec.in;							\
	fi | sed									\
	    -e 's/^\(%global pcmkversion \).*/\1$(SPEC_RELEASE_NO)/'			\
	    -e 's/^\(%global specversion \).*/\1$(SPECVERSION)/' 			\
	    -e 's/^\(%global commit \).*/\1$(SPEC_COMMIT)/'				\
	    -e 's/^\(%global commit_abbrev \).*/\1$(SPEC_ABBREV)/'			\
	    -e "s/PACKAGE_DATE/$$(date +'%a %b %d %Y')/"				\
	    -e 's/PACKAGE_VERSION/$(SPEC_RELEASE_NO)-$(SPECVERSION)/'			\
	    > "$@"

.PHONY: $(PACKAGE).spec
$(PACKAGE).spec: $(RPM_SPEC_DIR)/$(PACKAGE).spec

.PHONY: spec-clean
spec-clean:
	-rm -f $(RPM_SPEC_DIR)/$(PACKAGE).spec

.PHONY: srpm
srpm:	export srpm-clean $(RPM_SPEC_DIR)/$(PACKAGE).spec
	if [ -e $(BUILD_COUNTER) ]; then					\
		echo $(COUNT) > $(BUILD_COUNTER);				\
	fi
	rpmbuild -bs $(RPM_OPTS) $(WITH) "$(RPM_SPEC_DIR)/$(PACKAGE).spec"

.PHONY: srpm-clean
srpm-clean:
	-rm -f $(RPM_SRCRPM_DIR)/*.src.rpm

.PHONY: chroot
chroot: mock-$(MOCK_CFG) mock-install-$(MOCK_CFG) mock-sh-$(MOCK_CFG)
	@echo "Done"

.PHONY: mock-next
mock-next:
	$(MAKE) $(AM_MAKEFLAGS) F=$(shell expr 1 + $(F)) mock

.PHONY: mock-rawhide
mock-rawhide:
	$(MAKE) $(AM_MAKEFLAGS) F=rawhide mock

mock-install-%:
	@echo "Installing packages"
	mock --root=$* $(MOCK_OPTIONS) --install $(MOCK_DIR)/*.rpm \
		vi sudo valgrind lcov gdb fence-agents psmisc

.PHONY: mock-install
mock-install: mock-install-$(MOCK_CFG)
	@echo "Done"

.PHONY: mock-sh
mock-sh: mock-sh-$(MOCK_CFG)
	@echo "Done"

mock-sh-%:
	@echo "Connecting"
	mock --root=$* $(MOCK_OPTIONS) --shell
	@echo "Done"

mock-%: srpm mock-clean
	mock $(MOCK_OPTIONS) --root=$* --no-cleanup-after --rebuild	\
		$(WITH) $(RPM_SRCRPM_DIR)/*.src.rpm

.PHONY: mock
mock:   mock-$(MOCK_CFG)
	@echo "Done"

.PHONY: dirty
dirty:
	$(MAKE) $(AM_MAKEFLAGS) DIRTY=yes mock

.PHONY: mock-clean
mock-clean:
	-rm -rf $(MOCK_DIR)

.PHONY: rpm-dep
rpm-dep: $(RPM_SPEC_DIR)/$(PACKAGE).spec
	sudo yum-builddep $(PACKAGE).spec

# e.g. make WITH="--with pre_release" rpm
.PHONY: rpm
rpm:	srpm
	@echo To create custom builds, edit the flags and options in $(PACKAGE).spec first
	rpmbuild $(RPM_OPTS) $(WITH) --rebuild "$(RPM_SRCRPM_DIR)"/*.src.rpm

.PHONY: rpm-clean
rpm-clean: spec-clean srpm-clean
	-if [ -n "$(RPM_CLEAN)" ]; then rm -rf $(RPM_CLEAN); fi

.PHONY: rpmlint
rpmlint: $(RPM_SPEC_DIR)/$(PACKAGE).spec
	rpmlint -f rpm/rpmlintrc "$<"

.PHONY: release
release:
	$(MAKE) $(AM_MAKEFLAGS) TAG=$(LAST_RELEASE) rpm

.PHONY: rc
rc:
	$(MAKE) $(AM_MAKEFLAGS) TAG=$(LAST_RC) rpm


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

INDENT_IGNORE_PATHS	= daemons/controld/controld_fsa.h	\
			  lib/gnu/*
INDENT_PACEMAKER_STYLE	= --blank-lines-after-declarations		\
			  --blank-lines-after-procedures		\
			  --braces-after-func-def-line			\
			  --braces-on-if-line				\
			  --braces-on-struct-decl-line			\
			  --break-before-boolean-operator		\
			  --case-brace-indentation4			\
			  --case-indentation4				\
			  --comment-indentation0			\
			  --continuation-indentation4			\
			  --continue-at-parentheses			\
			  --cuddle-do-while				\
			  --cuddle-else					\
			  --declaration-comment-column0			\
			  --declaration-indentation1			\
			  --else-endif-column0				\
			  --honour-newlines				\
			  --indent-label0				\
			  --indent-level4				\
			  --line-comments-indentation0			\
			  --line-length80				\
			  --no-blank-lines-after-commas			\
			  --no-comment-delimiters-on-blank-lines	\
			  --no-space-after-function-call-names		\
			  --no-space-after-parentheses			\
			  --no-tabs					\
			  --preprocessor-indentation2			\
			  --procnames-start-lines			\
			  --space-after-cast				\
			  --start-left-side-of-comments			\
			  --swallow-optional-blank-lines		\
			  --tab-size8

indent:
	VERSION_CONTROL=none					\
		find $(INDENT_DIRS) -type f -name "*.[ch]"	\
		$(INDENT_IGNORE_PATHS:%= ! -path '%')		\
		-exec indent $(INDENT_PACEMAKER_STYLE) $(INDENT_OPTS) \{\} \;

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
gnulib-update:
	-test -e maint/gnulib \
	  || git clone https://git.savannah.gnu.org/git/gnulib.git maint/gnulib
	cd maint/gnulib && git pull
	maint/gnulib/gnulib-tool \
	  --source-base=lib/gnu --lgpl=2 --no-vc-files --no-conditional-dependencies \
	  $(GNU_MODS_AVOID:%=--avoid %) --import $(GNU_MODS)
	sed -i -e "s/bundled(gnulib).*/bundled(gnulib) = $(date +'%Y%m%d')/"	\
		rpm/pacemaker.spec.in

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

ancillary-clean: rpm-clean mock-clean coverity-clean coverage-clean
	-rm -f $(TARFILE)
