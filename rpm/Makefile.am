#
# Copyright 2003-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

# We want to support the use case where this file is fed straight to make
# without running automake first, so define defaults for any automake variables
# used in this file.
top_srcdir              ?= ..
abs_srcdir              ?= $(shell pwd)
abs_builddir            ?= $(abs_srcdir)
MAKE                    ?= make
PACKAGE                 ?= pacemaker
AM_V_at                 ?= @
MKDIR_P                 ?= mkdir -p

include $(top_srcdir)/mk/common.mk
include $(top_srcdir)/mk/release.mk

EXTRA_DIST		= pacemaker.spec.in		\
			  rpmlintrc

# Where to put RPM artifacts; possible values:
#
# - subtree (default): RPM sources (i.e. TARFILE) in top-level build directory,
#   everything else in dedicated "rpm" subdirectory of build tree
#
# - toplevel (deprecated): RPM sources, spec, and source rpm in top-level build
#   directory, everything else uses the usual rpmbuild defaults
#
# - anything else: The value will be treated as a directory path to be used for
#   all RPM artifacts. WARNING: The entire directory will get removed with
#   "make clean" or "make rpm-clean".
#
RPMDEST         	?= subtree

RPM_SPEC_DIR_subtree	= $(abs_builddir)/SPECS
RPM_SRCRPM_DIR_subtree	= $(abs_builddir)/SRPMS
RPM_OPTS_subtree	= --define "_sourcedir $(abs_builddir)/.." 	\
			  --define "_topdir $(abs_builddir)"
RPM_CLEAN_subtree	= "$(abs_builddir)/BUILD"			\
			  "$(abs_builddir)/BUILDROOT"			\
			  "$(abs_builddir)/RPMS"			\
			  "$(abs_builddir)/SPECS"			\
			  "$(abs_builddir)/SRPMS"

RPM_SPEC_DIR_toplevel	= $(abs_builddir)/..
RPM_SRCRPM_DIR_toplevel	= $(abs_builddir)/..
RPM_OPTS_toplevel	= --define "_sourcedir $(abs_builddir)/.." 		\
			  --define "_specdir   $(RPM_SPEC_DIR_toplevel)"	\
			  --define "_srcrpmdir $(RPM_SRCRPM_DIR_toplevel)"
RPM_CLEAN_toplevel	=

RPM_SPEC_DIR_other	= $(RPMDEST)/SPECS
RPM_SRCRPM_DIR_other	= $(RPMDEST)/SRPMS
RPM_OPTS_other		= --define "_sourcedir $(abs_builddir)/.." 	\
			  --define "_topdir $(RPMDEST)"
RPM_CLEAN_other		= "$(RPMDEST)"

RPMTYPE		= $(shell case "$(RPMDEST)" in 			\
			toplevel$(rparen) echo toplevel ;;	\
			subtree$(rparen) echo subtree ;;	\
			*$(rparen) echo other ;;		\
			esac)
RPM_SPEC_DIR	= $(RPM_SPEC_DIR_$(RPMTYPE))
RPM_SRCRPM_DIR	= $(RPM_SRCRPM_DIR_$(RPMTYPE))
RPM_OPTS	= $(RPM_OPTS_$(RPMTYPE))
RPM_CLEAN	= $(RPM_CLEAN_$(RPMTYPE))

WITH		?= --without doc

# If $(BUILD_COUNTER) is an existing file, its contents will be used as the
# spec version in built RPMs, unless $(SPECVERSION) is set to override it,
# and the next increment will be written back to the file after building.
BUILD_COUNTER	?= $(shell test -e build.counter && echo build.counter || echo ../build.counter)

LAST_COUNT      = $(shell test -e "$(BUILD_COUNTER)" && cat "$(BUILD_COUNTER)" || echo 0)
COUNT           = $(shell expr 1 + $(LAST_COUNT))
SPECVERSION	?= $(COUNT)

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

MOCK_DIR	= $(abs_builddir)/mock
MOCK_OPTIONS	?= --resultdir="$(MOCK_DIR)" --no-cleanup-after

F	?= $(shell test ! -e /etc/fedora-release && echo 0; test -e /etc/fedora-release && rpm --eval %{fedora})
ARCH	?= $(shell test ! -e /etc/fedora-release && uname -m; test -e /etc/fedora-release && rpm --eval %{_arch})
MOCK_CFG	?= $(shell test -e /etc/fedora-release && echo fedora-$(F)-$(ARCH))

distdir		= $(top_distdir)/rpm
TARFILE		= $(abs_builddir)/../$(top_distdir).tar.gz

export:
	if [ -f "$(TARFILE)" ]; then							\
	    echo "`date`: Using existing tarball: $(TARFILE)";				\
	else										\
	    cd $(abs_srcdir)/..;							\
	    if [ -n "$(DIRTY)" ]; then 							\
	        git commit -m "DO-NOT-PUSH" -a;						\
	        git archive --prefix=$(top_distdir)/ -o "$(TARFILE)" HEAD^{tree};	\
	        git reset --mixed HEAD^;						\
	    else									\
	        git archive --prefix=$(top_distdir)/ -o "$(TARFILE)" $(TAG)^{tree};	\
	    fi;										\
	    echo "`date`: Rebuilt $(TARFILE)";						\
	fi

# Depend on spec-clean so the spec gets rebuilt every time
$(RPM_SPEC_DIR)/$(PACKAGE).spec: spec-clean pacemaker.spec.in
	$(AM_V_at)$(MKDIR_P) "$(RPM_SPEC_DIR)"
	$(AM_V_GEN)if [ x"`git ls-files -m pacemaker.spec.in 2>/dev/null`" != x ]; then	\
	    cat "$(abs_srcdir)/pacemaker.spec.in";					\
	elif git cat-file -e $(TAG):rpm/pacemaker.spec.in 2>/dev/null; then		\
	    git show $(TAG):rpm/pacemaker.spec.in;					\
	elif git cat-file -e $(TAG):pacemaker.spec.in 2>/dev/null; then			\
	    git show $(TAG):pacemaker.spec.in;						\
	else 										\
	    cat "$(abs_srcdir)/pacemaker.spec.in";					\
	fi | sed									\
	    -e 's/^\(%global pcmkversion \).*/\1$(SPEC_RELEASE_NO)/'			\
	    -e 's/^\(%global specversion \).*/\1$(SPECVERSION)/' 			\
	    -e 's/^\(%global commit \).*/\1$(SPEC_COMMIT)/'				\
	    -e 's/^\(%global commit_abbrev \).*/\1$(SPEC_ABBREV)/'			\
	    -e "s/PACKAGE_DATE/$$(date +'%a %b %d %Y')/"				\
	    -e 's/PACKAGE_VERSION/$(SPEC_RELEASE_NO)-$(SPECVERSION)/'			\
	    > "$@"

.PHONY: spec $(PACKAGE).spec
spec $(PACKAGE).spec: $(RPM_SPEC_DIR)/$(PACKAGE).spec

spec-clean:
	-rm -f "$(RPM_SPEC_DIR)/$(PACKAGE).spec"

.PHONY: srpm
srpm:	export srpm-clean $(RPM_SPEC_DIR)/$(PACKAGE).spec
	if [ -e "$(BUILD_COUNTER)" ]; then		\
		echo $(COUNT) > "$(BUILD_COUNTER)";	\
	fi
	rpmbuild -bs $(RPM_OPTS) $(WITH) "$(RPM_SPEC_DIR)/$(PACKAGE).spec"

.PHONY: srpm-clean
srpm-clean:
	-rm -f "$(RPM_SRCRPM_DIR)"/*.src.rpm

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
	rpmlint -f rpmlintrc "$<"

.PHONY: rpm-dep
rpm-dep: $(RPM_SPEC_DIR)/$(PACKAGE).spec
	sudo yum-builddep "$(RPM_SPEC_DIR)/$(PACKAGE).spec"

.PHONY: release
release:
	$(MAKE) $(AM_MAKEFLAGS) TAG=$(LAST_RELEASE) rpm

.PHONY: rc
rc:
	$(MAKE) $(AM_MAKEFLAGS) TAG=$(LAST_RC) rpm

.PHONY: chroot
chroot: mock-$(MOCK_CFG) mock-install-$(MOCK_CFG) mock-sh-$(MOCK_CFG)
	@echo Done

.PHONY: mock-next
mock-next:
	$(MAKE) $(AM_MAKEFLAGS) F=$(shell expr 1 + $(F)) mock

.PHONY: mock-rawhide
mock-rawhide:
	$(MAKE) $(AM_MAKEFLAGS) F=rawhide mock

mock-install-%:
	@echo "Installing packages"
	mock --root=$* $(MOCK_OPTIONS) --install "$(MOCK_DIR)"/*.rpm \
		vi sudo valgrind lcov gdb fence-agents psmisc

.PHONY: mock-install
mock-install: mock-install-$(MOCK_CFG)
	@echo Done

.PHONY: mock-sh
mock-sh: mock-sh-$(MOCK_CFG)
	@echo Done

mock-sh-%:
	@echo Connecting
	mock --root=$* $(MOCK_OPTIONS) --shell
	@echo Done

mock-%: srpm mock-clean
	mock $(MOCK_OPTIONS) --root=$* --no-cleanup-after --rebuild	\
		$(WITH) "$(RPM_SRCRPM_DIR)"/*.src.rpm

.PHONY: mock
mock:   mock-$(MOCK_CFG)
	@echo Done

.PHONY: dirty
dirty:
	$(MAKE) $(AM_MAKEFLAGS) DIRTY=yes mock

.PHONY: mock-clean
mock-clean:
	-rm -rf "$(MOCK_DIR)"

clean-local: mock-clean rpm-clean
	-rm -f "$(TARFILE)"
