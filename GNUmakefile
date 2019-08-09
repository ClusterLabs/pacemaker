#
# Copyright 2008-2019 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

default: $(shell test ! -e configure && echo init) $(shell test -e configure && echo core)

-include Makefile

PACKAGE		?= pacemaker

# This Makefile can create 2 types of distributions:
#
# - "make dist" is automake's native functionality, based on the various
#   dist/nodist make variables; it always uses the current sources
#
# - "make export" is a custom target based on git archive and relevant entries
#   from .gitattributes; it defaults to current sources but can use any git tag
#
# Both types use the TARFILE name for the result, though they generate
# different contents.
distdir			= $(PACKAGE)-$(SHORTTAG)
TARFILE			= $(PACKAGE)-$(SHORTTAG).tar.gz

RPM_ROOT	= $(shell pwd)
RPM_OPTS	= --define "_sourcedir $(RPM_ROOT)" 	\
		  --define "_specdir   $(RPM_ROOT)" 	\
		  --define "_srcrpmdir $(RPM_ROOT)" 	\

MOCK_OPTIONS	?= --resultdir=$(RPM_ROOT)/mock --no-cleanup-after

# Default to building Fedora-compliant spec files
# SLES:     /etc/SuSE-release
# openSUSE: /etc/SuSE-release
# RHEL:     /etc/redhat-release, /etc/system-release
# Fedora:   /etc/fedora-release, /etc/redhat-release, /etc/system-release
# CentOS:   /etc/centos-release, /etc/redhat-release, /etc/system-release
F       ?= $(shell test ! -e /etc/fedora-release && echo 0; test -e /etc/fedora-release && rpm --eval %{fedora})
ARCH    ?= $(shell test -e /etc/fedora-release && rpm --eval %{_arch})
MOCK_CFG ?= $(shell test -e /etc/fedora-release && echo fedora-$(F)-$(ARCH))
DISTRO  ?= $(shell test -e /etc/SuSE-release && echo suse; echo fedora)
COMMIT  ?= HEAD
TAG     ?= $(shell T=$$(git describe --all '$(COMMIT)' 2>/dev/null | sed -n 's|tags/\(.*\)|\1|p'); \
	     test -n "$${T}" && echo "$${T}" \
	       || git log --pretty=format:%H -n 1 '$(COMMIT)' 2>/dev/null || echo DIST)
lparen = (
rparen = )
SHORTTAG ?= $(shell case $(TAG) in Pacemaker-*|DIST$(rparen) echo '$(TAG)' | cut -c11-;; \
	      *$(rparen) git log --pretty=format:%h -n 1 '$(TAG)';; esac)
SHORTTAG_ABBREV = $(shell printf %s '$(SHORTTAG)' | wc -c)
WITH    ?= --without doc
#WITH    ?= --without=doc --with=gcov

LAST_RC		?= $(shell test -e /Volumes || git tag -l | grep Pacemaker | sort -Vr | grep rc | head -n 1)
ifneq ($(origin VERSION), undefined)
LAST_RELEASE	?= Pacemaker-$(VERSION)
else
LAST_RELEASE	?= $(shell git tag -l | grep Pacemaker | sort -Vr | grep -v rc | head -n 1)
endif
NEXT_RELEASE	?= $(shell echo $(LAST_RELEASE) | awk -F. '/[0-9]+\./{$$3+=1;OFS=".";print $$1,$$2,$$3}')

BUILD_COUNTER	?= build.counter
LAST_COUNT      = $(shell test ! -e $(BUILD_COUNTER) && echo 0; test -e $(BUILD_COUNTER) && cat $(BUILD_COUNTER))
COUNT           = $(shell expr 1 + $(LAST_COUNT))

SPECVERSION	?= $(COUNT)

# rpmbuild wrapper that translates "--with[out] FEATURE" into RPM macros
#
# Unfortunately, at least recent versions of rpm do not support mentioned
# switch.  To work this around, we can emulate mechanism that rpm uses
# internally: unfold the flags into respective macro definitions:
#
#    --with[out] FOO  ->  --define "_with[out]_FOO --with[out]-FOO"
#
# $(1) ... WITH string (e.g., --with pre_release --without doc)
# $(2) ... options following the initial "rpmbuild" in the command
# $(3) ... final arguments determined with $2 (e.g., pacemaker.spec)
#
# Note that if $(3) is a specfile, extra case is taken so as to reflect
# pcmkversion correctly (using in-place modification).
#
# Also note that both ways to specify long option with an argument
# (i.e., what getopt and, importantly, rpm itself support) can be used:
#
#    --with FOO
#    --with=FOO
rpmbuild-with = \
	WITH=$$(getopt -o "" -l with:,without: -- $(1)) || exit 1; \
	CMD='rpmbuild $(2)'; PREREL=0; \
	eval set -- "$${WITH}"; \
	while true; do \
		case "$$1" in \
		--with) CMD="$${CMD} --define \"_with_$$2 --with-$$2\""; \
			[ "$$2" != pre_release ] || PREREL=1; shift 2;; \
		--without) CMD="$${CMD} --define \"_without_$$2 --without-$$2\""; \
		        [ "$$2" != pre_release ] || PREREL=0; shift 2;; \
		--) shift ; break ;; \
		*) echo "cannot parse WITH: $$1"; exit 1;; \
		esac; \
	done; \
	case "$(3)" in \
	*.spec) { [ $${PREREL} -eq 0 ] || [ $(LAST_RELEASE) = $(TAG) ]; } \
		&& sed -i "s/^\(%global pcmkversion \).*/\1$$(echo $(LAST_RELEASE) | sed -e s:Pacemaker-:: -e s:-.*::)/" $(3) \
		|| sed -i "s/^\(%global pcmkversion \).*/\1$$(echo $(NEXT_RELEASE) | sed -e s:Pacemaker-:: -e s:-.*::)/" $(3);; \
	esac; \
	CMD="$${CMD} $(3)"; \
	eval "$${CMD}"

init:
	./autogen.sh

# @TODO This should probably be what init does
.PHONY: init-if-needed
init-if-needed:
	test -e configure || ./autogen.sh
	test -e Makefile || ./configure

export:
	rm -f $(PACKAGE)-dirty.tar.* $(PACKAGE)-tip.tar.* $(PACKAGE)-HEAD.tar.*
	if [ ! -f $(TARFILE) ]; then						\
	    rm -f $(PACKAGE).tar.*;						\
	    if [ $(TAG) = dirty ]; then 					\
		git commit -m "DO-NOT-PUSH" -a;					\
		git archive --prefix=$(distdir)/ -o "$(TARFILE)" HEAD^{tree};	\
		git reset --mixed HEAD^; 					\
	    else								\
		git archive --prefix=$(distdir)/ -o "$(TARFILE)" $(TAG)^{tree};	\
	    fi;									\
	    echo `date`: Rebuilt $(TARFILE);					\
	else									\
	    echo `date`: Using existing tarball: $(TARFILE);			\
	fi

$(PACKAGE)-opensuse.spec: $(PACKAGE)-suse.spec
	cp $^ $@
	@echo Rebuilt $@

$(PACKAGE)-suse.spec: $(PACKAGE).spec.in GNUmakefile
	rm -f $@
	if [ x != x"`git ls-files -m | grep pacemaker.spec.in`" ]; then		\
	    cp $(PACKAGE).spec.in $@;						\
	    echo "Rebuilt $@ (local modifications)";				\
	elif [ x = x"`git show $(TAG):pacemaker.spec.in 2>/dev/null`" ]; then	\
	    cp $(PACKAGE).spec.in $@;						\
	    echo "Rebuilt $@";							\
	else 									\
	    git show $(TAG):$(PACKAGE).spec.in >> $@;				\
	    echo "Rebuilt $@ from $(TAG)";					\
	fi
	sed -i									\
	    -e 's:%{_docdir}/%{name}:%{_docdir}/%{name}-%{version}:g'		\
	    -e 's:%{name}-libs:lib%{name}3:g'					\
	    -e 's: libtool-ltdl-devel\(%{?_isa}\)\?::g'				\
	    -e 's:bzip2-devel:libbz2-devel:g'					\
	    -e 's:docbook-style-xsl:docbook-xsl-stylesheets:g'			\
	    -e 's: byacc::g'							\
	    -e 's:gnutls-devel:libgnutls-devel:g'				\
	    -e 's:corosynclib:libcorosync:g'					\
	    -e 's:cluster-glue-libs:libglue:g'					\
	    -e 's:shadow-utils:shadow:g'					\
	    -e 's: publican::g'							\
	    -e 's: 189: 90:g'							\
	    -e 's:%{_libexecdir}/lcrso:%{_libdir}/lcrso:g'			\
	    -e 's:procps-ng:procps:g'						\
	    $@
	@echo "Applied SUSE-specific modifications"


# Works for all fedora based distros
$(PACKAGE)-%.spec: $(PACKAGE).spec.in
	rm -f $@
	if [ x != x"`git ls-files -m | grep pacemaker.spec.in`" ]; then		\
	    cp $(PACKAGE).spec.in $(PACKAGE)-$*.spec;				\
	    echo "Rebuilt $@ (local modifications)";				\
	elif [ x = x"`git show $(TAG):pacemaker.spec.in 2>/dev/null`" ]; then	\
	    cp $(PACKAGE).spec.in $(PACKAGE)-$*.spec;				\
	    echo "Rebuilt $@";							\
	else 									\
	    git show $(TAG):$(PACKAGE).spec.in >> $(PACKAGE)-$*.spec;		\
	    echo "Rebuilt $@ from $(TAG)";					\
	fi

srpm-%:	export $(PACKAGE)-%.spec
	rm -f *.src.rpm
	cp $(PACKAGE)-$*.spec $(PACKAGE).spec
	echo "* $(shell date +"%a %b %d %Y") Andrew Beekhof <andrew@beekhof.net> $(shell git describe --tags $(TAG) | sed -e s:Pacemaker-:: -e s:-.*::)-1" >> $(PACKAGE).spec
	echo " - See included ChangeLog file or https://raw.github.com/ClusterLabs/pacemaker/master/ChangeLog for full details" >> $(PACKAGE).spec
	if [ -e $(BUILD_COUNTER) ]; then					\
		echo $(COUNT) > $(BUILD_COUNTER);				\
	fi
	sed -e 's/global\ specversion\ .*/global\ specversion\ $(SPECVERSION)/' \
	    -e 's/global\ commit\ .*/global\ commit\ $(SHORTTAG)/' \
	    -e 's/global\ commit_abbrev\ .*/global\ commit_abbrev\ $(SHORTTAG_ABBREV)/' \
	    -i $(PACKAGE).spec
	$(call rpmbuild-with,$(WITH),-bs --define "dist .$*" $(RPM_OPTS),$(PACKAGE).spec)

chroot: mock-$(MOCK_CFG) mock-install-$(MOCK_CFG) mock-sh-$(MOCK_CFG)
	@echo "Done"

mock-next:
	make F=$(shell expr 1 + $(F)) mock

mock-rawhide:
	make F=rawhide mock

mock-install-%:
	@echo "Installing packages"
	mock --root=$* $(MOCK_OPTIONS) --install $(RPM_ROOT)/mock/*.rpm vi sudo valgrind lcov gdb fence-agents psmisc

mock-install: mock-install-$(MOCK_CFG)
	@echo "Done"

mock-sh: mock-sh-$(MOCK_CFG)
	@echo "Done"

mock-sh-%:
	@echo "Connecting"
	mock --root=$* $(MOCK_OPTIONS) --shell
	@echo "Done"

# eg. make WITH="--with pre_release" rpm
mock-%:
	make srpm-$(firstword $(shell echo $(@:mock-%=%) | tr '-' ' '))
	-rm -rf $(RPM_ROOT)/mock
	@echo "mock --root=$* --rebuild $(WITH) $(MOCK_OPTIONS) $(RPM_ROOT)/*.src.rpm"
	mock --root=$* --no-cleanup-after --rebuild $(WITH) $(MOCK_OPTIONS) $(RPM_ROOT)/*.src.rpm

srpm:	srpm-$(DISTRO)
	@echo "Done"

mock:   mock-$(MOCK_CFG)
	@echo "Done"

rpm-dep: $(PACKAGE)-$(DISTRO).spec
	if [ x != x`which yum-builddep 2>/dev/null` ]; then			\
	    echo "Installing with yum-builddep";		\
	    sudo yum-builddep $(PACKAGE)-$(DISTRO).spec;	\
	elif [ x != x`which yum 2>/dev/null` ]; then				\
	    echo -e "Installing: $(shell grep BuildRequires pacemaker.spec.in | sed -e s/BuildRequires:// -e s:\>.*0:: | tr '\n' ' ')\n\n";	\
	    sudo yum install $(shell grep BuildRequires pacemaker.spec.in | sed -e s/BuildRequires:// -e s:\>.*0:: | tr '\n' ' ');	\
	elif [ x != x`which zypper` ]; then			\
	    echo -e "Installing: $(shell grep BuildRequires pacemaker.spec.in | sed -e s/BuildRequires:// -e s:\>.*0:: | tr '\n' ' ')\n\n";	\
	    sudo zypper install $(shell grep BuildRequires pacemaker.spec.in | sed -e s/BuildRequires:// -e s:\>.*0:: | tr '\n' ' ');\
	else							\
	    echo "I don't know how to install $(shell grep BuildRequires pacemaker.spec.in | sed -e s/BuildRequires:// -e s:\>.*0:: | tr '\n' ' ')";\
	fi

rpm:	srpm
	@echo To create custom builds, edit the flags and options in $(PACKAGE).spec first
	$(call rpmbuild-with,$(WITH),$(RPM_OPTS),--rebuild $(RPM_ROOT)/*.src.rpm)

release:
	make TAG=$(LAST_RELEASE) rpm

rc:
	make TAG=$(LAST_RC) rpm

dirty:
	make TAG=dirty mock


## Static analysis via coverity

# Aggressiveness (low, medium, or high)
COVLEVEL	?= low

# Generated outputs
COVERITY_DIR	= $(builddir)/coverity-$(TAG)
COVTAR		= $(builddir)/$(PACKAGE)-coverity-$(TAG).tgz
COVEMACS	= $(builddir)/$(TAG).coverity
COVHTML		= $(COVERITY_DIR)/output/errors

# Coverity outputs are phony so they get rebuilt every invocation

.PHONY: $(COVERITY_DIR)
$(COVERITY_DIR): init-if-needed core-clean coverity-clean
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
	@echo "  file://$(abs_builddir)/$(COVHTML)/index.html"
	@echo "When no longer needed, make coverity-clean"

# Remove all outputs regardless of tag
.PHONY: coverity-clean
coverity-clean:
	-rm -rf "$(builddir)"/coverity-*			\
		"$(builddir)"/$(PACKAGE)-coverity-*.tgz		\
		"$(builddir)"/*.coverity


## Change log generation

summary:
	@printf "\n* `date +"%a %b %d %Y"` `git config user.name` <`git config user.email`> $(NEXT_RELEASE)"
	@printf "\n- Changesets: `git log --pretty=oneline $(LAST_RELEASE)..HEAD | wc -l`"
	@printf "\n- Diff:      "
	@git diff $(LAST_RELEASE)..HEAD --shortstat include lib daemons tools xml

rc-changes:
	@make NEXT_RELEASE=$(shell echo $(LAST_RC) | sed s:-rc.*::) LAST_RELEASE=$(LAST_RC) changes

changes: summary
	@printf "\n- Features added since $(LAST_RELEASE)\n"
	@git log --pretty=format:'  +%s' --abbrev-commit $(LAST_RELEASE)..HEAD | grep -e Feature: | sed -e 's@Feature:@@' | sort -uf
	@printf "\n- Changes since $(LAST_RELEASE)\n"
	@git log --pretty=format:'  +%s' --no-merges --abbrev-commit $(LAST_RELEASE)..HEAD \
		| grep -e High: -e Fix: -e Bug | sed \
			-e 's@\(Fix\|High\|Bug\):@@' \
			-e 's@\(cib\|pacemaker-based\|based\):@CIB:@' \
			-e 's@\(crmd\|pacemaker-controld\|controld\):@controller:@' \
			-e 's@\(lrmd\|pacemaker-execd\|execd\):@executor:@' \
			-e 's@\(Fencing\|stonithd\|stonith\|pacemaker-fenced\|fenced\):@fencing:@' \
			-e 's@\(PE\|pengine\|pacemaker-schedulerd\|schedulerd\):@scheduler:@' \
		| sort -uf

authors:
	git log $(LAST_RELEASE)..$(COMMIT) --format='%an' | sort -u

changelog:
	@make changes > ChangeLog
	@printf "\n">> ChangeLog
	git show $(LAST_RELEASE):ChangeLog >> ChangeLog

DO_NOT_INDENT = lib/gnu daemons/controld/controld_fsa.h

indent:
	find . -name "*.[ch]" -exec ./p-indent \{\} \;
	git co HEAD $(DO_NOT_INDENT)

rel-tags: tags
	find . -name TAGS -exec sed -i 's:\(.*\)/\(.*\)/TAGS:\2/TAGS:g' \{\} \;

CLANG_analyzer = $(shell which scan-build)
CLANG_checkers = 

# Use CPPCHECK_ARGS to pass extra cppcheck options, e.g.:
# --enable={warning,style,performance,portability,information,all}
# --inconclusive --std=posix
CPPCHECK_ARGS ?=
cppcheck:
	cppcheck $(CPPCHECK_ARGS) -I include --max-configs=25 -q replace lib daemons tools

clang:
	test -e $(CLANG_analyzer)
	scan-build $(CLANG_checkers:%=-enable-checker %) make clean all

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
