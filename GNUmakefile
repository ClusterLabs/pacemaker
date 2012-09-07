#
# Copyright (C) 2008 Andrew Beekhof
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

default: $(shell test ! -e configure && echo initialize) $(shell test -e configure && echo core)

-include Makefile

PACKAGE		?= pacemaker

# Force 'make dist' to be consistent with 'make export' 
distprefix		= ClusterLabs-$(PACKAGE)
distdir			= $(distprefix)-$(TAG)
TARFILE			= $(distdir).tar.gz
DIST_ARCHIVES		= $(TARFILE)

RPM_ROOT	= $(shell pwd)
RPM_OPTS	= --define "_sourcedir $(RPM_ROOT)" 	\
		  --define "_specdir   $(RPM_ROOT)" 	\
		  --define "_srcrpmdir $(RPM_ROOT)" 	\

MOCK_OPTIONS	?= --resultdir=$(RPM_ROOT)/mock --no-cleanup-after

# Default to fedora compliant spec files
# SLES:     /etc/SuSE-release
# openSUSE: /etc/SuSE-release
# RHEL:     /etc/redhat-release
# Fedora:   /etc/fedora-release, /etc/redhat-release, /etc/system-release
F       ?= $(shell test ! -e /etc/fedora-release && echo 0; test -e /etc/fedora-release && rpm --eval %{fedora})
ARCH    ?= $(shell test -e /etc/fedora-release && rpm --eval %{_arch})
MOCK_CFG ?= $(shell test -e /etc/fedora-release && echo fedora-$(F)-$(ARCH))
DISTRO  ?= $(shell test -e /etc/SuSE-release && echo suse; echo fedora)
TAG     ?= $(shell git log --pretty="format:%h" -n 1)
WITH    ?= --without=doc
#WITH    ?= --without=doc --with=gcov 

LAST_RELEASE	?= $(shell test -e /Volumes || git tag -l | grep Pacemaker | sort -Vr | head -n 1)
NEXT_RELEASE	?= $(shell test -e /Volumes || git tag -l | grep Pacemaker | sort -Vr | head -n 1 | awk -F. '/[0-9]+\./{$$3+=1;OFS=".";print $$1,$$2,$$3}')

BUILD_COUNTER	?= build.counter
LAST_COUNT      = $(shell test ! -e $(BUILD_COUNTER) && echo 0; test -e $(BUILD_COUNTER) && cat $(BUILD_COUNTER))
COUNT           = $(shell expr 1 + $(LAST_COUNT))

initialize:
	./autogen.sh
	echo "Now run configure with any arguments (eg. --prefix) specific to your system"

export: 
	rm -f $(PACKAGE)-dirty.tar.* $(PACKAGE)-tip.tar.* $(PACKAGE)-HEAD.tar.*
	if [ ! -f $(TARFILE) ]; then						\
	    rm -f $(PACKAGE).tar.*;						\
	    if [ $(TAG) = dirty ]; then 					\
		git commit -m "DO-NOT-PUSH" -a;					\
		git archive --prefix=$(distdir)/ HEAD | gzip > $(TARFILE);	\
		git reset --mixed HEAD^; 					\
	    else								\
		git archive --prefix=$(distdir)/ $(TAG) | gzip > $(TARFILE);	\
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
	cp $(PACKAGE).spec.in $@
	sed -i.sed s:%{_docdir}/%{name}:%{_docdir}/%{name}-%{version}:g $@
	sed -i.sed s:corosynclib:libcorosync:g $@
	sed -i.sed s:libexecdir}/lcrso:libdir}/lcrso:g $@
	sed -i.sed 's:%{name}-libs:lib%{name}3:g' $@
	sed -i.sed s:heartbeat-libs:heartbeat:g $@
	sed -i.sed s:cluster-glue-libs:libglue:g $@
	sed -i.sed s:libselinux-devel:automake:g $@
	sed -i.sed s:lm_sensors-devel:automake:g $@
	sed -i.sed s:bzip2-devel:libbz2-devel:g $@
	sed -i.sed s:Development/Libraries:Development/Libraries/C\ and\ C++:g $@
	sed -i.sed s:System\ Environment/Daemons:Productivity/Clustering/HA:g $@
	sed -i.sed s:bcond_without\ publican:bcond_with\ publican:g $@
	sed -i.sed s:\#global\ py_sitedir:\%global\ py_sitedir:g $@
	sed -i.sed s:docbook-style-xsl:docbook-xsl-stylesheets:g $@
	sed -i.sed s:libtool-ltdl-devel::g $@
	sed -i.sed s:publican::g $@
	sed -i.sed s:byacc::g $@
	sed -i.sed s:without\ cman:with\ cman:g $@
	sed -i.sed s:.*pacemaker.service.*::g $@
	sed -i.sed s:global\ cs_major.*:global\ cs_major\ 1:g $@
	sed -i.sed s:global\ cs_minor.*:global\ cs_minor\ 4:g $@
	@echo Rebuilt $@

# Works for all fedora based distros
$(PACKAGE)-%.spec: $(PACKAGE).spec.in
	rm -f $@
	cp $(PACKAGE).spec.in $(PACKAGE)-$*.spec
	@echo Rebuilt $@

srpm-%:	export $(PACKAGE)-%.spec
	rm -f *.src.rpm
	cp $(PACKAGE)-$*.spec $(PACKAGE).spec
	if [ -e $(BUILD_COUNTER) ]; then								\
		echo $(COUNT) > $(BUILD_COUNTER);							\
	fi
	sed -i.sed 's/Source0:.*/Source0:\ $(TARFILE)/' $(PACKAGE).spec
	sed -i.sed 's/global\ specversion.*/global\ specversion\ $(COUNT)/' $(PACKAGE).spec
	sed -i.sed 's/global\ upstream_version.*/global\ upstream_version\ $(TAG)/' $(PACKAGE).spec
	sed -i.sed 's/global\ upstream_prefix.*/global\ upstream_prefix\ $(distprefix)/' $(PACKAGE).spec
	case $(TAG) in 															\
		Pacemaker*) sed -i.sed 's/Version:.*/Version:\ $(shell echo $(TAG) | sed s:Pacemaker-::)/' $(PACKAGE).spec;;		\
		*)          sed -i.sed 's/Version:.*/Version:\ $(shell echo $(NEXT_RELEASE) | sed s:Pacemaker-::)/' $(PACKAGE).spec;; 	\
	esac
	rpmbuild -bs --define "dist .$*" $(RPM_OPTS) $(WITH)  $(PACKAGE).spec

chroot: mock-$(MOCK_CFG) mock-install-$(MOCK_CFG) mock-sh-$(MOCK_CFG)
	echo "Done"

mock-next: 
	make F=$(shell expr 1 + $(F)) mock

mock-rawhide:
	make F=rawhide mock

mock-install-%:
	echo "Installing packages"
	mock --root=$* $(MOCK_OPTIONS) --install $(RPM_ROOT)/mock/*.rpm vi sudo valgrind lcov gdb

mock-sh-%:
	echo "Connecting"
	mock --root=$* $(MOCK_OPTIONS) --shell

# eg. WITH="--with cman" make rpm
mock-%: 
	make srpm-$(firstword $(shell echo $(@:mock-%=%) | tr '-' ' '))
	-rm -rf $(RPM_ROOT)/mock
	@echo "mock --root=$* --rebuild $(WITH) $(MOCK_OPTIONS) $(RPM_ROOT)/*.src.rpm"
	mock --root=$* --no-cleanup-after --rebuild $(WITH) $(MOCK_OPTIONS) $(RPM_ROOT)/*.src.rpm

srpm:	srpm-$(DISTRO)
	echo "Done"

mock:   mock-$(MOCK_CFG)
	echo "Done"

rpm:	srpm
	@echo To create custom builds, edit the flags and options in $(PACKAGE).spec first
	rpmbuild $(RPM_OPTS) $(WITH) --rebuild $(RPM_ROOT)/*.src.rpm

dirty:
	make TAG=dirty mock

COVERITY_DIR	 = $(shell pwd)/coverity-$(TAG)
COVHOST		?= coverity.example.com
COVPASS		?= password

coverity:
	test -e configure || ./autogen.sh
	test -e Makefile || ./configure
	make core-clean
	rm -rf $(COVERITY_DIR)
	cov-build --dir $(COVERITY_DIR) make core
	@echo "Waiting for a Coverity license..."
	cov-analyze --dir $(COVERITY_DIR) --wait-for-license
	cov-format-errors --dir $(COVERITY_DIR) --emacs-style > $(TAG).coverity
	cov-format-errors --dir $(COVERITY_DIR)
	rsync -avzxlSD --progress $(COVERITY_DIR)/c/output/errors/ root@www.clusterlabs.org:/var/www/html/coverity/$(PACKAGE)/$(TAG)
	make core-clean
#	cov-commit-defects --host $(COVHOST) --dir $(COVERITY_DIR) --stream $(PACKAGE) --user auto --password $(COVPASS)
	rm -rf $(COVERITY_DIR)

global: clean-generic
	gtags -q

%.8.html: %.8
	echo groff -mandoc `man -w ./$<` -T html > $@
	groff -mandoc `man -w ./$<` -T html > $@
	rsync -azxlSD --progress $@ root@www.clusterlabs.org:/var/www/html/man/

%.7.html: %.7
	echo groff -mandoc `man -w ./$<` -T html > $@
	groff -mandoc `man -w ./$<` -T html > $@
	rsync -azxlSD --progress $@ root@www.clusterlabs.org:/var/www/html/man/

abi:
	abi-check pacemaker $(LAST_RELEASE) $(TAG)
abi-www:
	abi-check -u pacemaker $(LAST_RELEASE) $(TAG)

www:	global
	make all
	find . -name "[a-z]*.8" -exec make \{\}.html  \;
	find . -name "[a-z]*.7" -exec make \{\}.html  \;
	htags -sanhIT
	rsync -avzxlSD --progress HTML/ root@www.clusterlabs.org:/var/www/html/global/$(PACKAGE)/$(TAG)
	make -C doc www
	make coverity

summary:
	@printf "\n* `date +"%a %b %d %Y"` `hg showconfig ui.username` $(NEXT_RELEASE)-1" 
	@printf "\n- Update source tarball to revision: `git id`"
	@printf "\n- Statistics:\n"
	@printf "  Changesets: `git log --pretty=format:'%h' $(LAST_RELEASE)..HEAD | wc -l`\n" 
	@printf "  Diff:      " 
	@git diff -r $(LAST_RELEASE)..HEAD --stat | tail -n 1

changes:
	@printf "\n* `date +"%a %b %d %Y"` `hg showconfig ui.username` $(NEXT_RELEASE)-1" > ChangeLog 
	@printf "\n- Update source tarball to revision: `git id`" >> ChangeLog 
	@printf "\n- Statistics:\n">> ChangeLog 
	@printf "  Changesets: `git log --pretty=format:'%h' $(LAST_RELEASE)..HEAD | wc -l`\n" >> ChangeLog 
	@printf "  Diff:      " >> ChangeLog 
	@git diff -r $(LAST_RELEASE)..HEAD --stat | tail -n 1 >> ChangeLog
	@printf "\n- Changes since $(LAST_RELEASE)\n" >> ChangeLog 
	@git log --pretty=format:'  +%s' --abbrev-commit $(LAST_RELEASE)..HEAD | grep -e High: | sed -e s@High:@@ -e s@PE:@pengine:@ | sort -uf >> ChangeLog 
	@printf "\n">> ChangeLog 
	git show $(LAST_RELEASE):ChangeLog >> ChangeLog
	@echo -e "\033[1;35m -- Don't forget to run the bumplibs.sh script! --\033[0m"

indent:
	find . -name "*.h" -exec ./p-indent \{\} \;
	find lib -name "*.c" -exec ./p-indent \{\} \;
	git co - lib/common/xml.c include/crm/cib_ops.h crmd/fsa_proto.h

rel-tags: tags
	find . -name TAGS -exec sed -i.sed 's:\(.*\)/\(.*\)/TAGS:\2/TAGS:g' \{\} \;

ccc_analyzer=/usr/lib64/clang-analyzer/scan-build/ccc-analyzer

clang:
	test -e $(ccc_analyzer) || echo "CLang Analyiser not available. Install the clang-analyzer package"
	test -e $(ccc_analyzer) || false
	make CC=$(ccc_analyzer) check

# V3	= scandir unsetenv alphasort 
# V2	= setenv strerror strchrnul strndup
# http://www.gnu.org/software/gnulib/manual/html_node/Initial-import.html#Initial-import
GNU_MODS	= crypto/md5
gnulib-update:
	-test ! -e gnulib && git clone git://git.savannah.gnu.org/gnulib.git
	cd gnulib && git pull
	gnulib/gnulib-tool --source-base=lib/gnu --lgpl=2 --no-vc-files --import $(GNU_MODS)
