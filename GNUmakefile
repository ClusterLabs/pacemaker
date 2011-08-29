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

-include Makefile

PACKAGE		?= pacemaker

# Force 'make dist' to be consistent with 'make export' 
distdir			= $(PACKAGE)-$(TAG)
TARFILE			= $(distdir).tar.bz2
DIST_ARCHIVES		= $(TARFILE)

LAST_RELEASE		= $(firstword $(shell hg tags| grep Pacemaker | head -n 1))

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
getdistro = $(shell test -e /etc/SuSE-release || echo fedora; test -e /etc/SuSE-release && echo suse)
PROFILE ?= $(shell rpm --eval fedora-%{fedora}-%{_arch})
DISTRO  ?= $(call getdistro)
TAG     ?= $(firstword $(shell hg id -i | tr '+' ' '))
WITH    ?= 

BUILD_COUNTER	?= build.counter
COUNT           = $(shell test ! -e $(BUILD_COUNTER) || echo $(shell expr 1 + $(shell cat $(BUILD_COUNTER))))

initialize:
	./autogen.sh
	echo "Now run configure with any arguments (eg. --prefix) specific to your system"

export: 
	rm -f $(PACKAGE)-scratch.tar.* $(PACKAGE)-tip.tar.*
	if [ ! -f $(TARFILE) ]; then						\
	    rm -f $(PACKAGE).tar.*;						\
	    if [ $(TAG) = scratch ]; then 					\
		hg commit -m "DO-NOT-PUSH";					\
		hg archive --prefix $(distdir) -t tbz2 -r tip $(TARFILE);	\
		hg rollback; 							\
	    else								\
		hg archive --prefix $(distdir) -t tbz2 -r $(TAG) $(TARFILE);	\
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
	sed -i.sed s:libexecdir:libdir:g $@
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
	@echo Rebuilt $@

# Works for all fedora based distros
$(PACKAGE)-%.spec: $(PACKAGE).spec.in
	rm -f $@
	cp $(PACKAGE).spec.in $(PACKAGE)-$*.spec
	@echo Rebuilt $@

srpm-%:	export $(PACKAGE)-%.spec
	rm -f *.src.rpm $(PACKAGE).spec
	cp $(PACKAGE)-$*.spec $(PACKAGE).spec
	if [ -e $(BUILD_COUNTER) ]; then								\
		echo $(COUNT) > $(BUILD_COUNTER);							\
		sed -i.sed 's/global\ specversion.*/global\ specversion\ $(COUNT)/' $(PACKAGE).spec;	\
	fi
	sed -i.sed 's/global\ upstream_version.*/global\ upstream_version\ $(TAG)/' $(PACKAGE).spec
	rpmbuild -bs --define "dist .$*" $(RPM_OPTS) $(WITH)  $(PACKAGE).spec

# eg. WITH="--with cman" make rpm
mock-%: 
	make srpm-$(firstword $(shell echo $(@:mock-%=%) | tr '-' ' '))
	-rm -rf $(RPM_ROOT)/mock
	@echo "mock --root=$* --rebuild $(WITH) $(MOCK_OPTIONS) $(RPM_ROOT)/*.src.rpm"
	mock -q --root=$* --rebuild $(WITH) $(MOCK_OPTIONS) $(RPM_ROOT)/*.src.rpm

srpm:	srpm-$(DISTRO)

mock:   mock-$(PROFILE)

rpm:	srpm
	@echo To create custom builds, edit the flags and options in $(PACKAGE).spec first
	rpmbuild $(RPM_OPTS) $(WITH) --rebuild $(RPM_ROOT)/*.src.rpm

scratch:
	make TAG=scratch mock

COVERITY_DIR	 = $(shell pwd)/coverity-$(TAG)
COVHOST		?= coverity.example.com
COVPASS		?= password

coverity:
	test -e configure || ./autogen.sh
	test -e Makefile || ./configure
	make clean
	rm -rf $(COVERITY_DIR)
	cov-build --dir $(COVERITY_DIR) make core
	@echo "Waiting for a Coverity license..."
	cov-analyze --dir $(COVERITY_DIR) --wait-for-license
	cov-format-errors --dir $(COVERITY_DIR) --emacs-style > $(TAG).coverity
	cov-format-errors --dir $(COVERITY_DIR)
	rsync -avzxlSD --progress $(COVERITY_DIR)/c/output/errors/ root@www.clusterlabs.org:/var/www/html/coverity/$(PACKAGE)/$(TAG)
	make clean
#	cov-commit-defects --host $(COVHOST) --dir $(COVERITY_DIR) --stream $(PACKAGE) --user auto --password $(COVPASS)
#	rm -rf $(COVERITY_DIR)

global: clean-generic
	gtags -q

www:	global
	htags -sanhIT
	rsync -avzxlSD --progress HTML/ root@www.clusterlabs.org:/var/www/html/global/$(PACKAGE)/$(TAG)
	make coverity
	make -C docs www

changes:
	@printf "\n* `date +"%a %b %d %Y"` `hg showconfig ui.username` $(VERSION)-1"
	@printf "\n- Update source tarball to revision: `hg id`"
	@printf "\n- Statistics:\n"
	@printf "  Changesets: `hg log -M --template "{desc|firstline|strip}\n" -r $(LAST_RELEASE):tip | wc -l`\n"
	@printf "  Diff:      "
	@hg diff -r $(LAST_RELEASE):tip | diffstat | tail -n 1
	@printf "\n- Changes since $(LAST_RELEASE)\n"
	@hg log -M --template "  + {desc|firstline|strip}\n" -r $(LAST_RELEASE):tip | grep -v -e Dev: -e Low: -e Hg: -e "Added tag.*for changeset" | sort -uf 
	@printf "\n"

indent:
	find . -name "*.c" -exec ./p-indent \{\} \;

rel-tags: tags
	find . -name TAGS -exec sed -i.sed 's:\(.*\)/\(.*\)/TAGS:\2/TAGS:g' \{\} \;
