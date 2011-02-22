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

initialize:
	./autogen.sh
	echo "Now run configure with any arguments (eg. --prefix) specific to your system"

export: 
	rm -f $(PACKAGE)-scratch.tar.* $(PACKAGE)-tip.tar.*
	if [ ! -f $(TARFILE) ]; then						\
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

$(PACKAGE)-suse.spec: $(PACKAGE).spec.in
	rm -f $@
	cp $(PACKAGE).spec.in $@
	sed -i.sed s:%{_docdir}/%{name}:%{_docdir}/%{name}-%{version}:g $@
	sed -i.sed s:corosynclib:libcorosync:g $@
	sed -i.sed s:pacemaker-libs:libpacemaker3:g $@
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
	@echo Rebuilt $@

#sed -i.sed 's/global\ specversion.*/global\ specversion\ $(shell expr 1 + $(lastword $(shell grep "global specversion" $(VARIANT)$(PACKAGE).spec)))/' $(PACKAGE)-$(DISTRO).spec

# Works for all fedora based distros
$(PACKAGE)-%.spec: $(PACKAGE).spec.in
	rm -f $@
	cp $(PACKAGE).spec.in $(PACKAGE)-$*.spec
	@echo Rebuilt $@

srpm-%:	export $(PACKAGE)-%.spec
	rm -f *.src.rpm $(PACKAGE).spec
	cp $(PACKAGE)-$*.spec $(PACKAGE).spec
	sed -i.sed 's/global\ upstream_version.*/global\ upstream_version\ $(TAG)/' $(PACKAGE).spec
	rpmbuild -bs --define "dist .$*" $(RPM_OPTS) $(PACKAGE).spec

# eg. WITH="--with cman" make rpm
mock-%: 
	make srpm-$(firstword $(shell echo $(@:mock-%=%) | tr '-' ' '))
	-rm -rf $(RPM_ROOT)/mock
	mock --root=$* --resultdir=$(RPM_ROOT)/mock --rebuild $(WITH) $(RPM_ROOT)/*.src.rpm

srpm:	srpm-$(DISTRO)

mock:   mock-$(PROFILE)

rpm:	srpm
	@echo To create custom builds, edit the flags and options in $(PACKAGE).spec first
	rpmbuild $(RPM_OPTS) $(WITH) --rebuild $(RPM_ROOT)/*.src.rpm

scratch:
	make TAG=scratch mock

deb:	
	echo To make create custom builds, edit the configure flags in debian/rules first
	dpkg-buildpackage -rfakeroot -us -uc 

global: clean-generic
	gtags -q

global-html: global
	htags -sanhIT

global-www: global-html
	rsync -avzxlSD --progress HTML/ root@www.clusterlabs.org:/var/lib/global/$(PACKAGE)

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

rel-tags: tags
	find . -name TAGS -exec sed -i.sed 's:\(.*\)/\(.*\)/TAGS:\2/TAGS:g' \{\} \;
