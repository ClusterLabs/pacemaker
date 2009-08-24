#
# Pacemaker code
#
# Copyright (C) 2004 Andrew Beekhof
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

EXTRA_DIST              = autogen.sh ConfigureMe README.in libltdl.tar

MAINTAINERCLEANFILES    = Makefile.in aclocal.m4 configure DRF/config-h.in \
                        DRF/stamp-h.in libtool.m4 ltdl.m4 libltdl.tar

SUBDIRS	= debian $(LIBLTDL_DIR) replace include lib pengine cib crmd fencing tools xml cts extra doc

#RPM_ROOT		= $(abs_builddir)
RPM_ROOT		= $(top_builddir)
RPM_OPTS	= --define "_sourcedir $(RPM_ROOT)" \
		  --define "_specdir $(RPM_ROOT)" \
		  --define "_builddir $(RPM_ROOT)" \
		  --define "_srcrpmdir $(RPM_ROOT)" \
		  --define "_rpmdir $(RPM_ROOT)"

AM_TAR			= tar
TARFILE			= $(PACKAGE).tar.gz
LAST_RELEASE		= Pacemaker-1.0.4
STABLE_SERIES		= stable-1.0

AUTOMAKE_OPTIONS	= foreign
##ACLOCAL                 = aclocal -I $(auxdir)

getdistro = $(shell test -e /etc/SuSE-release || echo fedora; test -e /etc/SuSE-release && echo suse)

tgz:
	rm -f $(TARFILE)
	hg archive -X pengine/test06 -X pengine/test10 -t tgz $(TARFILE)
	echo `date`: Rebuilt $(TARFILE)

srpm:	tgz
	-rm *.src.rpm
	-echo `date`: Building Source RPM for $(call getdistro) and derivatives
	rpmbuild -bs $(RPM_OPTS) $(top_srcdir)/$(PACKAGE)-$(call getdistro).spec

rpm:	srpm
	echo To create custom builds, edit the flags and options in $(PACKAGE)-$(call getdistro).spec first
	-echo `date`: Building Binary RPM for $(call getdistro) and derivatives
	rpmbuild $(RPM_OPTS) --rebuild $(top_builddir)/*.src.rpm

mock:	srpm
	mock --root fedora-rawhide-x86_64 --rebuild $(top_builddir)/*.src.rpm

changes:
	printf "$(PACKAGE) ($(VERSION)-1) stable; urgency=medium\n"
	printf "  * Update source tarball to revision: `$(HG) id`\n"
	printf "  * Statistics:\n"
	printf "      Changesets: `$(HG) log -M --template "{desc|firstline|strip}\n" -r $(LAST_RELEASE):tip | wc -l`\n"
	printf "      Diff:           "
	$(HG) diff -r $(LAST_RELEASE):tip | diffstat | tail -n 1
	printf "\n  * Testing Notes:\n"
	printf "\n  + Test hardware:\n"
	printf "\n  + All testing was performed with STONITH enabled\n"
	printf "\n  + Pending bugs encountered during testing:\n"
	printf "\n  * Changes since $(LAST_RELEASE)\n"
	$(HG) log -M --template "  + {desc|firstline|strip}\n" -r $(LAST_RELEASE):tip | grep -v -e Dev: -e Low: | sort -uf 
	printf "\n -- Andrew Beekhof <abeekhof@suse.de>  `date +"%a, %d %b %Y %T %z"`\n"

features:
	printf "$(PACKAGE) ($(VERSION)-1) unstable; urgency=medium\n"
	printf "  * Update source tarball to revision: `$(HG) id`\n"
	printf "  * Statistics:\n"
	printf "      Changesets: `$(HG) out -M --template "{desc|firstline|strip}\n" ../$(STABLE_SERIES) | wc -l`\n"
	printf "      Diff:           "
	$(HG) out -M -p ../$(STABLE_SERIES) | diffstat | tail -n 1
	printf "\n  * Changes added since $(STABLE_SERIES)\n"
	$(HG) out -M --template "  + {desc|firstline|strip}\n" ../$(STABLE_SERIES) | grep -v -e Dev: -e Low: | sort -uf 
	printf "\n -- Andrew Beekhof <abeekhof@suse.de>  `date +"%a, %d %b %Y %T %z"`\n"

global: clean-generic
	gtags -q

global-html: global
	htags -sanhIT

global-www: global-html
	rsync -avzxlSD --progress HTML/ root@clusterlabs.org:/var/lib/global/pacemaker

pretty:
	for file in `find . -name "*.c" | tr '\n' ' '`; do	\
		gnuindent $(PRETTY_ARGS) $$file;		\
	done

deb:	
	echo To make create custom builds, edit the configure flags in debian/rules first
	dpkg-buildpackage -rfakeroot -us -uc 

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/$(LCRSODIR)
	$(INSTALL) -d -m 750 $(DESTDIR)/$(CRM_CONFIG_DIR)
	$(INSTALL) -d -m 750 $(DESTDIR)/$(CRM_STATE_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(CRM_CONFIG_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(CRM_STATE_DIR)
if BUILD_AIS_SUPPORT
	rm -f $(DESTDIR)$(LCRSODIR)/pacemaker.lcrso $(DESTDIR)$(LCRSODIR)/service_crm.so
	cp $(DESTDIR)$(libdir)/service_crm.so $(DESTDIR)$(LCRSODIR)/pacemaker.lcrso
endif
# Use chown because the user/group may not exist

dist-clean-local:
	rm -f autoconf automake autoheader $(TARFILE)

maintainer-clean-local:
	rm -f libltdl.tar

.PHONY: rpm pkg handy handy-copy
