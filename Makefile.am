#
# linux-ha: Linux-HA code
#
# Copyright (C) 2002 Alan Robertson
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

EXTRA_DIST              = bootstrap ConfigureMe README.in libltdl.tar

RPM			= @RPM@
RPMFLAGS		= -ba
TARFILE			= pacemaker.tar.gz
AM_TAR			= tar
LAST_RELEASE		= Pacemaker-0.6.3

AUTOMAKE_OPTIONS	= foreign
##ACLOCAL                 = aclocal -I $(auxdir)

MAINTAINERCLEANFILES    = Makefile.in aclocal.m4 configure DRF/config-h.in \
                        DRF/stamp-h.in libtool.m4 ltdl.m4 libltdl.tar

SUBDIRS	= debian build replace include lib cib crmd pengine transitioner crm tools doc cts

tgz:
	rm -f $(TARFILE)
	hg archive -t tgz $(TARFILE)
	echo Rebuilt $(TARFILE) on `date`

changes:
	printf "$(PACKAGE) ($(VERSION)-1) stable; urgency=medium\n"
	printf "  * Update source tarball to revision: `hg id`\n"
	printf "  * Statistics:\n"
	printf "      Changesets: `hg log -M --template "{desc|firstline|strip}\n" -r $(LAST_RELEASE):tip | wc -l`\n"
	printf "      Diff:           "
	hg diff -r $(LAST_RELEASE):tip | diffstat | tail -n 1
	printf "\n  * Testing Notes:\n"
	printf "\n  + Test hardware:\n"
	printf "\n  + All testing was performed with STONITH enabled\n"
	printf "\n  + Pending bugs encountered during testing:\n"
	printf "\n  * Changes since $(LAST_RELEASE)\n"
	hg log -M --template "  + {desc|firstline|strip}\n" -r $(LAST_RELEASE):tip | grep -v Low: | sort -uf 
	printf "\n -- Andrew Beekhof <abeekhof@suse.de>  `date +"%a, %d %b %Y %T %z"`\n"

obs:	tgz
	make changes > .changes
	scp .changes $(TARFILE) vmhost.beekhof.net:Development/obs/server:ha-clustering/pacemaker/

home:	tgz
	make changes > .changes
	scp .changes $(TARFILE) vmhost.beekhof.net:Development/obs/home:beekhof/pacemaker-test/

global:
	gtags
	htags -sanhIT

global-www: global
	rsync -avzxlSD --progress HTML/ root@clusterlabs.org:/var/lib/global/pacemaker

rpmtgz: tgz
	echo "Installing $(TARFILE) into /usr/src/packages/SOURCES for rpm"
	-test -d /usr/src/packages/SOURCES && cp $(TARFILE) /usr/src/packages/SOURCES/
	-test -d /usr/src/redhat/SOURCES && cp $(TARFILE) /usr/src/redhat/SOURCES/

rpm:	rpmtgz
	$(RPM) $(RPMFLAGS) $(top_srcdir)/pacemaker.spec </dev/null;

drpm:	rpmtgz
	$(RPM) --nodeps $(RPMFLAGS) $(top_srcdir)/pacemaker.spec </dev/null;


deb:	tgz
	rm -rf $(distdir)
	tar -zxf $(TARFILE)
	cd $(distdir) ; dpkg-buildpackage -rfakeroot -us -uc 
	rm -rf $(distdir)

install-exec-local:
	test -d $(DESTDIR)$(LCRSODIR) || mkdir -p $(DESTDIR)$(LCRSODIR)
if BUILD_AIS_SUPPORT
	rm -f $(DESTDIR)$(LCRSODIR)/pacemaker.lcrso $(DESTDIR)$(LCRSODIR)/service_crm.so
	cp $(DESTDIR)$(libdir)/service_crm.so $(DESTDIR)$(LCRSODIR)/pacemaker.lcrso
endif

dist-clean-local:
	rm -f autoconf automake autoheader $(TARFILE)

maintainer-clean-local:
	rm -f libltdl.tar

# "pkg" format for Solaris etc.
pkg:
		(cd build/pkg && $(MAKE) PWD=`pwd` pkg)

# "port" format for BSD
portfile:	dist
		( cd build/port && $(MAKE) PWD=`pwd` portfile)

.PHONY: rpm pkg handy handy-copy
