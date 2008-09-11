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

RPM			= @RPM@
RPMFLAGS		= -ba
TARFILE			= pacemaker.tar.gz
AM_TAR			= tar
LAST_RELEASE		= 007c3a1c50f5
STABLE_SERIES		= unstable-0.7

BOMB_ADDRESS  = abeekhof@suse.de
BOMB_LAST    := $(shell test -e .bomb && cat .bomb)
BOMB_TARGET  := $(shell hg id -i)
BOMB_DATE    := $(shell python -c 'from time import *; print strftime ("%W, %Y", gmtime(time()))')
BOMB_SUBJECT := Pacemaker $(VERSION) patch update for week $(BOMB_DATE)

AUTOMAKE_OPTIONS	= foreign
##ACLOCAL                 = aclocal -I $(auxdir)

PRETTY_ARGS		= --braces-on-if-line --braces-on-struct-decl-line --cuddle-do-while --cuddle-else --leave-preprocessor-space --blank-lines-after-declarations --blank-lines-after-procedures -sc --case-indentation4 --no-space-after-function-call-names --no-blank-lines-after-commas --procnames-start-lines --leave-optional-blank-lines --indent-level4 --line-length100 --break-before-boolean-operator --ignore-newlines --no-space-after-if --no-space-after-for --no-space-after-while --paren-indentation4

MAINTAINERCLEANFILES    = Makefile.in aclocal.m4 configure DRF/config-h.in \
                        DRF/stamp-h.in libtool.m4 ltdl.m4 libltdl.tar

SUBDIRS	= debian build $(LIBLTDL_DIR) replace include lib cib crmd pengine fencing tools xml doc cts extra

tgz:
	rm -f $(TARFILE)
	hg archive -t tgz $(TARFILE)
	echo Rebuilt $(TARFILE) on `date`

bomb:
	if [ -e .bomb -a "$(BOMB_TARGET)" != "$(BOMB_LAST)" ]; then 							\
	  hg email --config ui.interactive=false -i -g -d -t $(BOMB_ADDRESS) -s '$(BOMB_SUBJECT)' -r $(BOMB_LAST):tip;	\
	  echo $(BOMB_TARGET) > .bomb;											\
	elif [ ! -e .bomb ]; then											\
	  echo "Initializing patch record";										\
	  echo $(BOMB_TARGET) > .bomb;											\
	else														\
	  echo "No patches to send";											\
	fi

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

features:
	printf "$(PACKAGE) ($(VERSION)-1) unstable; urgency=medium\n"
	printf "  * Update source tarball to revision: `hg id`\n"
	printf "  * Statistics:\n"
	printf "      Changesets: `hg out -M --template "{desc|firstline|strip}\n" ../$(STABLE_SERIES) | wc -l`\n"
	printf "      Diff:           "
	hg out -M -p ../$(STABLE_SERIES) | diffstat | tail -n 1
	printf "\n  * Changes added since $(STABLE_SERIES)\n"
	hg out -M --template "  + {desc|firstline|strip}\n" ../$(STABLE_SERIES) | grep -v Low: | sort -uf 
	printf "\n -- Andrew Beekhof <abeekhof@suse.de>  `date +"%a, %d %b %Y %T %z"`\n"

OBS_PREFIX=c001n16.suse.de:Development/obs

stable:	tgz
	make changes > .changes
	scp .changes $(TARFILE) $(OBS_PREFIX)/server:ha-clustering/pacemaker/

unstable:	tgz
	make changes > .changes
	scp .changes $(TARFILE) $(OBS_PREFIX)/server:ha-clustering:UNSTABLE/pacemaker/

factory:	tgz
	make changes > .changes
	scp .changes $(TARFILE) $(OBS_PREFIX)/server:ha-clustering:Factory/pacemaker/

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
	$(mkinstalldirs) $(DESTDIR)/$(HA_VARLIBDIR)/$(HB_PKG)/crm
	-chown $(HA_CCMUSER) $(DESTDIR)/$(HA_VARLIBDIR)/$(HB_PKG)/crm
	-chgrp $(HA_APIGROUP) $(DESTDIR)/$(HA_VARLIBDIR)/$(HB_PKG)/crm
	-chmod 750 $(DESTDIR)/$(HA_VARLIBDIR)/$(HB_PKG)/crm
	$(mkinstalldirs) $(DESTDIR)/$(HA_VARRUNDIR)/$(HB_PKG)/crm
	-chown $(HA_CCMUSER) $(DESTDIR)/$(HA_VARRUNDIR)/$(HB_PKG)/crm
	-chgrp $(HA_APIGROUP) $(DESTDIR)/$(HA_VARRUNDIR)/$(HB_PKG)/crm
	-chmod 750 $(DESTDIR)/$(HA_VARRUNDIR)/$(HB_PKG)/crm
	-test -d $(DESTDIR)$(LCRSODIR) || mkdir -p $(DESTDIR)$(LCRSODIR) 
if BUILD_AIS_SUPPORT
	rm -f $(DESTDIR)$(LCRSODIR)/pacemaker.lcrso $(DESTDIR)$(LCRSODIR)/service_crm.so
	cp $(DESTDIR)$(libdir)/service_crm.so $(DESTDIR)$(LCRSODIR)/pacemaker.lcrso
endif

clean-generic:
	find . -name ".gres.*" -exec rm \{\} \;
	find . -name "*~" -exec rm \{\} \;

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
