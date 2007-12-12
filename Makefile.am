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
RPMFLAGS		= -ta
TARFILE			= pacemaker.tar.gz
AM_TAR			= tar

AUTOMAKE_OPTIONS	= foreign
##ACLOCAL                 = aclocal -I $(auxdir)

MAINTAINERCLEANFILES    = Makefile.in aclocal.m4 configure DRF/config-h.in \
                        DRF/stamp-h.in libtool.m4 ltdl.m4 libltdl.tar

## proc-ha is left out from SUBDIRS (completely obsolete)

if SNMP_SUBAGENT_BUILD
SNMP_SUBAGENT_DIR = snmp_subagent
endif

if CIM_PROVIDER_BUILD
CIM_PROVIDER_DIR = cim
endif

SUBDIRS	= debian build replace include lib cib crmd pengine transitioner crm tools doc cts

HANDY_DOCS = doc/ChangeLog doc/GettingStarted.html doc/DirectoryMap.txt
HBDOCS = doc/heartbeat_api.html

# Pass these to configure when running "make distcheck"
DISTCHECK_CONFIGURE_FLAGS = --with-initdir=prefix

tgz:
	rm -f $(TARFILE)
	hg archive -t tgz $(TARFILE)
	echo Rebuilt $(TARFILE) on `date`

rpm:	tgz
	$(RPM) $(RPMFLAGS) $(TARFILE) </dev/null;

deb:	tgz
	rm -rf $(distdir)
	tar -zxf $(TARFILE)
	cd $(distdir) ; dpkg-buildpackage -rfakeroot -us -uc 
	rm -rf $(distdir)

install-exec-local:

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

drpm:		dist
		$(RPM) --nodeps $(RPMFLAGS) $(TARFILE) </dev/null;

.PHONY: rpm pkg handy handy-copy
