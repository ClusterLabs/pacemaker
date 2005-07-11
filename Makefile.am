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

##auxdir                  = @ac_aux_dir@
##AUX_DIST                = $(auxdir)/install-sh $(auxdir)/missing \
##                        $(auxdir)/mkinstalldirs
##AUX_DIST_EXTRA          = $(auxdir)/readline.m4 $(auxdir)/sys_errlist.m4 \
##                        $(auxdir)/sys_siglist.m4
EXTRA_DIST              = bootstrap rc.config.heartbeat 	\
			heartbeat.spec.in heartbeat.spec	\
			ConfigureMe autoconf-2.53.diff README.in libltdl.tar 

RPMREL			= @RPMREL@
RPM			= @RPM@
RPMFLAGS		= -ta --nodeps
TARFILE			= @TARFILE@
AM_TAR			= tar
RPMDIR=$(HOME)/rpms
WEBDIR=/home/alanr/ha-web/download
HBWEBDIR=/home/alanr/ha-web/heartbeat
RPMSRC=$(DESTDIR)$(RPMDIR)/SRPMS/$(PACKAGE)-$(VERSION)-$(RPMREL).src.rpm
RPM386=$(DESTDIR)$(RPMDIR)/RPMS/i586/$(PACKAGE)-$(VERSION)-$(RPMREL).i586.rpm
RPMstonith=$(DESTDIR)$(RPMDIR)/RPMS/i586/$(PACKAGE)-stonith-$(VERSION)-$(RPMREL).i586.rpm
RPMpils=$(DESTDIR)$(RPMDIR)/RPMS/i586/$(PACKAGE)-pils-$(VERSION)-$(RPMREL).i586.rpm
RPMldir=$(DESTDIR)$(RPMDIR)/RPMS/i586/$(PACKAGE)-ldirectord-$(VERSION)-$(RPMREL).i586.rpm

ALL_RPMS = $(RPMSRC) $(RPM386) $(RPMstonith) $(RPMldir) $(RPMpils)

AUTOMAKE_OPTIONS	= foreign
##ACLOCAL                 = aclocal -I $(auxdir)

MAINTAINERCLEANFILES    = Makefile.in aclocal.m4 configure DRF/config-h.in \
                        DRF/stamp-h.in libtool.m4 ltdl.m4 libltdl.tar 
coredir = 		@HA_COREDIR@
hauser = 		@HA_CCMUSER@

## proc-ha is left out from SUBDIRS (completely obsolete)

SUBDIRS	=		$(LIBLTDL_DIR) debian pkg port replace include config	\
			lib						\
			ldirectord heartbeat membership telecom		\
			linux-ha contrib resources			\
			crm lrm snmp_subagent				\
			tools logd fencing doc cts

HANDY_DOCS = doc/ChangeLog doc/GettingStarted.html doc/DirectoryMap.txt
HBDOCS = doc/heartbeat_api.html

# Pass these to configure when running "make distcheck"
DISTCHECK_CONFIGURE_FLAGS = --with-initdir=prefix

rpm:		dist
		$(RPM) --nodeps $(RPMFLAGS) $(TARFILE) </dev/null;

deb:		dist
		rm -rf $(distdir)
		tar -zxf $(TARFILE)
		cd $(distdir) ; dpkg-buildpackage -rfakeroot -us -uc 
		rm -rf $(distdir)

install-exec-local:
	-test -p $(DESTDIR)$(coredir) || mkdir -p $(DESTDIR)$(coredir)
	-chown root $(DESTDIR)$(coredir)
	-chmod 755 $(DESTDIR)$(coredir)
	-test -p $(DESTDIR)$(coredir)/root || mkdir -p $(DESTDIR)$(coredir)/root
	-chown root $(DESTDIR)$(coredir)/root
	-chmod 700 $(DESTDIR)$(coredir)/root
	-test -p $(DESTDIR)$(coredir)/nobody || mkdir -p $(DESTDIR)$(coredir)/nobody
	-chown nobody $(DESTDIR)$(coredir)/nobody
	-chmod 700 $(DESTDIR)$(coredir)/nobody
	-test -p $(DESTDIR)$(coredir)/$(hauser) || mkdir -p $(DESTDIR)$(coredir)/$(hauser)
	-chown $(hauser) $(DESTDIR)$(coredir)/$(hauser)
	-chmod 700 $(DESTDIR)$(coredir)/$(hauser)

# "pkg" format for Solaris etc.
pkg:
		(cd pkg && $(MAKE) PWD=`pwd` pkg)

# "port" format for BSD
portfile:	dist
		( cd port && $(MAKE) PWD=`pwd` portfile)

clean-generic: am_config_clean

am_config_clean:
		rm -fr $(PACKAGE)-*.tar.gz

drpm:		dist
		$(RPM) --nodeps $(RPMFLAGS) $(TARFILE) </dev/null;
handy: drpm handy-copy

handy-copy:
	cd doc; $(MAKE)
	rm -f $(WEBDIR)/ChangeLog
	cp $(HANDY_DOCS) $(TARFILE) $(ALL_RPMS) $(WEBDIR)
	cp $(HBDOCS) $(HBWEBDIR)



.PHONY: rpm pkg handy handy-copy
