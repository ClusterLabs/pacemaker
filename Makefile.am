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

EXTRA_DIST              = autogen.sh ConfigureMe README.in libltdl.tar m4/gnulib-cache.m4

MAINTAINERCLEANFILES    = Makefile.in aclocal.m4 configure DRF/config-h.in \
                        DRF/stamp-h.in libtool.m4 ltdl.m4 libltdl.tar

CORE	= $(LIBLTDL_DIR) replace include lib mcp pengine cib crmd fencing tools xml
SUBDIRS	= $(CORE) cts extra doc

doc_DATA = AUTHORS COPYING COPYING.LIB

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS  = -I m4

core:
	@echo "Building only core components: $(CORE)"
	list='$(CORE)'; for subdir in $$list; do echo "Building in $$subdir"; make -C $$subdir all || exit 1; done

core-install:
	@echo "Installing only core components: $(CORE)"
	list='$(CORE)'; for subdir in $$list; do echo "Installing in $$subdir"; make -C $$subdir install || exit 1; done

core-clean:
	@echo "Cleaning only core components: $(CORE)"
	list='$(CORE)'; for subdir in $$list; do echo "Installing in $$subdir"; make -C $$subdir clean || exit 1; done

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/$(LCRSODIR)
	$(INSTALL) -d -m 750 $(DESTDIR)/$(CRM_CONFIG_DIR)
	$(INSTALL) -d -m 750 $(DESTDIR)/$(CRM_STATE_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(CRM_CONFIG_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(CRM_STATE_DIR)
if BUILD_CS_PLUGIN
	rm -f $(DESTDIR)$(LCRSODIR)/pacemaker.lcrso $(DESTDIR)$(LCRSODIR)/service_crm.so
	cp $(DESTDIR)$(libdir)/service_crm.so $(DESTDIR)$(LCRSODIR)/pacemaker.lcrso
endif
if BUILD_HEARTBEAT_SUPPORT
	$(INSTALL) -d $(DESTDIR)/$(HB_DAEMON_DIR)
	ln -sf $(CRM_DAEMON_DIR)/attrd     $(DESTDIR)$(HB_DAEMON_DIR)/
	ln -sf $(CRM_DAEMON_DIR)/cib       $(DESTDIR)$(HB_DAEMON_DIR)/
	ln -sf $(CRM_DAEMON_DIR)/crmd      $(DESTDIR)$(HB_DAEMON_DIR)/
	ln -sf $(CRM_DAEMON_DIR)/pengine   $(DESTDIR)$(HB_DAEMON_DIR)/
	ln -sf $(CRM_DAEMON_DIR)/stonithd  $(DESTDIR)$(HB_DAEMON_DIR)/
endif
# Use chown because the user/group may not exist

clean-generic:
	rm -f $(TARFILE) *.tar.bz2 *.sed

dist-clean-local:
	rm -f autoconf automake autoheader

maintainer-clean-local:
	rm -f libltdl.tar

.PHONY: rpm pkg handy handy-copy
