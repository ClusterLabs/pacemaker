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

EXTRA_DIST              = autogen.sh m4/gnulib-cache.m4

MAINTAINERCLEANFILES    = Makefile.in aclocal.m4 configure DRF/config-h.in \
                        DRF/stamp-h.in libtool.m4 ltdl.m4

CORE	= replace include lib mcp attrd pengine cib crmd fencing lrmd tools xml
SUBDIRS	= $(CORE) extra doc

AM_CPPFLAGS		= -I$(top_srcdir)/include

doc_DATA = README.markdown COPYING

licensedir              = $(docdir)/licenses/
license_DATA            = $(wildcard licenses/*)

# Test components
SUBDIRS	+= cts

# Scratch file for ad-hoc testing
noinst_PROGRAMS = scratch
nodist_scratch_SOURCES	= scratch.c
scratch_LDADD	= $(top_builddir)/lib/common/libcrmcommon.la -lm

scratch.c:
	echo 'int main(void){}' >$@

core:
	@echo "Building only core components: $(CORE)"
	list='$(CORE)'; for subdir in $$list; do echo "Building $$subdir"; $(MAKE) -C $$subdir all || exit 1; done

core-install:
	@echo "Installing only core components: $(CORE)"
	list='$(CORE)'; for subdir in $$list; do echo "Installing $$subdir"; $(MAKE) -C $$subdir install || exit 1; done

core-clean:
	@echo "Cleaning only core components: $(CORE)"
	list='$(CORE)'; for subdir in $$list; do echo "Cleaning $$subdir"; $(MAKE) -C $$subdir clean || exit 1; done

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/$(LCRSODIR)
	$(INSTALL) -d -m 750 $(DESTDIR)/$(CRM_CONFIG_DIR)
	$(INSTALL) -d -m 750 $(DESTDIR)/$(CRM_CORE_DIR)
	$(INSTALL) -d -m 750 $(DESTDIR)/$(CRM_BLACKBOX_DIR)
	$(INSTALL) -d -m 770 $(DESTDIR)/$(CRM_LOG_DIR)
	$(INSTALL) -d -m 770 $(DESTDIR)/$(CRM_BUNDLE_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(CRM_CONFIG_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(CRM_CORE_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(CRM_BLACKBOX_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(CRM_LOG_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(CRM_BUNDLE_DIR)
# Use chown because the user/group may not exist

clean-generic:
	rm -f $(TARFILE) *.tar.bz2 *.sed

dist-clean-local:
	rm -f autoconf automake autoheader
