#
# Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

EXTRA_DIST              = autogen.sh m4/gnulib-cache.m4

MAINTAINERCLEANFILES    = Makefile.in aclocal.m4 configure DRF/config-h.in \
                        DRF/stamp-h.in libtool.m4 ltdl.m4

# Only these will get installed with a plain "make install"
CORE_INSTALL	= replace include lib daemons cib tools xml

# Only these will get built with a plain "make" or "make clean"
CORE		= $(CORE_INSTALL) cts

SUBDIRS	= $(CORE) doc extra

AM_CPPFLAGS		= -I$(top_srcdir)/include

doc_DATA = README.markdown COPYING

licensedir              = $(docdir)/licenses/
license_DATA            = $(wildcard licenses/*)

# Scratch file for ad-hoc testing
noinst_PROGRAMS = scratch
nodist_scratch_SOURCES	= scratch.c
scratch_LDADD	= $(top_builddir)/lib/common/libcrmcommon.la -lm

scratch.c:
	echo 'int main(void){}' >$@

core:
	@echo "Building only core components and tests: $(CORE)"
	list='$(CORE)'; for subdir in $$list; do echo "Building $$subdir"; $(MAKE) -C $$subdir all || exit 1; done

core-install:
	@echo "Installing only core components: $(CORE_INSTALL)"
	list='$(CORE_INSTALL)'; \
	for subdir in $$list; do \
	    echo "Installing $$subdir"; \
	    $(MAKE) -C $$subdir install || exit 1; \
	done

core-clean:
	@echo "Cleaning only core components and tests: $(CORE)"
	list='$(CORE)'; for subdir in $$list; do echo "Cleaning $$subdir"; $(MAKE) -C $$subdir clean || exit 1; done

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/$(LCRSODIR)
	$(INSTALL) -d -m 750 $(DESTDIR)/$(PACEMAKER_CONFIG_DIR)
	$(INSTALL) -d -m 750 $(DESTDIR)/$(CRM_CONFIG_DIR)
	$(INSTALL) -d -m 750 $(DESTDIR)/$(CRM_CORE_DIR)
	$(INSTALL) -d -m 750 $(DESTDIR)/$(CRM_BLACKBOX_DIR)
	$(INSTALL) -d -m 770 $(DESTDIR)/$(CRM_LOG_DIR)
	$(INSTALL) -d -m 770 $(DESTDIR)/$(CRM_BUNDLE_DIR)
	-chgrp $(CRM_DAEMON_GROUP) $(DESTDIR)/$(PACEMAKER_CONFIG_DIR)
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
