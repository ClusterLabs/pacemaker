#
# Copyright 2003-2019 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

EXTRA_DIST		= CONTRIBUTING.md	\
			  GNUmakefile		\
			  INSTALL.md		\
			  README.markdown	\
			  autogen.sh		\
			  pacemaker.spec.in	\
			  rpmlintrc		\
			  m4/gnulib-cache.m4	\
			  m4/gnulib-tool.m4

MAINTAINERCLEANFILES    = Makefile.in aclocal.m4 configure DRF/config-h.in \
                        DRF/stamp-h.in libtool.m4 ltdl.m4

# Disable building Publican documentation when doing "make distcheck", because
# some of our book sources are in the source directory, while others are
# dynamically generated in the build directory, and publican can't handle that.
#
# @TODO To support VPATH builds for Publican, we'd probably have to create
# a separate subtree of the build directory to use as Publican's source
# directory, and copy the static sources into it.
AM_DISTCHECK_CONFIGURE_FLAGS	= --with-brand=""

# Only these will get installed with a plain "make install"
CORE_INSTALL	= replace include lib daemons tools xml

# Only these will get built with a plain "make" or "make clean"
CORE		= $(CORE_INSTALL) cts

SUBDIRS	= $(CORE) doc extra maint

AM_CPPFLAGS		= -I$(top_srcdir)/include

doc_DATA = README.markdown COPYING

licensedir              = $(docdir)/licenses/
dist_license_DATA	= $(wildcard licenses/*)

# Scratch file for ad-hoc testing
noinst_PROGRAMS = scratch
nodist_scratch_SOURCES	= scratch.c
scratch_LDADD	= $(top_builddir)/lib/common/libcrmcommon.la -lm

scratch.c:
	echo 'int main(void){}' >$@

core:
	@echo "Building only core components and tests: $(CORE)"
	@for subdir in $(CORE); do \
		echo "Building $$subdir"; \
		$(MAKE) -C $$subdir all || exit 1; \
	done

core-install:
	@echo "Installing only core components: $(CORE_INSTALL)"
	@for subdir in $(CORE_INSTALL); do \
	    echo "Installing $$subdir"; \
	    $(MAKE) -C $$subdir install || exit 1; \
	done

core-clean:
	@echo "Cleaning only core components and tests: $(CORE)"
	@for subdir in $(CORE); do \
		echo "Cleaning $$subdir"; \
		$(MAKE) -C $$subdir clean || exit 1; \
	done

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
