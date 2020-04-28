#
# Copyright 2003-2019 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

# m4/glibtests.m4 is copied from https://gitlab.gnome.org/GNOME/glib/blob/master/m4macros/glibtests.m4.
EXTRA_DIST		= CONTRIBUTING.md	\
			  GNUmakefile		\
			  INSTALL.md		\
			  README.markdown	\
			  autogen.sh		\
			  m4/glibtests.m4 \
			  m4/gnulib-cache.m4	\
			  m4/gnulib-tool.m4	\
			  rpm/rpmlintrc		\
			  rpm/pacemaker.spec.in

DISTCLEANFILES		= config.status

MAINTAINERCLEANFILES	= Makefile.in		\
			  aclocal.m4		\
			  config.guess		\
			  config.sub		\
			  configure		\
			  depcomp		\
			  install-sh		\
			  ltmain.sh		\
			  missing		\
			  py-compile		\
			  test-driver

# Disable building Publican documentation when doing "make distcheck", because
# some of our book sources are in the source directory, while others are
# dynamically generated in the build directory, and publican can't handle that.
#
# In a non-VPATH build, doc isn't entered with a plain "make" because the
# GNUmakefile sets "core" as the default target. However in a VPATH build,
# there is no GNUmakefile, so "all" becomes the default target.
#
# Also, don't try to install files outside the build directory.
#
# @TODO To support VPATH builds for Publican, we could use the same "copy all
# static inputs into the build tree" trick that xml/Makefile.am uses for
# static schema files.
AM_DISTCHECK_CONFIGURE_FLAGS	= --with-brand=""					\
				  --prefix="$$dc_install_base/usr"			\
				  --sysconfdir="$$dc_install_base/etc"			\
				  --with-initdir="$$dc_install_base/etc/init.d"		\
				  --with-ocfdir="$$dc_install_base/usr/lib/ocf"		\
				  --with-systemdsystemunitdir="$$dc_install_base$(systemdsystemunitdir)"

# Only these will get installed with a plain "make install"
CORE_INSTALL	= replace include lib daemons tools xml

# Only these will get built with a plain "make" or "make clean"
CORE		= $(CORE_INSTALL) cts

SUBDIRS	= $(CORE) doc extra maint tests

AM_CPPFLAGS		= -I$(top_srcdir)/include

doc_DATA = README.markdown COPYING

licensedir              = $(docdir)/licenses/
dist_license_DATA	= $(wildcard licenses/*)

# Scratch file for ad-hoc testing
EXTRA_PROGRAMS		= scratch
nodist_scratch_SOURCES	= scratch.c
scratch_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la

core:
	@echo "Building only core components and tests: $(CORE)"
	@for subdir in $(CORE); do \
		echo "Building $$subdir"; \
		$(MAKE) $(AM_MAKEFLAGS) -C $$subdir all || exit 1; \
	done

core-install:
	@echo "Installing only core components: $(CORE_INSTALL)"
	@for subdir in $(CORE_INSTALL); do \
	    echo "Installing $$subdir"; \
	    $(MAKE) $(AM_MAKEFLAGS) -C $$subdir install || exit 1; \
	done

core-clean:
	@echo "Cleaning only core components and tests: $(CORE)"
	@for subdir in $(CORE); do \
		echo "Cleaning $$subdir"; \
		$(MAKE) $(AM_MAKEFLAGS) -C $$subdir clean || exit 1; \
	done

install-exec-local:
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
	-rm -f *.tar.bz2 *.sed

PACKAGE         ?= pacemaker

# In a normal build, this file is included by GNUmakefile, which serves as the
# "real" makefile. But in a VPATH build, GNUmakefile won't exist in the build
# tree, and this file will be the "real" makefile. EXTRA_CLEAN_TARGETS handles
# both cases: GNUmakefile defines it before including this file, so the
# clean-local target can clean up files created by GNUmakefile targets.
# If this file is used alone, the variable will be undefined.
clean-local: $(EXTRA_CLEAN_TARGETS)
	-rm -f scratch $(builddir)/$(PACKAGE)-*.tar.gz

distclean-local:
	-rm -rf libltdl autom4te.cache
