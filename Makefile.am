#
# Copyright 2003-2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

# This directory must be same as in configure.ac's AC_CONFIG_MACRO_DIR
ACLOCAL_AMFLAGS		= -I m4

EXTRA_DIST		= CONTRIBUTING.md	\
			  GNUmakefile		\
			  INSTALL.md		\
			  README.markdown	\
			  autogen.sh		\
			  m4/CC_CHECK_LDFLAGS.m4	\
			  m4/CHECK_ENUM_VALUE.m4	\
			  m4/gnulib-cache.m4	\
			  m4/gnulib-tool.m4	\
			  m4/PKG_CHECK_VAR.m4	\
			  m4/REQUIRE_HEADER.m4	\
			  m4/version.m4

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

# Don't try to install files outside build directory for "make distcheck".
AM_DISTCHECK_CONFIGURE_FLAGS	= --prefix="$$dc_install_base/usr"			\
				  --sysconfdir="$$dc_install_base/etc"			\
				  --with-initdir="$$dc_install_base/etc/init.d"		\
				  --with-ocfdir="$$dc_install_base/usr/lib/ocf"		\
				  --with-systemdsystemunitdir="$$dc_install_base$(systemdsystemunitdir)"

# Only these will get built with a plain "make"
CORE	= replace include lib daemons tools xml po python cts rpm

SUBDIRS	= $(CORE) agents devel doc etc maint tests

AM_CPPFLAGS		= -I$(top_srcdir)/include

doc_DATA = README.markdown COPYING

licensedir              = $(docdir)/licenses/
dist_license_DATA	= $(wildcard licenses/*)

# Directories that should be created on install and removed on uninstall
## owned by root:haclient, mode 0750
ROOT_DIRS	= $(PACEMAKER_CONFIG_DIR)
## owned by hacluster:haclient, mode 0750
DAEMON_R_DIRS	= $(CRM_CONFIG_DIR)	\
		  $(CRM_CORE_DIR)	\
		  $(CRM_BLACKBOX_DIR)
## owned by hacluster:haclient, mode 0770
DAEMON_RW_DIRS	= $(CRM_BUNDLE_DIR)	\
		  $(CRM_LOG_DIR)

core:
	@echo "Building only core components and tests: $(CORE)"
	@for subdir in $(CORE); do \
		echo "Building $$subdir"; \
		$(MAKE) $(AM_MAKEFLAGS) -C $$subdir all || exit 1; \
	done

core-clean:
	@echo "Cleaning only core components and tests: $(CORE)"
	@for subdir in $(CORE); do \
		echo "Cleaning $$subdir"; \
		$(MAKE) $(AM_MAKEFLAGS) -C $$subdir clean || exit 1; \
	done

install-exec-local:
	for DIR in $(ROOT_DIRS) $(DAEMON_R_DIRS); do				\
		$(INSTALL) -d -m 750 "$(DESTDIR)/$$DIR";			\
	done
	for DIR in $(DAEMON_RW_DIRS); do					\
		$(INSTALL) -d -m 770 "$(DESTDIR)/$$DIR";			\
	done
	-for DIR in $(ROOT_DIRS); do						\
		chgrp $(CRM_DAEMON_GROUP) "$(DESTDIR)/$$DIR";			\
	done
	-for DIR in $(DAEMON_R_DIRS) $(DAEMON_RW_DIRS); do			 \
		chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) "$(DESTDIR)/$$DIR"; \
	done

# Remove created directories only if they're empty
uninstall-hook:
	-for DIR in $(ROOT_DIRS) $(DAEMON_R_DIRS) $(DAEMON_RW_DIRS); do	\
		rmdir "$(DESTDIR)/$$DIR";				\
	done

clean-generic:
	-rm -f *.tar.bz2 *.sed

PACKAGE         ?= pacemaker

clean-local:
	-rm -f $(builddir)/$(PACKAGE)-*.tar.gz

distclean-local:
	-rm -rf libltdl autom4te.cache
