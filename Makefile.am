#
# Copyright 2003-2026 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk

# This directory must be same as in configure.ac's AC_CONFIG_MACRO_DIR
ACLOCAL_AMFLAGS		= -I m4

EXTRA_DIST = CONTRIBUTING.md
EXTRA_DIST += GNUmakefile
EXTRA_DIST += INSTALL.md
EXTRA_DIST += README.markdown
EXTRA_DIST += autogen.sh
EXTRA_DIST += m4/CC_CHECK_LDFLAGS.m4
EXTRA_DIST += m4/CHECK_ENUM_VALUE.m4
EXTRA_DIST += m4/REQUIRE_HEADER.m4
EXTRA_DIST += m4/version.m4

DISTCLEANFILES		= config.status

MAINTAINERCLEANFILES += aclocal.m4
MAINTAINERCLEANFILES += config.guess
MAINTAINERCLEANFILES += config.sub
MAINTAINERCLEANFILES += configure
MAINTAINERCLEANFILES += depcomp
MAINTAINERCLEANFILES += install-sh
MAINTAINERCLEANFILES += ltmain.sh
MAINTAINERCLEANFILES += missing
MAINTAINERCLEANFILES += py-compile
MAINTAINERCLEANFILES += test-driver

# Don't try to install files outside build directory for "make distcheck".
AM_DISTCHECK_CONFIGURE_FLAGS = --prefix="$$dc_install_base/usr"
AM_DISTCHECK_CONFIGURE_FLAGS += --sysconfdir="$$dc_install_base/etc"
AM_DISTCHECK_CONFIGURE_FLAGS += --with-initdir="$$dc_install_base/etc/init.d"
AM_DISTCHECK_CONFIGURE_FLAGS += --with-ocfdir="$$dc_install_base/usr/lib/ocf"
AM_DISTCHECK_CONFIGURE_FLAGS += --with-systemdsystemunitdir="$$dc_install_base$(systemdsystemunitdir)"

# Only these will get built with a plain "make"
CORE = include
CORE += lib
CORE += daemons
CORE += tools
CORE += xml
CORE += po
CORE += python
CORE += cts
CORE += rpm

SUBDIRS = $(CORE)
SUBDIRS += agents
SUBDIRS += devel
SUBDIRS += doc
SUBDIRS += etc
SUBDIRS += maint
SUBDIRS += tests

doc_DATA = README.markdown
doc_DATA += COPYING

licensedir              = $(docdir)/licenses/
dist_license_DATA	= $(wildcard licenses/*)

# Directories that should be created on install and removed on uninstall
## owned by root:haclient, mode 0750
ROOT_DIRS	= $(PACEMAKER_CONFIG_DIR)
## owned by hacluster:haclient, mode 0750
DAEMON_R_DIRS = $(CRM_CONFIG_DIR)
DAEMON_R_DIRS += $(CRM_CORE_DIR)
DAEMON_R_DIRS += $(CRM_BLACKBOX_DIR)
## owned by hacluster:haclient, mode 0770
DAEMON_RW_DIRS = $(CRM_BUNDLE_DIR)
DAEMON_RW_DIRS += $(CRM_LOG_DIR)

.PHONY: core
core:
	@echo "Building only core components and tests: $(CORE)"
	@for subdir in $(CORE); do \
		echo "Building $$subdir"; \
		$(MAKE) $(AM_MAKEFLAGS) -C $$subdir all || exit 1; \
	done

.PHONY: core-clean
core-clean:
	@echo "Cleaning only core components and tests: $(CORE)"
	@for subdir in $(CORE); do \
		echo "Cleaning $$subdir"; \
		$(MAKE) $(AM_MAKEFLAGS) -C $$subdir clean || exit 1; \
	done

.PHONY: install-exec-local
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
.PHONY: uninstall-hook
uninstall-hook:
	-for DIR in $(ROOT_DIRS) $(DAEMON_R_DIRS) $(DAEMON_RW_DIRS); do	\
		rmdir "$(DESTDIR)/$$DIR";				\
	done

.PHONY: clean-generic
clean-generic:
	-rm -f *.tar.bz2 *.sed

PACKAGE         ?= pacemaker

.PHONY: clean-local
clean-local:
	-rm -f $(builddir)/$(PACKAGE)-*.tar.gz
	-if [ "x$(top_srcdir)" != "x$(top_builddir)" ]; then \
		rm -rf $(top_builddir)/python; \
	fi

.PHONY: distclean-local
distclean-local:
	-rm -rf libltdl autom4te.cache
