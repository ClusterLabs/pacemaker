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

EXTRA_DIST		= CONTRIBUTING.md	\
			  GNUmakefile		\
			  INSTALL.md		\
			  README.markdown	\
			  autogen.sh		\
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

CORE	= replace include lib mcp attrd pengine cib crmd fencing lrmd tools xml
SUBDIRS	= $(CORE) extra doc

AM_CPPFLAGS		= -I$(top_srcdir)/include

doc_DATA = README.markdown COPYING

ACLOCAL_AMFLAGS  = -I m4

licensedir              = $(docdir)/licenses/
dist_license_DATA	= $(wildcard licenses/*)

# Test components
SUBDIRS	+= cts

testdir			= $(datadir)/$(PACKAGE)/tests/
test_SCRIPTS		= coverage.sh
dist_test_SCRIPTS	= BasicSanity.sh
dist_test_DATA		= valgrind-pcmk.suppressions

EXTRA_SCRIPTS		= abi-check bumplibs.sh

# Scratch file for ad-hoc testing
EXTRA_PROGRAMS		= scratch
nodist_scratch_SOURCES	= scratch.c
scratch_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la

core:
	@echo "Building only core components: $(CORE)"
	@for subdir in $(CORE); do \
		echo "Building $$subdir"; \
		$(MAKE) -C $$subdir all || exit 1; \
	done

core-install:
	@echo "Installing only core components: $(CORE)"
	@for subdir in $(CORE); do \
	    echo "Installing $$subdir"; \
	    $(MAKE) -C $$subdir install || exit 1; \
	done

core-clean:
	@echo "Cleaning only core components: $(CORE)"
	@for subdir in $(CORE); do \
		echo "Cleaning $$subdir"; \
		$(MAKE) -C $$subdir clean || exit 1; \
	done

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/$(LCRSODIR)
	$(INSTALL) -d -m 750 $(DESTDIR)/$(CRM_CONFIG_DIR)
	$(INSTALL) -d -m 750 $(DESTDIR)/$(CRM_CORE_DIR)
	$(INSTALL) -d -m 750 $(DESTDIR)/$(CRM_BLACKBOX_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(CRM_CONFIG_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(CRM_CORE_DIR)
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/$(CRM_BLACKBOX_DIR)
if BUILD_CS_PLUGIN
	rm -f $(DESTDIR)$(LCRSODIR)/pacemaker.lcrso $(DESTDIR)$(LCRSODIR)/service_crm.so
	cp $(DESTDIR)$(libdir)/service_crm.so $(DESTDIR)$(LCRSODIR)/pacemaker.lcrso
endif
# Use chown because the user/group may not exist

clean-generic:
	-rm -f *.tar.bz2 *.sed

# In a normal build, this file is included by GNUmakefile, which serves as the
# "real" makefile. But in a VPATH build, GNUmakefile won't exist in the build
# tree, and this file will be the "real" makefile. EXTRA_CLEAN_TARGETS handles
# both cases: GNUmakefile defines it before including this file, so the
# clean-local target can clean up files created by GNUmakefile targets.
# If this file is used alone, the variable will be undefined.
clean-local: $(EXTRA_CLEAN_TARGETS)
	-rm -f scratch

distclean-local:
	-rm -rf libltdl autom4te.cache
