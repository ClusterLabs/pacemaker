#
# Copyright 2003-2026 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk

LIBS = cib
LIBS += lrmd
LIBS += service
LIBS += fencing
LIBS += cluster

pkgconfig_DATA = $(LIBS:%=pacemaker-%.pc)
pkgconfig_DATA += libpacemaker.pc
pkgconfig_DATA += pacemaker.pc
pkgconfig_DATA += pacemaker-pe_status.pc

if BUILD_DEPRECATED_LIBS
pkgconfig_DATA		+= pacemaker-pe_rules.pc
endif

EXTRA_DIST		= $(pkgconfig_DATA:%=%.in)

SUBDIRS = common
SUBDIRS += pengine
SUBDIRS += cib
SUBDIRS += services
SUBDIRS += fencing
SUBDIRS += lrmd
SUBDIRS += cluster
SUBDIRS += pacemaker
