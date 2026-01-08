#
# Copyright 2004-2026 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk

headerdir=$(pkgincludedir)/crm

header_HEADERS = cib.h
header_HEADERS += cib_compat.h
header_HEADERS += cluster.h
header_HEADERS += crm.h
header_HEADERS += crm_compat.h
header_HEADERS += lrmd.h
header_HEADERS += lrmd_events.h
header_HEADERS += msg_xml.h
header_HEADERS += msg_xml_compat.h
header_HEADERS += services.h
header_HEADERS += services_compat.h
header_HEADERS += stonith-ng.h

noinst_HEADERS		= $(wildcard *_internal.h)

SUBDIRS = common
SUBDIRS += pengine
SUBDIRS += cib
SUBDIRS += fencing
SUBDIRS += cluster
