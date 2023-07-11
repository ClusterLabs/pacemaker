#
# Copyright 2004-2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

MAINTAINERCLEANFILES	= Makefile.in

headerdir=$(pkgincludedir)/crm

header_HEADERS		= cib.h			\
			  cluster.h		\
			  compatibility.h	\
			  crm.h			\
			  crm_compat.h		\
			  lrmd.h		\
			  lrmd_events.h		\
			  msg_xml.h		\
			  msg_xml_compat.h	\
			  services.h		\
			  services_compat.h	\
			  stonith-ng.h

noinst_HEADERS		= lrmd_internal.h services_internal.h

SUBDIRS                 = common pengine cib fencing cluster
