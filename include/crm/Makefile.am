#
# Copyright 2004-2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

MAINTAINERCLEANFILES	= Makefile.in

headerdir=$(pkgincludedir)/crm

header_HEADERS		= cib.h			\
			  cib_compat.h		\
			  cluster.h		\
			  crm.h			\
			  crm_compat.h		\
			  lrmd.h		\
			  lrmd_events.h		\
			  msg_xml.h		\
			  msg_xml_compat.h	\
			  services.h		\
			  stonith-ng.h

noinst_HEADERS		= $(wildcard *_internal.h)

SUBDIRS                 = common 	\
			  pengine 	\
			  cib 		\
			  fencing 	\
			  cluster
