#
# Copyright 2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/python.mk

MAINTAINERCLEANFILES    = Makefile.in

# Commands intended to be run only via other commands
halibdir		= $(CRM_DAEMON_DIR)
dist_halib_SCRIPTS	= cts-support

ctsdir		=	$(datadir)/$(PACKAGE)/tests/cts
cts_DATA	=	pacemaker-cts-dummyd@.service
dist_cts_DATA	=	cts.conf
if BUILD_UPSTART
dist_cts_DATA	+=	pacemaker-cts-dummyd.conf
endif
cts_SCRIPTS	= fence_dummy		\
		  LSBDummy		\
		  pacemaker-cts-dummyd

PYCHECKFILES ?= cts-support pacemaker-cts-dummyd
