#
# Copyright 2003-2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk

LIBS			= cib 		\
			  lrmd 		\
			  service 	\
			  fencing 	\
			  cluster

pkgconfig_DATA		= $(LIBS:%=pacemaker-%.pc)	\
			  libpacemaker.pc		\
			  pacemaker.pc			\
			  pacemaker-pe_status.pc

if BUILD_DEPRECATED_LIBS
pkgconfig_DATA		+= pacemaker-pe_rules.pc
endif

EXTRA_DIST		= $(pkgconfig_DATA:%=%.in)

SUBDIRS	= common 	\
	  pengine 	\
	  cib 		\
	  services 	\
	  fencing 	\
	  lrmd 		\
	  cluster 	\
	  pacemaker
