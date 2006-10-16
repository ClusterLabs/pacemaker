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
MAINTAINERCLEANFILES    = Makefile.in

INCLUDES        = -I$(top_builddir)/include -I$(top_srcdir)/include	\
		-I$(top_builddir)/libltdl   -I$(top_srcdir)/libltdl	\
		-I$(top_builddir)/linux-ha  -I$(top_srcdir)/linux-ha \
		-I$(top_builddir)           -I$(top_srcdir)

EXTRA_DIST	= version.h

hadir		= $(sysconfdir)/ha.d
halibdir	= $(libdir)/@HB_PKG@
commmoddir	= $(halibdir)/modules/comm
havarlibdir	= $(localstatedir)/lib/@HB_PKG@

# sockets with path
crmdir		= $(havarlibdir)/crm
apigid		= @HA_APIGID@
crmuid		= @HA_CCMUID@

COMMONLIBS	= $(CRM_DEBUG_LIBS)					\
		$(top_builddir)/lib/clplumbing/libplumb.la		\
		$(top_builddir)/lib/pils/libpils.la			\
		$(top_builddir)/lib/crm/common/libcrmcommon.la	\
		$(top_builddir)/lib/crm/pengine/libpe_rules.la	\
		$(top_builddir)/lib/crm/cib/libcib.la			\
		$(top_builddir)/lib/apphb/libapphb.la			\
		$(top_builddir)/lib/hbclient/libhbclient.la		\
		$(GLIBLIB)						\
		$(LIBRT)

LIBRT 		= @LIBRT@
AM_CFLAGS	= @CFLAGS@						\
		$(CRM_DEBUG_FLAGS)

## libraries
lib_LTLIBRARIES	= 

## binary progs
halib_PROGRAMS	= crmd atest

## SOURCES

noinst_HEADERS	= crmd.h crmd_fsa.h crmd_messages.h fsa_defines.h 	\
		fsa_matrix.h fsa_proto.h crmd_utils.h crmd_callbacks.h \
		crmd_lrm.h version.h

atest_SOURCES	= atest.c
atest_CFLAGS	= -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
atest_LDADD	= $(COMMONLIBS)


crmd_SOURCES	= main.c crmd.c 					\
		fsa.c control.c messages.c ccm.c callbacks.c		\
		election.c join_client.c join_dc.c subsystems.c 	\
		cib.c pengine.c tengine.c lrm.c 			\
		utils.c misc.c

crmd_CFLAGS	= -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
crmd_LDADD	= $(COMMONLIBS) 					\
		  $(top_builddir)/lib/lrm/liblrm.la			\
		  $(top_builddir)/membership/ccm/libccmclient.la  

# Simple HA client app
#clnt_SOURCES	= clnt.c

#clnt_CFLAGS	= $(XML_FLAGS) -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
#clnt_LDFLAGS	= $(XML_LIBS)
#clnt_LDADD	= $(COMMONLIBS) 

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:

uninstall-local:

graphs:	fsa_inputs.png fsa_inputs_by_action.png fsa_actions_by_state.png

%.png: %.dot
	dot -Tpng $< > $@ 

%.dot : fsa_matrix.h
	perl make_dot.pl

version.h: version

VERSION_FILE="$(top_builddir)/crm/crmd/version.h"
CRM_HG_VERSION=$(shell hg -R $(top_srcdir) id | tr ' ' ':')
CRM_NOW_VERSION=$(shell test -f $(VERSION_FILE) && head -n 1 $(VERSION_FILE))

version:
	if [ "x$(CRM_HG_VERSION)" = "x" -a "x$(CRM_NOW_VERSION)" = "x" ]; then		\
		echo "Unknown CRM version"; 						\
		echo "/* unknown */" > $(VERSION_FILE); 				\
		echo "#define CRM_HG_VERSION \"unknown\"" >> $(VERSION_FILE); 		\
	elif [ "x$(CRM_HG_VERSION)" = "x" ]; then					\
		echo "Exported CRM version correct: $(CRM_NOW_VERSION)"; 		\
	elif [ "/* $(CRM_HG_VERSION) */" = "$(CRM_NOW_VERSION)" ]; then 		\
		echo "CRM version correct: $(CRM_NOW_VERSION)"; 			\
	else 										\
		echo "Updating CRM version"; 						\
		echo "/* $(CRM_HG_VERSION) */" > $(VERSION_FILE); 			\
		echo "#define CRM_HG_VERSION \"$(CRM_HG_VERSION)\"" >> $(VERSION_FILE); \
	fi

