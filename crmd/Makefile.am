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
		-I$(top_builddir)/libltdl   -I$(top_srcdir)/libltdl

halibdir	= $(CRM_DAEMON_DIR)

## binary progs
halib_PROGRAMS	= crmd

## SOURCES

noinst_HEADERS	= crmd.h crmd_fsa.h crmd_messages.h fsa_defines.h 	\
		fsa_matrix.h fsa_proto.h crmd_utils.h crmd_callbacks.h \
		crmd_lrm.h te_callbacks.h tengine.h

crmd_SOURCES	= main.c crmd.c corosync.c					\
		fsa.c control.c messages.c membership.c callbacks.c		\
		election.c join_client.c join_dc.c subsystems.c throttle.c	\
		cib.c pengine.c tengine.c lrm.c lrm_state.c remote_lrmd_ra.c	\
		utils.c misc.c te_events.c te_actions.c te_utils.c te_callbacks.c

if BUILD_HEARTBEAT_SUPPORT
crmd_SOURCES += heartbeat.c
endif

crmd_LDADD	= $(top_builddir)/lib/fencing/libstonithd.la		\
		$(top_builddir)/lib/transition/libtransitioner.la	\
		$(top_builddir)/lib/pengine/libpe_rules.la		\
		$(top_builddir)/lib/cib/libcib.la			\
		$(top_builddir)/lib/cluster/libcrmcluster.la		\
		$(top_builddir)/lib/common/libcrmcommon.la		\
		$(top_builddir)/lib/services/libcrmservice.la		\
		$(top_builddir)/lib/lrmd/liblrmd.la		\
		$(CLUSTERLIBS)
if BUILD_XML_HELP
man7_MANS =	crmd.7

%.xml:	%
	$(top_builddir)/crmd/$< metadata | $(XSLTPROC) --nonet --novalid --stringparam man.name $< $(top_srcdir)/xml/ocf-meta2man.xsl - > $(top_builddir)/crmd/$@

%.7:	%.xml
	$(XSLTPROC) $(MANPAGE_XSLT) $(top_builddir)/crmd/$<
endif

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:

uninstall-local:

graphs:	fsa_inputs.png fsa_inputs_by_action.png fsa_actions_by_state.png

%.png: %.dot
	dot -Tpng $< > $@ 

%.dot : fsa_matrix.h make_dot.pl
	perl $(top_srcdir)/crmd/make_dot.pl $(top_srcdir)/crmd/fsa_matrix.h $(top_builddir)/crmd
