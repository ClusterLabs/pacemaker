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
		-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl 	\
		-I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha	\
		-I$(top_builddir) -I$(top_srcdir)

hadir		= $(sysconfdir)/ha.d
halibdir	= $(libdir)/@HB_PKG@
commmoddir	= $(halibdir)/modules/comm
havarlibdir	= $(localstatedir)/lib/@HB_PKG@

crmdir		= $(havarlibdir)/crm

COMMONLIBS	= $(CRM_DEBUG_LIBS) 					\
		$(top_builddir)/lib/clplumbing/libplumb.la		\
		$(top_builddir)/lib/pils/libpils.la			\
		$(top_builddir)/lib/crm/common/libcrmcommon.la 	\
		$(top_builddir)/lib/crm/cib/libcib.la	 	\
		$(top_builddir)/lib/apphb/libapphb.la			\
		$(top_builddir)/lib/hbclient/libhbclient.la		\
		$(GLIBLIB)						\
		$(LIBRT)

LIBRT 		= @LIBRT@
AM_CFLAGS	= @CFLAGS@ $(CRM_DEBUG_FLAGS)


## binary progs
halib_PROGRAMS	= ttest tengine

## SOURCES
noinst_HEADERS	= tengine.h

tengine_SOURCES	= tengine.c unpack.c utils.c callbacks.c main.c
tengine_CFLAGS	= $(XML_FLAGS) -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
tengine_LDFLAGS	= $(XML_LIBS)
tengine_LDADD	= $(COMMONLIBS) \
                    $(top_builddir)/lib/fencing/libstonithd.la

ttest_SOURCES	= tengine.c unpack.c utils.c callbacks.c ttest.c
ttest_CFLAGS	= $(XML_FLAGS) -DTESTING=1 -DHA_VARLIBDIR='"@HA_VARLIBDIR@"'
ttest_LDFLAGS	= $(XML_LIBS)
ttest_LDADD	= $(COMMONLIBS) \
                    $(top_builddir)/lib/fencing/libstonithd.la


clean-generic:
	rm -f *.log *.debug *~

install-exec-local:

uninstall-local:
