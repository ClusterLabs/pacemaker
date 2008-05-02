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
		-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl

halibdir	= $(libdir)/@HB_PKG@

COMMONLIBS	=  							\
		$(top_builddir)/lib/crm/common/libcrmcommon.la 		\
		$(top_builddir)/lib/crm/cib/libcib.la	 		\
		$(CLUSTERLIBS) $(GLIBLIB) $(LIBRT) $(GNUTLSLIBS)

## binary progs
halib_PROGRAMS	= tengine ttest

## SOURCES
noinst_HEADERS	= tengine.h te_callbacks.h

tengine_SOURCES	= actions.c events.c utils.c callbacks.c main.c
tengine_LDADD	= $(COMMONLIBS) $(CLUSTERLIBS) \
                    $(top_builddir)/lib/crm/transition/libtransitioner.la

ttest_SOURCES	= actions.c events.c utils.c callbacks.c ttest.c
ttest_LDADD	= $(COMMONLIBS) $(CLUSTERLIBS) \
                    $(top_builddir)/lib/crm/transition/libtransitioner.la

clean-generic:
	rm -f *.log *.debug *~

install-exec-local:

uninstall-local:
