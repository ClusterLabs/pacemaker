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

INCLUDES        = -I$(top_builddir)/include  -I$(top_srcdir)/include  \
		  -I$(top_builddir)/libltdl  -I$(top_srcdir)/libltdl  \
		  -I$(AISPREFIX)/include/openais


EXTRA_DIST	= cib.pam

hadir		= $(sysconfdir)/ha.d
halibdir	= $(libdir)/@HB_PKG@
commmoddir	= $(halibdir)/modules/comm

COMMONLIBS	= $(top_builddir)/lib/crm/common/libcrmcommon.la	\
		  $(top_builddir)/lib/crm/cib/libcib.la			\
		  $(GLIBLIB)						\
		  $(LIBRT)

## binary progs
halib_PROGRAMS	= cib cibmon
sbin_PROGRAMS   = cibpipe

## SOURCES
#noinst_HEADERS		= config.h control.h crmd.h
noinst_HEADERS		= cibio.h cibmessages.h cibprimatives.h notify.h \
			callbacks.h

cib_SOURCES		= io.c primatives.c messages.c cib.c notify.c	\
			callbacks.c main.c remote.c common.c

cib_LDADD		= $(COMMONLIBS) $(CRYPTOLIB) $(CLUSTERLIBS)	\
			$(top_builddir)/lib/crm/common/libcrmcluster.la

cib_LDFLAGS		= $(GNUTLSLIBS)

cibmon_SOURCES		= cibmon.c
cibmon_LDADD		= $(COMMONLIBS)

cibpipe_SOURCES		= primatives.c messages.c common.c cibpipe.c

cibpipe_LDADD		= $(COMMONLIBS) $(CRYPTOLIB)
cibpipe_CFLAGS		= -DCIBPIPE=1

clean-generic:
	rm -f *.log *.debug *.xml *~

install-exec-local:
#	cp -f $(top_srcdir)/crm/cib/cib.pam $(DESTDIR)/etc/pam.d/cib

uninstall-local:
