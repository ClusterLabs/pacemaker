#
# heartbeat: Linux-HA heartbeat code
#
# Copyright (C) 2001 Michael Moerz
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
MAINTAINERCLEANFILES    = Makefile.in ccdv

INCLUDES                = -I$(top_builddir)/include -I$(top_srcdir)/include   \
			  -I$(AISPREFIX)/include/openais

EXTRA_DIST		= ccdv.c attrd.h

halibdir		= $(libdir)/@HB_PKG@
halib_SCRIPTS		= haresources2cib.py
halib_PROGRAMS		= attrd pingd

sbin_PROGRAMS		= attrd_updater

## SOURCES
ccdv: 	$(top_srcdir)/tools/ccdv.c
	gcc $(AM_CFLAGS) $(CFLAGS) -o ccdv $(top_srcdir)/tools/ccdv.c

# A little trick. Now ccdv can be auto-built but not auto-cleaned.
attrd_DEPENDENCIES	= ccdv
attrd_SOURCES		= attrd.c
attrd_LDADD		=  						\
		  $(top_builddir)/lib/crm/common/libcrmcommon.la	\
		  $(top_builddir)/lib/crm/common/libcrmcluster.la	\
		  $(top_builddir)/lib/crm/cib/libcib.la			\
		  $(GLIBLIB)						\
		  $(CLUSTERLIBS)					\
		  $(LIBRT)

pingd_SOURCES		= pingd.c
pingd_LDADD		=  						\
		  $(top_builddir)/lib/crm/common/libcrmcommon.la	\
		  $(GLIBLIB)						\
		  $(CLUSTERLIBS)					\
		  $(LIBRT)

attrd_updater_SOURCES	= attrd_updater.c
attrd_updater_LDADD	=  						\
		  $(top_builddir)/lib/crm/common/libcrmcommon.la	\
		  $(GLIBLIB)						\
		  $(CLUSTERLIBS)					\
		  $(LIBRT)

.PHONY: install-exec-hook
