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

INCLUDES                = -I$(top_builddir)/include -I$(top_srcdir)/include \
			  -I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha \
			  -I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl

EXTRA_DIST		= ccdv.c attrd.h $(hanoarch_DATA) $(sbin_SCRIPTS)

apigid			= @HA_APIGID@
habindir		= @bindir@
halibdir		= $(libdir)/@HB_PKG@
hanoarchdir		= @HA_NOARCHDATAHBDIR@
gliblib			= @GLIBLIB@

halib_SCRIPTS		= haresources2cib.py
hanoarch_DATA		= utillib.sh README.hb_report
sbin_SCRIPTS		= hb_report ocf-tester

if CRM_BUILD
halib_PROGRAMS		= attrd pingd
sbin_PROGRAMS		= attrd_updater
endif

## SOURCES
ccdv: 	$(top_srcdir)/tools/ccdv.c
	gcc $(AM_CFLAGS) $(CFLAGS) -o ccdv $(top_srcdir)/tools/ccdv.c

# A little trick. Now ccdv can be auto-built but not auto-cleaned.
attrd_DEPENDENCIES	= ccdv
attrd_SOURCES		= attrd.c
attrd_LDADD		=  						\
		  -lhbclient						\
		  $(top_builddir)/lib/crm/common/libcrmcommon.la	\
		  $(top_builddir)/lib/crm/cib/libcib.la			\
		  $(GLIBLIB)						\
		  $(LIBRT)

pingd_SOURCES		= pingd.c
pingd_LDADD		=  						\
		  -lhbclient						\
		  $(top_builddir)/lib/crm/common/libcrmcommon.la	\
		  $(GLIBLIB)						\
		  $(LIBRT)

attrd_updater_SOURCES	= attrd_updater.c
attrd_updater_LDADD	=  						\
		  -lhbclient						\
		  $(top_builddir)/lib/clplumbing/libplumb.la		\
		  $(top_builddir)/lib/crm/common/libcrmcommon.la	\
		  $(GLIBLIB)						\
		  $(LIBRT)

.PHONY: install-exec-hook
