#
# Copyright (C) 2007 Andrew Beekhof
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

INCLUDES        = -I$(AISPREFIX)/include/openais

plugindir		= $(libdir)
plugin_LTLIBRARIES	= service_crm.la

#ais_PROGRAMS	= atest

service_crm_la_SOURCES	= utils.c plugin.c utils.h plugin.h
service_crm_la_LDFLAGS	= -export-dynamic -module -avoid-version 
# Extra LDFLAGS: -bundle -bundle_loader /opt/local/sbin/aisexec -bind_at_load
service_crm_la_LIBADD	= $(GLIBLIB)

COMMONLIBS	= $(CRM_DEBUG_LIBS)					\
		$(top_builddir)/lib/clplumbing/libplumb.la		\
		$(top_builddir)/lib/crm/common/libcrmcommon.la		\
		$(GLIBLIB)						\
		$(CURSESLIBS)						\
		$(CLUSTERLIBS)						\
		$(LIBRT)

#atest_SOURCES	= test.c
#atest_LDADD	= $(COMMONLIBS)

#CFLAGS that cant be used here: -ansi -Wcast-qual -Wwrite-strings
CFLAGS			= $(NON_FATAL_CFLAGS:-Wwrite-strings=)

#POST_INSTALL = ls -al $(plugindir)
install-exec-local:
	echo Ensure $(plugindir)/$(lib_LTLIBRARIES:.la=.so) is later linked/copied to $(LCRSODIR)/$(lib_LTLIBRARIES:.la=.lcrso)

clean-generic:
	rm -f *.log *.debug *~ .gres.* testcases/.gres.*
