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

plugindir		= $(libdir)
plugin_LTLIBRARIES	= service_crm.la

#ais_PROGRAMS	= atest

service_crm_la_SOURCES	= utils.c plugin.c utils.h plugin.h
service_crm_la_LDFLAGS	= -export-dynamic -module -avoid-version 
# Extra LDFLAGS: -bundle -bundle_loader /opt/local/sbin/aisexec -bind_at_load
service_crm_la_LIBADD	= 

# OpenAIS's logging violates -Wwrite-strings all over the place
TMP_ANSI	= $(CFLAGS_COPY:-ansi=)
TMP_STR		= $(TMP_ANSI:-Wwrite-strings=)
CFLAGS		= $(TMP_STR:-Wcast-qual=)

if GCC_4
CFLAGS		+= -Wno-pointer-sign
endif

#POST_INSTALL = ls -al $(plugindir)
install-exec-local:
	echo Ensure $(plugindir)/$(lib_LTLIBRARIES:.la=.so) is later linked/copied to $(LCRSODIR)/$(lib_LTLIBRARIES:.la=.lcrso)

clean-local:
	rm -f *.log *.debug *~ .gres.* testcases/.gres.*
