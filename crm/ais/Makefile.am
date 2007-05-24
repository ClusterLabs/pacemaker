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

aisdir		= $(prefix)/libexec/lcrso
ais_LTLIBRARIES	= crmais.la

crmais_la_SOURCES	= plugin.c
crmais_la_LDFLAGS	= -export-dynamic -module -avoid-version 
# Extra LDFLAGS: -bundle -bundle_loader /opt/local/sbin/aisexec -bind_at_load
crmais_la_LIBADD	= $(top_builddir)/lib/clplumbing/libplumb.la	\
			  $(top_builddir)/lib/crm/common/libcrmcommon.la

#CFLAGS that cant be used here: -ansi -Wcast-qual -Wwrite-strings
CFLAGS			= $(NON_FATAL_CFLAGS:-Wwrite-strings=)

#ifeq (${OPENAIS_COMPAT}, DARWIN)
#service_cfg.lcrso: cfg.o
#	$(CC) $(LDFLAGS) -bundle $(LDFLAGS) -bundle_loader ./aisexec -bind_at_load cfg.o -o $@
#else
#service_cfg.lcrso: cfg.o
#	$(CC) -shared -Wl,-soname,service_cfg.lcrso cfg.o -o $@
#endif

install-exec-local:
	cd $(aisdir) && sudo ln -sf $(ais_LTLIBRARIES:.la=.so) $(ais_LTLIBRARIES:.la=.lcrso)

clean-generic:
	rm -f *.log *.debug *~ .gres.* testcases/.gres.*

# Manual version
ais:   plugin.o
	echo $(CFLAGS)
	$(CC) $(LDFLAGS) -bundle $(LDFLAGS) -L/opt/local/lib $(GLIBLIB) -lplumb -lcrmcommon -bundle_loader /opt/local/sbin/aisexec -bind_at_load -bind_at_load plugin.o -o $(aisdir)/crm_ais.so
