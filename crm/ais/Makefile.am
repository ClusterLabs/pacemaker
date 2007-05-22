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

ais_LTLIBRARIES	= crm_ais.la
aisdir		= /opt/local/libexec/lcrso

# Disable various warnings we cant control
CFLAGS		= -g

crm_ais_la_SOURCES	= plugin.c
crm_ais_la_LDFLAGS	= -export-dynamic -module -avoid-version 
# Extra LDFLAGS: -bundle -bundle_loader /opt/local/sbin/aisexec -bind_at_load
crm_ais_la_LIBADD	= -lplumb -lcrmcommon

#ifeq (${OPENAIS_COMPAT}, DARWIN)
#service_cfg.lcrso: cfg.o
#	$(CC) $(LDFLAGS) -bundle $(LDFLAGS) -bundle_loader ./aisexec -bind_at_load cfg.o -o $@
#else
#service_cfg.lcrso: cfg.o
#	$(CC) -shared -Wl,-soname,service_cfg.lcrso cfg.o -o $@
#endif

install-exec-local:
	cd $(aisdir) && sudo ln -sf crm_ais.so crm_ais.lcrso 
