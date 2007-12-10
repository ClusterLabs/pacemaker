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

## Subdirectories
SUBDIRS			=  admin
DIST_SUBDIRS		=  admin ais

if BUILD_NATIVE_AIS
SUBDIRS			+= ais
endif

dtddir			= $(HA_NOARCHDATAHBDIR)
crm_varlibdir		= $(HA_VARLIBDIR)/$(HB_PKG)/crm
crm_varrundir		= $(HA_VARRUNDIR)/$(HB_PKG)/crm

EXTRA_DIST		= crm-1.0.dtd
dtd_SCRIPTS		= crm.dtd

crm.dtd: crm-1.0.dtd
	cp $(top_srcdir)/crm/crm-1.0.dtd crm.dtd

install-exec-local:
	$(mkinstalldirs) $(DESTDIR)/$(crm_varlibdir)
	-chown $(HA_CCMUSER) $(DESTDIR)/$(crm_varlibdir)
	-chgrp $(HA_APIGROUP) $(DESTDIR)/$(crm_varlibdir)
	-chmod 750 $(DESTDIR)/$(crm_varlibdir)
	$(mkinstalldirs) $(DESTDIR)/$(crm_varrundir)
	-chown $(HA_CCMUSER) $(DESTDIR)/$(crm_varrundir)
	-chgrp $(HA_APIGROUP) $(DESTDIR)/$(crm_varrundir)
	-chmod 750 $(DESTDIR)/$(crm_varrundir)
