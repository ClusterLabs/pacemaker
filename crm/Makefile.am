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
SUBDIRS			=  cib crmd pengine tengine admin test
DIST_SUBDIRS		=  cib crmd pengine tengine admin test

crmdir			= $(HA_VARLIBDIR)/$(HB_PKG)/crm
noinst_HEADERS 	= dmalloc_wrapper.h

install-exec-local:
	$(mkinstalldirs) $(DESTDIR)/$(crmdir)
	-chown $(HA_CCMUSER) $(DESTDIR)/$(crmdir)
	-chgrp $(HA_APIGROUP) $(DESTDIR)/$(crmdir)
	-chmod g+w $(DESTDIR)/$(crmdir)
