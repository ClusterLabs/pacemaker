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
SUBDIRS			=  common cib crmd lrmd pengine tengine admin


crmdir			= $(HA_VARLIBDIR)/$(HB_PKG)/crm

install-exec-local:
	$(mkinstalldirs) $(DESTDIR)$(crmdir)
	-chgrp $(apigid) $(DESTDIR)/$(crmdir)
#	-chown $(ccmuid) $(DESTDIR)/$(crmdir)
	chmod 770 $(DESTDIR)/$(crmdir)
#	test -p $(DESTDIR)$(ccmreqfifo) || mkfifo -m 200 $(DESTDIR)$(ccmreqfifo)
#	test -p $(DESTDIR)$(ccmresfifo) || mkfifo -m 600 $(DESTDIR)$(ccmresfifo)
#	-chgrp $(apigid) $(DESTDIR)/$(ccmreqfifo)
#	-chgrp $(apigid) $(DESTDIR)/$(ccmresfifo)
#	-chown $(ccmuid) $(DESTDIR)/$(ccmreqfifo)
#	-chown $(ccmuid) $(DESTDIR)/$(ccmresfifo)

