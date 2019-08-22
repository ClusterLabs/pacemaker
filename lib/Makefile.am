#
# Copyright (C) 2004-2009 Andrew Beekhof
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

LIBS			= cib lrmd service pengine fencing cluster

PC_FILES		= $(LIBS:%=pacemaker-%.pc)	\
			  pacemaker.pc

EXTRA_DIST		= $(PC_FILES:%=%.in)

all-local: $(PC_FILES)

install-exec-local: $(PC_FILES)
	$(INSTALL) -d $(DESTDIR)/$(libdir)/pkgconfig
	$(INSTALL) -m 644 $(PC_FILES) $(DESTDIR)/$(libdir)/pkgconfig

uninstall-local:
	-cd $(DESTDIR)/$(libdir)/pkgconfig && rm -f $(PC_FILES)
	-rmdir $(DESTDIR)/$(libdir)/pkgconfig 2> /dev/null

clean-local:
	rm -f $(PC_FILES)

## Subdirectories...
SUBDIRS	= gnu common pengine transition cib services fencing lrmd cluster
DIST_SUBDIRS =  $(SUBDIRS) ais

if BUILD_CS_PLUGIN
SUBDIRS			+= ais
endif

