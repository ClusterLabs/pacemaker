#
# Copyright 2004-2019 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
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
DIST_SUBDIRS = $(SUBDIRS)

if BUILD_CS_PLUGIN
SUBDIRS			+= ais
else
DIST_SUBDIRS		+= ais
endif
