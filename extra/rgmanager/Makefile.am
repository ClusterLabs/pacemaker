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

if BUILD_CMAN

# Migration tools
bin_PROGRAMS = ccs_flatten disable_rgmanager
bin_SCRIPTS = ccs2cib
ccs_flatten_SOURCES = reslist.c resrules.c restree.c flatten.c xmlconf.c
disable_rgmanager_SOURCES = disable_rgmanager.c

dist_pkgdata_DATA = cluconf2cib.xsl

ccs2cib: ccs2cib.in
	echo "#!/bin/sh" > $@
	echo >> $@
	echo XSL_FILE=\"$(pkgdatadir)/cluconf2cib.xsl\" >> $@
	echo SAXON_JAR=\"$(datadir)/java/saxon.jar\" >> $@
	echo >> $@
	cat $^ >> $@
	chmod +x $@
endif
