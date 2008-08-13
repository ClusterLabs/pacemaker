#
# doc: Pacemaker code
#
# Copyright (C) 2008 Andrew Beekhof
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

docdir 			= $(datadir)/doc/pacakges/@HB_PKG@-@VERSION@

OTHER_DOCS              = AUTHORS COPYING COPYING.LGPL README 

man_MANS		= cibadmin.8 crm_resource.8

EXTRA_DIST = $(man_MANS)

%.txt: %.html
	if [ "X$(HTML2TXT)" = "X" ]; then echo "Lynx or w3m or user-defined HTML2TXT required to convert $< to $@" >$@ ; else $(HTML2TXT) -dump $< >$@ ; fi
