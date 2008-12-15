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

docdir 			= $(datadir)/doc/packages/@PKG_NAME@
htmlfiles		= crm_cli.html
txtfiles		= crm_cli.txt

OTHER_DOCS              = AUTHORS COPYING COPYING.LGPL README README.hb2openais

doc_DATA		= $(OTHER_DOCS) $(txtfiles) $(htmlfiles)

EXTRA_DIST		= $(OTHER_DOCS) $(txtfiles) $(htmlfiles)

crm_cli.html: crm_cli.txt
	-asciidoc --unsafe --backend=xhtml11 $<
