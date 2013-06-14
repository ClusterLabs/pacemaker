#
# heartbeat: Linux-HA heartbeat code
#
# Copyright (C) 2001 Michael Moerz
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

CLEANFILES      = LSBDummy

EXTRA_DIST      = $(cts_SCRIPTS) $(cts_DATA)

ctsdir		= $(datadir)/$(PACKAGE)/tests/cts
ctslibdir	= $(pyexecdir)/cts

ctslib_PYTHON	=	__init__.py		\
			CTSvars.py		\
			CM_lha.py		\
			CM_ais.py		\
			CTS.py			\
			CTSaudits.py		\
			CTStests.py		\
			CTSscenarios.py		\
			CIB.py

cts_DATA	=	README cts.supp

cts_SCRIPTS	=	cluster_test		\
			CTSlab.py		\
			LSBDummy		\
			$(top_srcdir)/fencing/fence_dummy

SUBDIRS	= benchmark
