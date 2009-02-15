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

CLEANFILES      = $(cts_PYTHON) CTSproxy.py getpeinputs.sh LSBDummy

ctsdir		= $(datadir)/@PACKAGE@/cts

cts_PYTHON	=				\
			CM_lha.py		\
			CM_ais.py		\
			CTS.py			\
			CTSaudits.py		\
			CTSlab.py		\
			CTStests.py		\
			extracttests.py		\
			getpeinputs.sh		\
			OCFIPraTest.py		\
			CIB.py

cts_DATA	=	README

cts_SCRIPTS	=				\
			CTSproxy.py		\
			getpeinputs.sh		\
			cluster_test		\
			LSBDummy

all-local: $(cts_PYTHON)
