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

CLEANFILES      = LSBDummy HBDummy

EXTRA_SCRIPTS		= cluster_test		\
			  OCFIPraTest.py

testdir		= $(datadir)/$(PACKAGE)/tests

ctslibdir		= $(pyexecdir)/cts
ctslib_PYTHON		= __init__.py		\
			  CIB.py		\
			  cib_xml.py		\
			  CM_lha.py		\
			  CM_ais.py		\
			  CTS.py		\
			  CTSaudits.py		\
			  CTSscenarios.py	\
			  CTStests.py		\
			  environment.py	\
			  logging.py		\
			  patterns.py		\
			  remote.py		\
			  watcher.py
nodist_ctslib_PYTHON	= CTSvars.py

ctsdir		= 	$(testdir)/cts
cts_DATA	=	pacemaker-cts-dummyd.service
dist_cts_DATA	=	README.md cts.supp
dist_cts_SCRIPTS	= cts			\
			  CTSlab.py		\
			  $(top_srcdir)/fencing/fence_dummy
cts_SCRIPTS		= HBDummy		\
			  LSBDummy		\
			  lxc_autogen.sh	\
			  pacemaker-cts-dummyd

SUBDIRS	= benchmark
