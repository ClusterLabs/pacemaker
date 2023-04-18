#
# Copyright 2001-2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

MAINTAINERCLEANFILES    = Makefile.in

noinst_SCRIPTS		= cluster_test		\
			  OCFIPraTest.py

# Commands intended to be run only via other commands
halibdir		= $(CRM_DAEMON_DIR)
dist_halib_SCRIPTS	= cts-log-watcher

ctslibdir		= $(pythondir)/cts
ctslib_PYTHON		= __init__.py		\
			  CIB.py		\
			  cib_xml.py		\
			  ClusterManager.py	\
			  CM_corosync.py	\
			  CTSscenarios.py	\
			  CTStests.py

ctsdir			= $(datadir)/$(PACKAGE)/tests/cts
cts_SCRIPTS		= CTSlab.py		\
			  cts
