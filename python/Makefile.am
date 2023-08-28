#
# Copyright 2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

MAINTAINERCLEANFILES    = Makefile.in

EXTRA_DIST = pylintrc

SUBDIRS	= pacemaker \
	  tests

.PHONY: check-local
check-local:
	PYTHONPATH=$(top_srcdir)/python:$(top_builddir)/python $(PYTHON) -m unittest discover -v -s $(top_srcdir)/python/tests $(top_builddir)/python/tests

.PHONY: pylint
pylint:
	pylint $(SUBDIRS)
