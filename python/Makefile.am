#
# Copyright 2023-2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/python.mk

MAINTAINERCLEANFILES    = Makefile.in

EXTRA_DIST = pylintrc

SUBDIRS	= pacemaker \
	  tests

PYCHECKFILES ?= $(SUBDIRS)

.PHONY: check-local
check-local:
	if [ "x$(top_srcdir)" != "x$(top_builddir)" ]; then \
		cp -r $(top_srcdir)/python/* $(abs_top_builddir)/python/; \
	fi
	PYTHONPATH=$(top_builddir)/python $(PYTHON) -m unittest discover -v -s $(top_builddir)/python/tests
