#
# Copyright 2023-2024 the Pacemaker project contributors
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
	if [ "x$(top_srcdir)" != "x$(top_builddir)" ]; then \
		cp -r $(top_srcdir)/python/* $(abs_top_builddir)/python/; \
	fi
	PYTHONPATH=$(top_builddir)/python $(PYTHON) -m unittest discover -v -s $(top_builddir)/python/tests

.PHONY: pylint
pylint:
	pylint $(SUBDIRS)

# Disabled warnings:
# E501 - Line too long
#
# Disable unused imports on __init__.py files (we likely just have them
# there for re-exporting).
# Disable docstrings warnings on unit tests.
.PHONY: pyflake
pyflake:
	flake8 --ignore=E501 --per-file-ignores="__init__.py:F401 tests/*:D100,D101,D102,D104" $(SUBDIRS)
