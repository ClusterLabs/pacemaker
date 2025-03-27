#
# Copyright 2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

.PHONY: pylint
pylint: $(PYCHECKFILES)
	PYTHONPATH=$(abs_top_builddir)/python:$(abs_top_builddir)/python/pacemaker/.libs \
	pylint --rcfile $(top_srcdir)/python/pylintrc $(PYCHECKFILES)

# Disabled warnings:
# W503 - Line break occurred before a binary operator
#        (newer versions of pyflake and PEP8 want line breaks after binary
#        operators, but older versions still suggest before)
# E402 - Module level import not at top of file
# 	 (pylint already warns about this, and we shouldn't need to add
# 	 ignore pragmas for two tools)
# E501 - Line too long
# F401 - Imported but not used
# 	 (pylint already warns about this, and we shouldn't need to add
# 	 ignore pragmas for two tools)
#
# Disable docstrings warnings on unit tests.
.PHONY: pyflake
pyflake: $(PYCHECKFILES)
	PYTHONPATH=$(abs_top_builddir)/python:$(abs_top_builddir)/python/pacemaker/.libs \
	flake8 --ignore=W503,E402,E501,F401 --per-file-ignores="tests/*:D100,D101,D102,D104" $(PYCHECKFILES)
