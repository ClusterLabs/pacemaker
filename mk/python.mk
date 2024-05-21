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
	PYTHONPATH=$(abs_top_builddir)/python \
	pylint --rcfile $(top_srcdir)/python/pylintrc $(PYCHECKFILES)

# Disabled warnings:
# W503 - Line break occurred before a binary operator
#        (newer versions of pyflake and PEP8 want line breaks after binary
#        operators, but older versions still suggest before)
# E501 - Line too long
#
# Disable unused imports on __init__.py files (we likely just have them
# there for re-exporting).
# Disable docstrings warnings on unit tests.
.PHONY: pyflake
pyflake: $(PYCHECKFILES)
	PYTHONPATH=$(abs_top_builddir)/python \
	flake8 --ignore=W503,E501 --per-file-ignores="__init__.py:F401 tests/*:D100,D101,D102,D104" $(PYCHECKFILES)
