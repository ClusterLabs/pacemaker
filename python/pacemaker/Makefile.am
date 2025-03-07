#
# Copyright 2023-2025 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk

pyexec_LTLIBRARIES = _pcmksupport.la

_pcmksupport_la_SOURCES = pcmksupport.c
_pcmksupport_la_CPPFLAGS = $(PYTHON_CFLAGS)
_pcmksupport_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version -export-symbols-regex PyInit__pcmksupport
_pcmksupport_la_LIBADD = $(top_builddir)/lib/pacemaker/libpacemaker.la

pkgpython_PYTHON = __init__.py 		\
		   _library.py 		\
		   exceptions.py 	\
		   exitstatus.py 	\
		   resource.py

nodist_pkgpython_PYTHON = buildoptions.py

SUBDIRS = _cts
