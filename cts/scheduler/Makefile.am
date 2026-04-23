#
# Copyright 2001-2026 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk

pedir		= $(datadir)/$(PACKAGE)/tests/scheduler

.PHONY: list
list:
	@for T in "$(srcdir)"/xml/*.xml; do       \
		echo $$(basename $$T .xml);             \
	done

SUBDIRS = dot
SUBDIRS += exp
SUBDIRS += scores
SUBDIRS += stderr
SUBDIRS += summary
SUBDIRS += xml
