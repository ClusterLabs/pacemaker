#
# Copyright 2001-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
MAINTAINERCLEANFILES    = Makefile.in

pedir		= $(datadir)/$(PACKAGE)/tests/scheduler

.PHONY: list
list:
	@for T in "$(srcdir)"/xml/*.xml; do       \
		echo $$(basename $$T .xml);             \
	done

SUBDIRS	= dot 		\
	  exp 		\
	  scores 	\
	  stderr 	\
	  summary 	\
	  xml
