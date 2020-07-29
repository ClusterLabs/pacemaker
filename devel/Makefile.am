#
# Copyright 2020 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

EXTRA_SCRIPTS		= coccinelle/test/testrunner.sh
EXTRA_DIST		= $(EXTRA_SCRIPTS) \
				  coccinelle/ref-passed-variables-inited.cocci \
				  coccinelle/test/ref-passed-variables-inited.input.c \
				  coccinelle/test/ref-passed-variables-inited.output

# Coccinelle is a tool that takes special patch-like files (called semantic patches) and
# applies them throughout a source tree.  This is useful when refactoring, changing APIs,
# catching dangerous or incorrect code, and other similar tasks.  It's not especially
# easy to write a semantic patch but most users should only be concerned about running
# the target and inspecting the results.
#
# Documentation (including examples, which are the most useful):
# http://coccinelle.lip6.fr/documentation.php
#
# Run the "make cocci" target to just output what would be done, or "make cocci-inplace"
# to apply the changes to the source tree.
#
# COCCI_FILES may be set on the command line, if you want to test just a single file
# while it's under development.  Otherwise, it is a list of all the files that are ready
# to be run.
#
# ref-passed-variables-inited.cocci seems to be returning some false positives around
# GHashTableIters, so it is disabled for the moment.
COCCI_FILES ?=

cocci:
	for f in $(COCCI_FILES); do \
	  for d in daemons include lib tools; do \
	    test $$d = "include" \
	      && spatch $(_SPATCH_FLAGS) --include-headers --local-includes \
	         --preprocess --sp-file $$f --dir ../$$d \
		  || spatch $(_SPATCH_FLAGS) --local-includes \
			 --preprocess --sp-file $$f --dir ../$$d; \
		done; \
	done

cocci-inplace:
	$(MAKE) $(AM_MAKEFLAGS) _SPATCH_FLAGS=--in-place cocci

cocci-test:
	for f in coccinelle/test/*.c; do \
		coccinelle/test/testrunner.sh $$f; \
	done
