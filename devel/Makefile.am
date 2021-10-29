#
# Copyright 2020-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

# Coccinelle is a tool that takes special patch-like files (called semantic patches) and
# applies them throughout a source tree.  This is useful when refactoring, changing APIs,
# catching dangerous or incorrect code, and other similar tasks.  It's not especially
# easy to write a semantic patch but most users should only be concerned about running
# the target and inspecting the results.
#
# Documentation (including examples, which are the most useful):
#     https://coccinelle.gitlabpages.inria.fr/website/docs/
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
COCCI_FILES ?=	coccinelle/string-any-of.cocci			\
		coccinelle/string-empty.cocci			\
		coccinelle/string-null-matches.cocci		\
		coccinelle/use-func.cocci


dist_noinst_SCRIPTS	= coccinelle/test/testrunner.sh
EXTRA_DIST		= README gdbhelpers $(COCCI_FILES)		\
			  coccinelle/ref-passed-variables-inited.cocci	\
			  coccinelle/rename-fn.cocci			\
			  coccinelle/test/ref-passed-variables-inited.input.c \
			  coccinelle/test/ref-passed-variables-inited.output

# Any file in this list is allowed to use any of the pcmk__ internal functions.
# Coccinelle can use any transformation that depends on "internal" to rewrite
# code to use the internal functions.
MAY_USE_INTERNAL_FILES = $(shell find .. -path "../lib/*.c" -o -path "../lib/*private.h" -o -path "../tools/*.c" -o -path "../daemons/*.c" -o -path '../include/pcmki/*h' -o -name '*internal.h')

# And then any file in this list is public API, which may not use internal
# functions.  Thus, only those transformations that do not depend on "internal"
# may be applied.
OTHER_FILES = $(shell find ../include -name '*h' -a \! -name '*internal.h' -a \! -path '../include/pcmki/*')

cocci:
	-for cf in $(COCCI_FILES); do \
		for f in $(MAY_USE_INTERNAL_FILES); do \
			spatch $(_SPATCH_FLAGS) -D internal --very-quiet --local-includes --preprocess --sp-file $$cf $$f; \
		done ; \
		for f in $(OTHER_FILES); do \
			spatch $(_SPATCH_FLAGS) --very-quiet --local-includes --preprocess --sp-file $$cf $$f; \
		done ; \
	done

cocci-inplace:
	$(MAKE) $(AM_MAKEFLAGS) _SPATCH_FLAGS=--in-place cocci

cocci-test:
	for f in coccinelle/test/*.c; do \
		coccinelle/test/testrunner.sh $$f; \
	done

# Scratch file for ad-hoc testing
EXTRA_PROGRAMS		= scratch
nodist_scratch_SOURCES	= scratch.c
scratch_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la

clean-local:
	-rm -f $(EXTRA_PROGRAMS)
