#
# Copyright 2020-2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk
include $(top_srcdir)/mk/release.mk

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

#
# Static analysis
#

## clang

# See scan-build(1) for possible checkers (leave empty to use default set)
CLANG_checkers ?=

clang:
	OUT=$$(cd $(top_builddir)					\
		&& scan-build $(CLANG_checkers:%=-enable-checker %)	\
		$(MAKE) $(AM_MAKEFLAGS) CFLAGS="-std=c99 $(CFLAGS)"	\
		clean all 2>&1);					\
	REPORT=$$(echo "$$OUT"						\
		| sed -n -e "s/.*'scan-view \(.*\)'.*/\1/p");		\
	[ -z "$$REPORT" ] && echo "$$OUT" || scan-view "$$REPORT"

## coverity

# Aggressiveness (low, medium, or high)
COVLEVEL	?= low

# Generated outputs
COVERITY_DIR	= $(abs_top_builddir)/coverity-$(TAG)
COVTAR		= $(abs_top_builddir)/$(PACKAGE)-coverity-$(TAG).tgz
COVEMACS	= $(abs_top_builddir)/$(TAG).coverity
COVHTML		= $(COVERITY_DIR)/output/errors

# Coverity outputs are phony so they get rebuilt every invocation

.PHONY: $(COVERITY_DIR)
$(COVERITY_DIR): coverity-clean
	$(MAKE) $(AM_MAKEFLAGS) -C $(top_builddir) init core-clean
	$(AM_V_GEN)cd $(top_builddir)	\
		&& cov-build --dir "$@" $(MAKE) $(AM_MAKEFLAGS) core

# Public coverity instance

.PHONY: $(COVTAR)
$(COVTAR): $(COVERITY_DIR)
	$(AM_V_GEN)tar czf "$@" --transform="s@.*$(TAG)@cov-int@" "$<"

.PHONY: coverity
coverity: $(COVTAR)
	@echo "Now go to https://scan.coverity.com/users/sign_in and upload:"
	@echo "  $(COVTAR)"
	@echo "then make clean at the top level"

# Licensed coverity instance
#
# The prerequisites are a little hacky; rather than actually required, some
# of them are designed so that things execute in the proper order (which is
# not the same as GNU make's order-only prerequisites).

.PHONY: coverity-analyze
coverity-analyze: $(COVERITY_DIR)
	@echo ""
	@echo "Analyzing (waiting for coverity license if necessary) ..."
	cd $(top_builddir) && cov-analyze --dir "$<" --wait-for-license	\
		--security --aggressiveness-level "$(COVLEVEL)"

.PHONY: $(COVEMACS)
$(COVEMACS): coverity-analyze
	$(AM_V_GEN)cd $(top_builddir)	\
		&& cov-format-errors --dir "$(COVERITY_DIR)" --emacs-style > "$@"

.PHONY: $(COVHTML)
$(COVHTML): $(COVEMACS)
	$(AM_V_GEN)cd $(top_builddir)	\
		&& cov-format-errors --dir "$(COVERITY_DIR)" --html-output "$@"

.PHONY: coverity-corp
coverity-corp: $(COVHTML)
	$(MAKE) $(AM_MAKEFLAGS) -C $(top_builddir) core-clean
	@echo "Done. See:"
	@echo "  file://$(COVHTML)/index.html"
	@echo "When no longer needed, make coverity-clean"

# Remove all outputs regardless of tag
.PHONY: coverity-clean
coverity-clean:
	-rm -rf "$(abs_builddir)"/coverity-*			\
		"$(abs_builddir)"/$(PACKAGE)-coverity-*.tgz	\
		"$(abs_builddir)"/*.coverity


## cppcheck

# Use CPPCHECK_ARGS to pass extra cppcheck options, e.g.:
# --enable={warning,style,performance,portability,information,all}
# --inconclusive --std=posix
# -DBUILD_PUBLIC_LIBPACEMAKER -DDEFAULT_CONCURRENT_FENCING_TRUE
CPPCHECK_ARGS ?=

CPPCHECK_DIRS = replace lib daemons tools
CPPCHECK_OUT = $(abs_top_builddir)/cppcheck.out

cppcheck:
	cppcheck $(CPPCHECK_ARGS) -I $(top_srcdir)/include	\
		--output-file=$(CPPCHECK_OUT)			\
		--max-configs=30 --inline-suppr -q		\
		--library=posix --library=gnu --library=gtk	\
		$(GLIB_CFLAGS) -D__GNUC__ 			\
		$(foreach dir,$(CPPCHECK_DIRS),$(top_srcdir)/$(dir))
	@echo "Done: See $(CPPCHECK_OUT)"
	@echo "When no longer needed, make cppcheck-clean"

.PHONY: cppcheck-clean
cppcheck-clean:
	-rm -f "$(CPPCHECK_OUT)"


#
# indent cannot cope with all our exceptions and needs heavy manual editing
#

# indent target: Limit indent to these directories
INDENT_DIRS	?= .

# indent target: Extra options to pass to indent
INDENT_OPTS	?=

INDENT_IGNORE_PATHS	= daemons/controld/controld_fsa.h	\
			  lib/gnu/*
INDENT_PACEMAKER_STYLE	= --blank-lines-after-declarations		\
			  --blank-lines-after-procedures		\
			  --braces-after-func-def-line			\
			  --braces-on-if-line				\
			  --braces-on-struct-decl-line			\
			  --break-before-boolean-operator		\
			  --case-brace-indentation4			\
			  --case-indentation4				\
			  --comment-indentation0			\
			  --continuation-indentation4			\
			  --continue-at-parentheses			\
			  --cuddle-do-while				\
			  --cuddle-else					\
			  --declaration-comment-column0			\
			  --declaration-indentation1			\
			  --else-endif-column0				\
			  --honour-newlines				\
			  --indent-label0				\
			  --indent-level4				\
			  --line-comments-indentation0			\
			  --line-length80				\
			  --no-blank-lines-after-commas			\
			  --no-comment-delimiters-on-blank-lines	\
			  --no-space-after-function-call-names		\
			  --no-space-after-parentheses			\
			  --no-tabs					\
			  --preprocessor-indentation2			\
			  --procnames-start-lines			\
			  --space-after-cast				\
			  --start-left-side-of-comments			\
			  --swallow-optional-blank-lines		\
			  --tab-size8

indent:
	VERSION_CONTROL=none					\
		find $(INDENT_DIRS) -type f -name "*.[ch]"	\
		$(INDENT_IGNORE_PATHS:%= ! -path '%')		\
		-exec indent $(INDENT_PACEMAKER_STYLE) $(INDENT_OPTS) \{\} \;

#
# Scratch file for ad-hoc testing
#

EXTRA_PROGRAMS		= scratch
nodist_scratch_SOURCES	= scratch.c
scratch_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la

clean-local: coverity-clean cppcheck-clean
	-rm -f $(EXTRA_PROGRAMS)
