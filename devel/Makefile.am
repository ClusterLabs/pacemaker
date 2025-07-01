#
# Copyright 2020-2025 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk
include $(top_srcdir)/mk/release.mk

EXTRA_DIST = README 	\
	     gdbhelpers

#
# Static analysis
#

## clang

# See scan-build(1) for possible checkers (leave empty to use default set)
CLANG_checkers ?=

.PHONY: clang
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
	-rm -rf "$(abs_top_builddir)"/coverity-*			\
		"$(abs_top_builddir)"/$(PACKAGE)-coverity-*.tgz	\
		"$(abs_top_builddir)"/*.coverity


## cppcheck

GLIB_CFLAGS	?= $(pkg-config --cflags glib-2.0)
GLIB_INCL_DEF_CFLAGS = $(shell echo $(GLIB_CFLAGS) 		\
				| tr ' ' '\n' | grep '^-[IDU]' | paste -d ' ')

# Use CPPCHECK_ARGS to pass extra cppcheck options, e.g.:
# --enable={warning,style,performance,portability,information,all}
# --inconclusive --std=posix
# -DDEFAULT_CONCURRENT_FENCING_TRUE
CPPCHECK_ARGS ?=

CPPCHECK_DIRS = replace lib daemons tools
CPPCHECK_OUT = $(abs_top_builddir)/cppcheck.out

.PHONY: cppcheck
cppcheck:
	cppcheck $(CPPCHECK_ARGS) -I $(top_srcdir)/include	\
		-I $(top_srcdir)/lib/common 			\
		--check-level=exhaustive 			\
		--include=/usr/include/qb/qblog.h 		\
		--output-file=$(CPPCHECK_OUT)			\
		--max-configs=30 --inline-suppr -q		\
		--library=posix --library=gnu --library=gtk	\
		$(GLIB_INCL_DEF_CFLAGS) -D__GNUC__ 		\
		$(foreach dir,$(CPPCHECK_DIRS),$(top_srcdir)/$(dir))
	@echo "Done: See $(CPPCHECK_OUT)"
	@echo "When no longer needed, make cppcheck-clean"

.PHONY: cppcheck-clean
cppcheck-clean:
	-rm -f "$(CPPCHECK_OUT)"

#
# Coverage/profiling
#

COVERAGE_DIR = $(abs_top_builddir)/coverage

# Check coverage of unit tests
.PHONY: coverage
coverage: coverage-partial-clean
	cd $(top_builddir) 						\
	&& $(MAKE) $(AM_MAKEFLAGS) 					\
	&& lcov --capture --no-external --exclude='*_test.c' --initial 	\
		--directory lib --ignore-errors=unused 			\
		--output-file pacemaker_base.info 			\
	&& $(MAKE) $(AM_MAKEFLAGS) check 				\
	&& lcov --capture --no-external --exclude='*_test.c' 		\
		--directory lib --ignore-errors=unused 			\
		--output-file pacemaker_test.info 			\
	&& lcov --add-tracefile pacemaker_base.info 			\
		--add-tracefile pacemaker_test.info			\
		--output-file pacemaker_total.info 			\
	&& genhtml --output-directory $(COVERAGE_DIR) 			\
		--show-details --title "Pacemaker library code coverage"\
		pacemaker_total.info

# Check coverage of CLI regression tests
.PHONY: coverage-cts
coverage-cts: coverage-partial-clean
	cd $(top_builddir) 						\
	&& $(MAKE) $(AM_MAKEFLAGS) 					\
	&& lcov --capture --no-external --initial --directory tools 	\
		--output-file pacemaker_base.info 			\
	&& cts/cts-cli 							\
	&& lcov --capture --no-external --directory tools 		\
		--output-file pacemaker_test.info 			\
	&& lcov --add-tracefile pacemaker_base.info 			\
		--add-tracefile pacemaker_test.info			\
		--output-file pacemaker_total.info 			\
	&& genhtml --output-directory $(COVERAGE_DIR) 			\
		--show-details --title "Pacemaker tools code coverage" 	\
		pacemaker_total.info

# Remove coverage-related files that aren't needed across runs
.PHONY: coverage-partial-clean
coverage-partial-clean:
	-rm -f $(top_builddir)/pacemaker_*.info
	-rm -rf $(COVERAGE_DIR)
	-find $(top_builddir) -name "*.gcda" -exec rm -f \{\} \;

# This target removes all coverage-related files.  It is only to be run when
# done with coverage analysis and you are ready to go back to normal development,
# starting with re-running ./configure.  It is not to be run in between
# "make coverage" runs.
#
# In particular, the *.gcno files are generated when the source is built.
# Removing those files will break "make coverage" until the whole source tree
# has been built and the *.gcno files generated again.
.PHONY: coverage-clean
coverage-clean: coverage-partial-clean
	-find $(top_builddir) -name "*.gcno" -exec rm -f \{\} \;

# Automatic code formatting - this makes use of clang-format and the .clang-format
# config file.  It's based on GNU coding, but heavily modified for our needs
# and to reflect the C coding guidelines documentation.

# Limit clang-format to these directories
INDENT_DIRS	?= .

# Extra options to pass to clang-format
INDENT_OPTS	?=

.PHONY: indent
indent:
	find $(INDENT_DIRS) -type f -name "*.[ch]" \
		-exec clang-format $(INDENT_OPTS) \{\} \;

#
# Check whether copyrights have been updated appropriately
# (Set COMMIT to desired commit or commit range to check, defaulting to HEAD,
# or set it empty to check uncommitted changes)
#
YEAR		= $(shell date +%Y)
MODIFIED_FILES	= $(shell case "$(COMMIT)" in				\
		  	[0-9a-f]*$(rparen)				\
				git diff-tree --no-commit-id		\
					--name-only "$(COMMIT)" -r ;;	\
		  	*$(rparen)					\
				cd "$(top_srcdir)";			\
				git ls-files --modified ;;		\
			esac)

.PHONY: copyright
copyright:
	@cd "$(top_srcdir)" && for file in $(MODIFIED_FILES); do	\
		if ! grep 'opyright .*$(YEAR).* Pacemaker' "$$file"	\
			>/dev/null 2>&1; then				\
			echo "$$file";					\
		fi;							\
	done

#
# Scratch file for ad-hoc testing
#

EXTRA_PROGRAMS		= scratch
nodist_scratch_SOURCES	= scratch.c
scratch_LDADD		= $(top_builddir)/lib/common/libcrmcommon.la

.PHONY: clean-local
clean-local: coverage-clean coverity-clean cppcheck-clean
	-rm -f $(EXTRA_PROGRAMS)
