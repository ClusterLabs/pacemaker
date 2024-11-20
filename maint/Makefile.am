#
# Copyright 2019-2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

# Define release-related variables
include $(top_srcdir)/mk/release.mk
include $(top_srcdir)/mk/common.mk

noinst_SCRIPTS		= bumplibs
EXTRA_DIST		= README

#
# Change log generation
#

# Count changes in these directories
CHANGELOG_DIRS = ../include 	\
		 ../lib 	\
		 ../daemons 	\
		 ../tools 	\
		 ../xml

.PHONY: require_last_release
require_last_release:
	@if [ -z "$(CHECKOUT)" ]; then					\
		echo "This target must be run from a git checkout";	\
		exit 1;							\
	elif ! "$(GIT)" rev-parse $(LAST_RELEASE) >/dev/null 2>&1; then	\
		echo "LAST_RELEASE must be set to a valid git tag";	\
		exit 1;							\
	fi

.PHONY: summary
summary: require_last_release
	@printf "# %s (%s)\n* %d commits with%s\n"			\
		"$(NEXT_RELEASE)" "$$(date +'%d %b %Y')"		\
		"$$("$(GIT)" log --pretty=oneline --no-merges		\
			$(LAST_RELEASE)..HEAD | wc -l)"			\
		"$$("$(GIT)" diff $(LAST_RELEASE)..HEAD --shortstat	\
			$(CHANGELOG_DIRS))"

.PHONY: changes
changes: summary
	@printf "\n## Features added since $(LAST_RELEASE)\n\n"
	@"$(GIT)" log --pretty=format:'%s' --no-merges			\
		--abbrev-commit $(LAST_RELEASE)..HEAD			\
		| sed -n -e 's/^ *Feature: */* /p' | sort -uf		\
		| sed -e 's/^\( *[-+*] \)\([^:]*:\)\(.*\)$$/\1**\2**\3/'	\
		      -e 's/\([ (]\)\([A-Za-z0-9]*_[^ ,]*\)/\1`\2`/g'
	@printf "\n## Fixes since $(LAST_RELEASE)\n\n"
	@"$(GIT)" log --pretty=format:'%s' --no-merges			\
		--abbrev-commit $(LAST_RELEASE)..HEAD			\
		| sed -n -e 's/^ *\(Fix\|High\|Bug\): */* /p'		\
		| sed -e 's/\(\(pacemaker-\)?based\):/CIB:/'		\
		      -e 's/\(\(pacemaker-\)?execd\):/executor:/'	\
		      -e 's/\(\(pacemaker-\)?controld\):/controller:/'	\
		      -e 's/\(\(pacemaker-\)?fenced\):/fencing:/'	\
		| sort -uf						\
		| sed -e 's/^\( *[-+*] \)\([^:]*:\)\(.*\)$$/\1**\2**\3/'	\
		      -e 's/\([ (]\)\([A-Za-z0-9]*_[^ ,]*\)/\1`\2`/g'
	@printf "\n## Public API changes since $(LAST_RELEASE)\n\n"
	@"$(GIT)" log --pretty=format:'%s' --no-merges			\
		--abbrev-commit $(LAST_RELEASE)..HEAD			\
		| sed -n -e 's/^ *API: */* /p' | sort -uf		\
		| sed -e 's/^\( *[-+*] \)\([^:]*:\)\(.*\)$$/\1**\2**\3/'	\
		      -e 's/\([ (]\)\([A-Za-z0-9]*_[^ ,]*\)/\1`\2`/g'

.PHONY: changelog
changelog: require_last_release
	@printf "%s\n\n%s\n"						\
		"$$($(MAKE) $(AM_MAKEFLAGS) changes			\
			| grep -v 'make\(\[[0-9]*\]\)\?:')"		\
		"$$(cat ../ChangeLog.md)" > ../ChangeLog.md

.PHONY: authors
authors: require_last_release
	"$(GIT)" log $(LAST_RELEASE)..$(COMMIT) --format='%an' | sort -u
