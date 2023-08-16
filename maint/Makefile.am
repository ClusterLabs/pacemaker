#
# Copyright 2019-2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

# Define release-related variables
include $(abs_srcdir)/../mk/release.mk

noinst_SCRIPTS		= bumplibs
EXTRA_DIST		= README

#
# Change log generation
#

# Count changes in these directories
CHANGELOG_DIRS = ../include ../lib ../daemons ../tools ../xml

.PHONY: require_last_release
require_last_release:
	@if [ -z "$(CHECKOUT)" ]; then					\
		echo "This target must be run from a git checkout";	\
		exit 1;							\
	elif ! git rev-parse $(LAST_RELEASE) >/dev/null 2>&1; then	\
		echo "LAST_RELEASE must be set to a valid git tag";	\
		exit 1;							\
	fi

.PHONY: summary
summary: require_last_release
	@printf "* %s %s <%s> %s\n" "$$(date +'%a %b %d %Y')"		\
		"$$(git config user.name)" "$$(git config user.email)"	\
		"$(NEXT_RELEASE)"
	@printf "\055 %d commits with%s\n"				\
		"$$(git log --pretty=oneline --no-merges		\
			$(LAST_RELEASE)..HEAD | wc -l)"			\
		"$$(git diff $(LAST_RELEASE)..HEAD --shortstat		\
			$(CHANGELOG_DIRS))"

.PHONY: changes
changes: summary
	@printf "\n- Features added since $(LAST_RELEASE)\n"
	@git log --pretty=format:'%s' --no-merges			\
		--abbrev-commit $(LAST_RELEASE)..HEAD			\
		| sed -n -e 's/^ *Feature: */  + /p' | sort -uf
	@printf "\n- Fixes since $(LAST_RELEASE)\n"
	@git log --pretty=format:'%s' --no-merges			\
		--abbrev-commit $(LAST_RELEASE)..HEAD			\
		| sed -n -e 's/^ *\(Fix\|High\|Bug\): */  + /p' | sed	\
		-e 's/\(cib\|pacemaker-based\|based\):/CIB:/'		\
		-e 's/\(lrmd\|pacemaker-execd\|execd\):/executor:/'	\
		-e 's/\(crmd\|pacemaker-controld\|controld\):/controller:/'		\
		-e 's/\(Fencing\|stonithd?\|pacemaker-fenced\|fenced\):/fencing:/'	\
		-e 's/\(PE\|pengine\|pacemaker-schedulerd\|schedulerd\):/scheduler:/'	\
		| sort -uf
	@printf "\n- Public API changes since $(LAST_RELEASE)\n"
	@git log --pretty=format:'%s' --no-merges			\
		--abbrev-commit $(LAST_RELEASE)..HEAD			\
		| sed -n -e 's/^ *API: */  + /p' | sort -uf

.PHONY: changelog
changelog: require_last_release
	@printf "%s\n\n%s\n"						\
		"$$($(MAKE) $(AM_MAKEFLAGS) changes			\
			| grep -v 'make\(\[[0-9]*\]\)\?:')"		\
		"$$(cat ../ChangeLog)" > ../ChangeLog

.PHONY: authors
authors: require_last_release
	git log $(LAST_RELEASE)..$(COMMIT) --format='%an' | sort -u
