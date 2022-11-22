#
# Copyright 2008-2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

# Define variables related to release version and such

COMMIT	?= HEAD

# TAG defaults to DIST when in a source distribution instead of a git checkout,
# the tag name if COMMIT is tagged, and the full commit ID otherwise.
TAG	?= $(shell								\
	     T=$$(git describe --tags --exact-match '$(COMMIT)' 2>/dev/null);	\
	     [ -n "$${T}" ] && echo "$${T}" 					\
	     || git log --pretty=format:%H -n 1 '$(COMMIT)' 2>/dev/null		\
	     || echo DIST)

# If DIRTY=anything is passed to make, generated versions will end in ".mod"
# as long as there are uncommitted changes and COMMIT is not changed from the
# default.
DIRTY_EXT	= $(shell [ -n "$(DIRTY)" ]				\
			&& [ "$(COMMIT)" == "HEAD" ] 			\
			&& ! git diff-index --quiet HEAD -- 2>/dev/null	\
			&& echo .mod)

# These can be used in case statements to avoid make interpreting parentheses
lparen = (
rparen = )

# git tag of highest-versioned release candidate (such as "Pacemaker-2.1.5-rc2")
# or empty if not in git checkout
LAST_RC		?= $(shell git tag -l 2>/dev/null				\
		     | sed -n -e 's/^\(Pacemaker-[0-9.]*-rc[0-9]*\)$$/\1/p'	\
		     | sort -Vr | head -n 1)

# This will be empty if not in a git checkout
CHECKOUT	= $(shell git rev-parse --git-dir 2>/dev/null)

# VERSION is set by configure, but we allow some make targets to be run without
# running configure first, so set a reasonable default in that case.
VERSION		?= $(shell if [ -z "$(CHECKOUT)" ]; then			\
			echo 0.0.0;						\
		     else							\
			git tag -l						\
				| sed -n -e 's/^\(Pacemaker-[0-9.]*\)$$/\1/p'	\
				| sort -Vr | head -n 1;				\
		     fi)

# What the git tag would be for configured VERSION (such as "Pacemaker-2.1.5")
LAST_RELEASE	?= Pacemaker-$(VERSION)

# What the git tag would be for configured VERSION with minor-minor version bump
# (such as "Pacemaker-2.1.6"; this should be manually overriden when bumping
# the major or minor version)
NEXT_RELEASE	?= $(shell echo $(LAST_RELEASE) 			\
		     | awk -F. '/[0-9]+\./{$$3+=1;OFS=".";print $$1,$$2,$$3}')

# We have two make targets for creating distributions:
#
# - "make dist" is automake's native functionality, based on the various
#   dist/nodist make variables; it always uses the current sources
#
# - "make export" is a custom target based on "git archive" and relevant
#   entries from .gitattributes; it defaults to current sources but can use any
#   git tag
#
# Both targets use the same name for the result, though they generate different
# contents.
#
# The directory is named pacemaker-<version> when in a source distribution
# instead of a git checkout, pacemaker-<version_part_of_tag> for tagged
# commits, and pacemaker-<short_commit> otherwise.
top_distdir	= $(PACKAGE)-$(shell						\
		  case $(TAG) in						\
			DIST$(rparen)						\
				[ -n "$(VERSION)" ] && echo "$(VERSION)"	\
					|| echo DIST;;				\
			Pacemaker-*$(rparen)					\
				echo '$(TAG)' | cut -c11-;;			\
			*$(rparen)						\
				git log --pretty=format:%h -n 1 '$(TAG)';;	\
		  esac)$(DIRTY_EXT)
