#
# Copyright 2008-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

# Define variables related to release version and such

COMMIT  ?= HEAD

# TAG defaults to DIST when not in a git checkout (e.g. from a distribution),
# the tag name if COMMIT is tagged, and the full commit ID otherwise.
TAG     ?= $(shell T=$$(git describe --tags --exact-match '$(COMMIT)' 2>/dev/null); \
	     test -n "$${T}" && echo "$${T}" \
	       || git log --pretty=format:%H -n 1 '$(COMMIT)' 2>/dev/null || echo DIST)
lparen = (
rparen = )

LAST_RC		?= $(shell git tag -l|sed -n -e 's/^\(Pacemaker-[0-9.]*-rc[0-9]*\)$$/\1/p'|sort -Vr|head -n 1)
LAST_FINAL	?= $(shell git tag -l|sed -n -e 's/^\(Pacemaker-[0-9.]*\)$$/\1/p'|sort -Vr|head -n 1)
LAST_RELEASE	?= $(shell test "Pacemaker-$(VERSION)" = "Pacemaker-" && echo "$(LAST_FINAL)" || echo "Pacemaker-$(VERSION)")
NEXT_RELEASE	?= $(shell echo $(LAST_RELEASE) | awk -F. '/[0-9]+\./{$$3+=1;OFS=".";print $$1,$$2,$$3}')

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
# The directory is named pacemaker-DIST when not in a git checkout (e.g.
# from a distribution itself), pacemaker-<version_part_of_tag> for tagged
# commits, and pacemaker-<short_commit> otherwise.
top_distdir	= $(PACKAGE)-$(shell						\
		  case $(TAG) in						\
			DIST$(rparen)						\
				echo DIST;;					\
			Pacemaker-*$(rparen)					\
				echo '$(TAG)' | cut -c11-;;			\
			*$(rparen)						\
				git log --pretty=format:%h -n 1 '$(TAG)';;	\
		  esac)$(shell if [ -n "$(DIRTY)" ]; then echo ".mod"; fi)
