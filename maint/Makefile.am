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

#
# gnulib updates
#
# See https://www.gnu.org/software/gnulib/manual/html_node/
#

# V3	= scandir unsetenv alphasort xalloc
# V2	= setenv strerror strchrnul strndup
GNU_MODS	= crypto/md5-buffer
# stdint appears to be surrogate only for C99-lacking environments
GNU_MODS_AVOID	= stdint

.PHONY: gnulib-update
gnulib-update:
	@echo 'Newer versions of gnulib require automake 1.14'
	@echo 'Pacemaker cannot update until minimum supported automake is 1.14'
	@exit 1
	if test -e gnulib; then							\
		cd gnulib && git pull;						\
	else									\
		git clone https://git.savannah.gnu.org/git/gnulib.git gnulib	\
			&& cd gnulib && git config pull.rebase false;		\
	fi
	cd $(top_srcdir) && maint/gnulib/gnulib-tool --source-base=lib/gnu 	\
		--lgpl=2 --no-vc-files --no-conditional-dependencies --libtool	\
		$(GNU_MODS_AVOID:%=--avoid %) --import $(GNU_MODS)
	sed -i -e "s/bundled(gnulib).*/bundled(gnulib) = `date +'%Y%m%d'`/"	\
		../rpm/pacemaker.spec.in
	sed -i -e "s/_GL_EXTERN_INLINE/_GL_INLINE/" 				\
		-e "s#left_over -= 64;#left_over \&= 63; /* helps static analysis */#"	\
		-e "s#&ctx->buffer\[16\]#\&(((char *) ctx->buffer)[64]) /* helps static analysis */#"	\
		../lib/gnu/md5.c
