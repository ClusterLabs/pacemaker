#
# Copyright 2003-2020 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/mk/common.mk

# Things you might want to override on the command line

# Books to generate
BOOKS		?= Clusters_from_Scratch \
			   Pacemaker_Administration	\
		   Pacemaker_Development	\
		   Pacemaker_Remote

# Output formats to generate. Possible values:
#  html       (multiple HTML files)
#  dirhtml    (HTML files named index.html in multiple directories)
#  singlehtml (a single large HTML file)
#  text
#  pdf
#  epub
#  latex
#  linkcheck  (not actually a format; check validity of external links)
#
# The results will end up in <book>/_build/<format>
BOOK_FORMATS	?= html

# Set to "a4" or "letter" if building latex format
PAPER		?= letter

# Additional options for sphinx-build
SPHINXFLAGS	?=

# toplevel rsync destination for www targets (without trailing slash)
RSYNC_DEST	?= root@www.clusterlabs.org:/var/www/html

# End of useful overrides


EXTRA_DIST	= $(wildcard */*.rst)

# recursive, preserve symlinks/permissions/times, verbose, compress,
# don't cross filesystems, sparse, show progress
RSYNC_OPTS      = -rlptvzxS --progress

BOOK_RSYNC_DEST	= $(RSYNC_DEST)/$(PACKAGE)/doc/$(PACKAGE_SERIES)

TAG	?= $(shell [ -n "`git tag --points-at HEAD | head -1`" ]		\
	           && ( git tag --points-at HEAD | head -1 )			\
		   || git log --pretty=format:Pacemaker-2.0.3-%h -n 1 HEAD)

BOOK		= none

DEPS_Clusters_from_Scratch	= shared/pacemaker-intro.rst
DEPS_Pacemaker_Administration	= shared/pacemaker-intro.rst
DEPS_Pacemaker_Development	=
DEPS_Pacemaker_Remote		=  $(wildcard $(srcdir)/Pacemaker_Remote/images/*.png)

if BUILD_SPHINX_DOCS
$(BOOKS:%=%/conf.py): conf.py.in
	$(AM_V_GEN)sed							\
		-e 's/%VERSION%/$(VERSION)/g'				\
		-e 's/%BOOK_ID%/$(@:%/conf.py=%)/g'			\
		-e 's/%BOOK_TITLE%/$(subst _, ,$(@:%/conf.py=%))/g'	\
		$(<) > "$@"

$(BOOK)/_build: _static/pacemaker.css $(BOOK)/conf.py $(DEPS_$(BOOK)) $(wildcard $(srcdir)/$(BOOK)/*.rst)
	@echo 'Building "$(subst _, ,$(BOOK))" because of $?' $(PCMK_quiet)
	$(AM_V_at)rm -rf "$@"
	$(AM_V_BOOK)for format in $(BOOK_FORMATS); do			\
		echo -e "\n * Building $$format" $(PCMK_quiet);		\
		doctrees="doctrees";					\
		real_format="$$format";					\
		case "$$format" in					\
			pdf) real_format="latex" ;;			\
			gettext) doctrees="gettext-doctrees" ;;		\
		esac;							\
		$(SPHINX) -b "$$real_format" -d "$@/$$doctrees"		\
			-c "$(builddir)/$(BOOK)"			\
			-D latex_paper_size=$(PAPER) $(SPHINXFLAGS)	\
			"$(srcdir)/$(BOOK)" "$@/$$format"		\
			$(PCMK_quiet);					\
		if [ "$$format" = "pdf" ]; then				\
			$(MAKE) $(AM_MAKEFLAGS)	-C "$@/$$format"	\
				all-pdf;				\
		fi;							\
	done
endif

.PHONY: books-upload
books-upload: all
if BUILD_SPHINX_DOCS
	@echo "Uploading $(PACKAGE_SERIES) documentation set"
	@for book in $(BOOKS); do 					\
		echo " * $$book";					\
		buildfile="$$book/_build/build-$(PACKAGE_SERIES).txt";	\
		echo "Generated on `date --utc` from version $(TAG)"	\
			> "$$buildfile";				\
		rsync $(RSYNC_OPTS) "$$buildfile"			\
			$(BOOK_FORMATS:%=$$book/_build/%)		\
			"$(BOOK_RSYNC_DEST)/$$book/";			\
	done
endif

all-local:
if BUILD_SPHINX_DOCS
	@for book in $(BOOKS); do					\
		$(MAKE) $(AM_MAKEFLAGS) BOOK=$$book			\
			PAPER="$(PAPER)" SPHINXFLAGS="$(SPHINXFLAGS)"	\
			BOOK_FORMATS="$(BOOK_FORMATS)" $$book/_build;	\
	done
endif

clean-local:
	$(AM_V_at)-rm -rf $(BOOKS:%="$(builddir)/%/_build") $(BOOKS:%="$(builddir)/%/conf.py")
