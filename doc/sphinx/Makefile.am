#
# Copyright 2003-2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/mk/common.mk

# Define release-related variables
include $(top_srcdir)/mk/release.mk

# Things you might want to override on the command line

# Books to generate
BOOKS		?= Clusters_from_Scratch	\
		   Pacemaker_Administration	\
		   Pacemaker_Development	\
		   Pacemaker_Explained		\
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
BOOK_FORMATS	?= singlehtml

# Set to "a4paper" or "letterpaper" if building latex format
PAPER          ?= letterpaper

# Additional options for sphinx-build
SPHINXFLAGS	?=

# toplevel rsync destination for www targets (without trailing slash)
RSYNC_DEST	?= root@www.clusterlabs.org:/var/www/html

# End of useful overrides


# Example scheduler transition graphs
# @TODO The original CIB XML for these is long lost. Ideally, we would recreate
# something similar and keep those here instead of the DOTs (or use a couple of
# scheduler regression test inputs instead), then regenerate the SVG
# equivalents using crm_simulate and dot when making a release.
DOTS =	$(wildcard shared/images/*.dot)

# Vector sources for generated PNGs (including SVG equivalents of DOTS, created
# manually using dot)
SVGS =	$(wildcard shared/images/pcmk-*.svg) $(DOTS:%.dot=%.svg)

# PNG images generated from SVGS
#
# These will not be accessible in a VPATH build, which will generate warnings
# when building the documentation, but the make will still succeed. It is
# nontrivial to get them working for VPATH builds and not worth the effort.
PNGS_GENERATED	= $(SVGS:%.svg=%.png)

# Original PNG image sources
PNGS_Clusters_from_Scratch = $(wildcard Clusters_from_Scratch/images/*.png)
PNGS_Pacemaker_Explained   = $(wildcard Pacemaker_Explained/images/*.png)
PNGS_Pacemaker_Remote      = $(wildcard Pacemaker_Remote/images/*.png)

STATIC_FILES	= $(wildcard _static/*.css)

EXTRA_DIST	= $(wildcard */*.rst) $(DOTS) $(SVGS)		\
		  $(PNGS_Clusters_from_Scratch)			\
		  $(PNGS_Pacemaker_Explained)			\
		  $(PNGS_Pacemaker_Remote)			\
		  $(STATIC_FILES)				\
		  conf.py.in

# recursive, preserve symlinks/permissions/times, verbose, compress,
# don't cross filesystems, sparse, show progress
RSYNC_OPTS      = -rlptvzxS --progress

BOOK_RSYNC_DEST	= $(RSYNC_DEST)/$(PACKAGE)/doc/$(PACKAGE_SERIES)

BOOK		= none

DEPS_intro			= shared/pacemaker-intro.rst $(PNGS_GENERATED)

DEPS_Clusters_from_Scratch	= $(DEPS_intro) $(PNGS_Clusters_from_Scratch)
DEPS_Pacemaker_Administration	= $(DEPS_intro)
DEPS_Pacemaker_Development	=
DEPS_Pacemaker_Explained	= $(DEPS_intro) $(PNGS_Pacemaker_Explained)
DEPS_Pacemaker_Remote		= $(PNGS_Pacemaker_Remote)

if BUILD_SPHINX_DOCS

INKSCAPE_CMD	= $(INKSCAPE) --export-dpi=90 -C

# Pattern rule to generate PNGs from SVGs
# (--export-png works with Inkscape <1.0, --export-filename with >=1.0;
# create the destination directory in case this is a VPATH build)
%.png: %.svg
	$(AM_V_at)-$(MKDIR_P) "$(shell dirname "$@")"
	$(AM_V_GEN) {							\
		$(INKSCAPE_CMD) --export-png="$@" "$<" 2>/dev/null	\
		|| $(INKSCAPE_CMD) --export-filename="$@" "$<";		\
	} $(PCMK_quiet)

# Create a book's Sphinx configuration.
# Create the book directory in case this is a VPATH build.
$(BOOKS:%=%/conf.py): conf.py.in
	$(AM_V_at)-$(MKDIR_P) "$(@:%/conf.py=%)"
	$(AM_V_GEN)sed							\
		-e 's/%VERSION%/$(VERSION)/g'				\
		-e 's/%BOOK_ID%/$(@:%/conf.py=%)/g'			\
		-e 's/%BOOK_TITLE%/$(subst _, ,$(@:%/conf.py=%))/g'	\
		-e 's#%SRC_DIR%#$(abs_srcdir)#g'			\
		$(<) > "$@"

$(BOOK)/_build: $(STATIC_FILES) $(BOOK)/conf.py $(DEPS_$(BOOK)) $(wildcard $(srcdir)/$(BOOK)/*.rst)
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
			-D latex_elements.papersize=$(PAPER)		\
			$(SPHINXFLAGS)					\
			"$(srcdir)/$(BOOK)" "$@/$$format"		\
			$(PCMK_quiet);					\
		if [ "$$format" = "pdf" ]; then				\
			$(MAKE) $(AM_MAKEFLAGS)	-C "$@/$$format"	\
				all-pdf;				\
		fi;							\
	done
endif

build-$(PACKAGE_SERIES).txt: all
	$(AM_V_GEN)echo "Generated on `date --utc` from version $(TAG)" > "$@"

.PHONY: books-upload
books-upload: all build-$(PACKAGE_SERIES).txt
if BUILD_SPHINX_DOCS
	@echo "Uploading $(PACKAGE_SERIES) documentation set"
	@for book in $(BOOKS); do 					\
		echo " * $$book";					\
		rsync $(RSYNC_OPTS) $(BOOK_FORMATS:%=$$book/_build/%)	\
			"$(BOOK_RSYNC_DEST)/$$book/";			\
	done
	@rsync $(RSYNC_OPTS) "$(builddir)/build-$(PACKAGE_SERIES).txt"	\
		"$(RSYNC_DEST)/$(PACKAGE)/doc"

all-local:
	@for book in $(BOOKS); do					\
		$(MAKE) $(AM_MAKEFLAGS) BOOK=$$book			\
			PAPER="$(PAPER)" SPHINXFLAGS="$(SPHINXFLAGS)"	\
			BOOK_FORMATS="$(BOOK_FORMATS)" $$book/_build;	\
	done

install-data-local: all-local
	$(AM_V_at)for book in $(BOOKS); do				\
		for format in $(BOOK_FORMATS); do			\
			formatdir="$$book/_build/$$format";		\
			for f in `find "$$formatdir" -print`; do	\
				dname="`echo $$f | sed s:_build/::`";	\
				dloc="$(DESTDIR)/$(docdir)/$$dname";	\
				if [ -d "$$f" ]; then			\
					$(INSTALL) -d -m 755 "$$dloc";	\
				else					\
					$(INSTALL_DATA) "$$f" "$$dloc";	\
				fi					\
			done;						\
		done;							\
	done

uninstall-local:
	$(AM_V_at)for book in $(BOOKS); do		\
		rm -rf "$(DESTDIR)/$(docdir)/$$book";	\
	done
endif

clean-local:
	$(AM_V_at)-rm -rf				\
		$(BOOKS:%="$(builddir)/%/_build")	\
		$(BOOKS:%="$(builddir)/%/conf.py")	\
		$(PNGS_GENERATED)
