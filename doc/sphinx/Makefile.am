#
# Copyright 2003-2026 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/mk/common.mk

# Define release- and upload-related variables
include $(top_srcdir)/mk/release.mk
include $(top_srcdir)/mk/uploads.mk

# Things you might want to override on the command line

# Books to generate
BOOKS		?= Clusters_from_Scratch	\
		   Pacemaker_Administration	\
		   Pacemaker_Development	\
		   Pacemaker_Explained		\
		   Pacemaker_Python_API

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

# End of useful overrides


# All images needed by the documentation are PNGs (added to the source
# repository and distributions). Some of these PNGs can be regenerated
# manually from DOT and/or SVG sources (also in the source repository, but
# not distributed).
#
# To regenerate an SVG from a DOT, you can use dot:
#
#    dot $NAME.dot -Tsvg > $NAME.svg
#
# To regenerate a PNG from an SVG, you can use Inkscape (>= 1.0):
#
#    inkscape --export-dpi=90 -C --export-filename=$NAME.png $NAME.svg
#
# @TODO The original CIB XML for the example scheduler transitions
# (Policy-Engine-*) is long lost. Ideally, we would recreate something similar
# and keep that XML here (or use a couple of scheduler regression test inputs
# instead). Then the DOTs could be regenerated as well, using crm_simulate.
PNGS_shared			= $(wildcard shared/images/*.png)
PNGS_Clusters_from_Scratch	= $(wildcard Clusters_from_Scratch/images/*.png)
PNGS_Pacemaker_Explained	= $(wildcard Pacemaker_Explained/images/*.png)

STATIC_FILES	= $(wildcard _static/*.css)

EXTRA_DIST = $(wildcard */*.rst)
EXTRA_DIST += $(PNGS_shared)
EXTRA_DIST += $(PNGS_Clusters_from_Scratch)
EXTRA_DIST += $(PNGS_Pacemaker_Explained)
EXTRA_DIST += $(wildcard Pacemaker_Python_API/_templates/*rst)
EXTRA_DIST += $(STATIC_FILES)
EXTRA_DIST += conf.py.in

PACKAGE_SERIES=$(shell echo "$(VERSION)" | awk -F. '{ print $$1"."$$2 }')

BOOK_RSYNC_DEST	= $(RSYNC_PACKAGE_DEST)/doc/$(PACKAGE_SERIES)

BOOK		= none

DEPS_intro = shared/pacemaker-intro.rst
DEPS_intro += $(PNGS_shared)

DEPS_Clusters_from_Scratch = $(DEPS_intro)
DEPS_Clusters_from_Scratch += $(PNGS_Clusters_from_Scratch)
DEPS_Pacemaker_Administration	= $(DEPS_intro)
DEPS_Pacemaker_Development	=
DEPS_Pacemaker_Explained = $(DEPS_intro)
DEPS_Pacemaker_Explained += $(PNGS_Pacemaker_Explained)
DEPS_Pacemaker_Python_API 	= ../../python

if BUILD_SPHINX_DOCS

# Create a book's Sphinx configuration.
# Create the book directory in case this is a VPATH build.
$(BOOKS:%=%/conf.py): conf.py.in
	$(AM_V_at)-$(MKDIR_P) "$(@:%/conf.py=%)"
	$(AM_V_GEN)sed								\
		-e 's/%VERSION%/$(VERSION)/g'					\
		-e 's/%PACKAGE_SERIES%/$(PACKAGE_SERIES)/g'			\
		-e 's/%BOOK_ID%/$(@:%/conf.py=%)/g'				\
		-e 's/%BOOK_TITLE%/$(subst _, ,$(@:%/conf.py=%))/g'		\
		-e 's#%SRC_DIR%#$(abs_srcdir)#g'				\
		-e 's#%ABS_TOP_SRCDIR%#$(abs_top_srcdir)#g'			\
		-e 's#%CONFIGDIR%#@CONFIGDIR@#g'				\
		-e 's#%CRM_BLACKBOX_DIR%#@CRM_BLACKBOX_DIR@#g'			\
		-e 's#%CRM_CONFIG_DIR%#@CRM_CONFIG_DIR@#g'			\
		-e 's#%CRM_DAEMON_GROUP%#@CRM_DAEMON_GROUP@#g'			\
		-e 's#%CRM_DAEMON_USER%#@CRM_DAEMON_USER@#g'			\
		-e 's#%CRM_LOG_DIR%#@CRM_LOG_DIR@#g'				\
		-e 's#%PCMK_SCHEMA_DIR%#@PCMK_SCHEMA_DIR@#g'			\
		-e 's#%PACEMAKER_CONFIG_DIR%#@PACEMAKER_CONFIG_DIR@#g'		\
		-e 's#%PCMK__GNUTLS_PRIORITIES%#@PCMK__GNUTLS_PRIORITIES@#g'	\
		-e 's#%PCMK__REMOTE_SCHEMA_DIR%#@PCMK__REMOTE_SCHEMA_DIR@#g'	\
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
		"$(RSYNC_PACKAGE_DEST)/doc/"
endif

.PHONY: vars
vars:
	@echo "BOOK_FORMATS='$(BOOK_FORMATS)'"
	@echo "PAPER='$(PAPER)'"
	@echo "SPHINXFLAGS='$(SPHINXFLAGS)'"
	@echo "RSYNC_DEST='$(RSYNC_DEST)'"
	@echo "RSYNC_PACKAGE_DEST='$(RSYNC_PACKAGE_DEST)'"
	@echo "VERSION='$(VERSION)'"
	@echo "PACKAGE_SERIES='$(PACKAGE_SERIES)'"

.PHONY: all-local
all-local:
if BUILD_SPHINX_DOCS
	@for book in $(BOOKS); do					\
		$(MAKE) $(AM_MAKEFLAGS) BOOK=$$book			\
			PAPER="$(PAPER)" SPHINXFLAGS="$(SPHINXFLAGS)"	\
			BOOK_FORMATS="$(BOOK_FORMATS)" $$book/_build;	\
	done
endif

.PHONY: install-data-local
install-data-local: all-local
if BUILD_SPHINX_DOCS
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
endif

.PHONY: uninstall-local
uninstall-local:
if BUILD_SPHINX_DOCS
	$(AM_V_at)for book in $(BOOKS); do		\
		rm -rf "$(DESTDIR)/$(docdir)/$$book";	\
	done
endif

.PHONY: clean-local
clean-local:
	$(AM_V_at)-rm -rf				\
		$(BOOKS:%="$(builddir)/%/_build")	\
		$(BOOKS:%="$(builddir)/%/conf.py")	\
		$(BOOKS:%="$(builddir)/%/generated")
