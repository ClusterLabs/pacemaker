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
BOOKS		?= none

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

# End of useful overrides


EXTRA_DIST	= $(wildcard */*.rst)

BOOK		= none

if BUILD_SPHINX_DOCS
$(BOOKS:%=%/conf.py): conf.py.in
	$(AM_V_GEN)sed							\
		-e 's/%VERSION%/$(VERSION)/g'				\
		-e 's/%BOOK_ID%/$(@:%/conf.py=%)/g'			\
		-e 's/%BOOK_TITLE%/$(subst _, ,$(@:%/conf.py=%))/g'	\
		$(<) > "$@"

$(BOOK)/_build: _static/pacemaker.css $(BOOK)/conf.py $(wildcard $(srcdir)/$(BOOK)/*.rst)
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

all-local:
if BUILD_SPHINX_DOCS
	@for book in $(BOOKS); do					\
		$(MAKE) $(AM_MAKEFLAGS) BOOK=$$book			\
			PAPER="$(PAPER)" SPHINXFLAGS="$(SPHINXFLAGS)"	\
			BOOK_FORMATS="$(BOOK_FORMATS)" $$book/_build;	\
	done
endif

clean-local:
	$(AM_V_at)-rm -rf $(BOOKS:%="$(builddir)/%/_build")
