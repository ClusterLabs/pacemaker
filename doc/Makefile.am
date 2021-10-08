#
# Copyright 2003-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/mk/common.mk

# Define release-related variables
include $(top_srcdir)/mk/release.mk

# What formats to use for book uploads (i.e. "make www";
# use BOOK_FORMATS in sphinx subdirectory to change local builds)
BOOK_FORMATS		?= html singlehtml pdf epub

# Deprecated plaintext documents (dynamically converted to HTML)
DEPRECATED_ORIGINAL	= crm_fencing.txt
DEPRECATED_GENERATED	=
if BUILD_ASCIIDOC
DEPRECATED_GENERATED	+= $(DEPRECATED_ORIGINAL:%.txt=%.html)
endif
DEPRECATED_ALL		= $(DEPRECATED_ORIGINAL) $(DEPRECATED_GENERATED)

doc_DATA		= $(DEPRECATED_ALL)
noinst_SCRIPTS		= abi-check

SUBDIRS		= sphinx

EXTRA_DIST	= $(DEPRECATED_ORIGINAL)

# toplevel rsync destination for www targets (without trailing slash)
RSYNC_DEST      ?= root@www.clusterlabs.org:/var/www/html

# recursive, preserve symlinks/permissions/times, verbose, compress,
# don't cross filesystems, sparse, show progress
RSYNC_OPTS      = -rlptvzxS --progress

if IS_ASCIIDOC
ASCIIDOC_HTML_ARGS	= --unsafe --backend=xhtml11
ASCIIDOC_DBOOK_ARGS	= -b docbook -d book
else
ASCIIDOC_HTML_ARGS	= --backend=html5
ASCIIDOC_DBOOK_ARGS	= -b docbook45 -d book
endif

%.html: %.txt
	$(AM_V_GEN)$(ASCIIDOC_CONV) $(ASCIIDOC_HTML_ARGS) --out-file=$@ $< $(PCMK_quiet)

# For Makefile debugging
.PHONY: vars
vars:
	@echo DEPRECATED_ORIGINAL=\'$(DEPRECATED_ORIGINAL)\'
	@echo DEPRECATED_GENERATED=\'$(DEPRECATED_GENERATED)\'
	@echo LAST_RELEASE=\'$(LAST_RELEASE)\'
	@echo TAG=\'$(TAG)\'


.PHONY: deprecated-upload
deprecated-upload: $(DEPRECATED_ALL)
	rsync $(RSYNC_OPTS) $(DEPRECATED_ALL) "$(RSYNC_DEST)/$(PACKAGE)/doc/"

.PHONY: deprecated-clean
deprecated-clean:
	-rm -f $(DEPRECATED_GENERATED)


# Annotated source code as HTML

# Cleaning first ensures we don't index unrelated stuff like RPM sources
global:
	$(MAKE) $(AM_MAKEFLAGS) -C .. clean-generic
	$(MAKE) $(AM_MAKEFLAGS) -C ../rpm rpm-clean
	cd .. && gtags -q && htags -sanhIT doc

global-upload: global
	rsync $(RSYNC_OPTS) HTML/ "$(RSYNC_DEST)/$(PACKAGE)/global/$(TAG)/"

global-clean:
	-rm -rf HTML


# Man pages as HTML

%.8.html: %.8
	groff -mandoc `man -w ./$<` -T html > $@

%.7.html: %.7
	groff -mandoc `man -w ./$<` -T html > $@

manhtml:
	$(MAKE) $(AM_MAKEFLAGS) -C .. all
	find .. -name "[a-z]*.[78]" -exec $(MAKE) $(AM_MAKEFLAGS) \{\}.html \;

manhtml-upload: manhtml
	find .. -name "[a-z]*.[78].html" -exec \
		rsync $(RSYNC_OPTS) \{\} "$(RSYNC_DEST)/$(PACKAGE)/man/" \;

manhtml-clean:
	-find .. -name "[a-z]*.[78].html" -exec rm \{\} \;


# API documentation as HTML

doxygen: Doxyfile
	doxygen Doxyfile

doxygen-upload: doxygen
	rsync $(RSYNC_OPTS) api/html/ "$(RSYNC_DEST)/$(PACKAGE)/doxygen/$(TAG)/"

doxygen-clean:
	-rm -rf api


# ABI compatibility report as HTML

abi: abi-check
	./abi-check $(PACKAGE) $(LAST_RELEASE) $(TAG)

abi-www:
	export RSYNC_DEST=$(RSYNC_DEST); ./abi-check -u $(PACKAGE) $(LAST_RELEASE) $(TAG)

abi-clean:
	-rm -rf abi_dumps compat_reports


# The main documentation books (which are actually in the sphinx subdirectory)
books-upload:
	$(MAKE) $(AM_MAKEFLAGS)	-C sphinx clean
	$(MAKE) $(AM_MAKEFLAGS)	-C sphinx	\
		RSYNC_DEST="$(RSYNC_DEST)"	\
		BOOK_FORMATS="$(BOOK_FORMATS)"	\
		books-upload


# All online documentation (except ABI compatibility, which is run separately)
.PHONY: www
www: clean-local deprecated-upload manhtml-upload global-upload doxygen-upload books-upload

clean-local: global-clean manhtml-clean doxygen-clean abi-clean deprecated-clean

# "make check" will cause "make all" to be run, which means docs will get built
# as a part of running tests if they haven't already.  That seems unnecessary, so
# override the default check-recursive rule with this one that just returns.  If
# we ever need to add tests to this directory, this rule will have to come out.
check-recursive:
	@true
