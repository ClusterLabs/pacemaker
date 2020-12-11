#
# Copyright 2003-2020 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/mk/common.mk

# Deprecated plaintext documents (dynamically converted to HTML)
DEPRECATED_ORIGINAL	= crm_fencing.txt
DEPRECATED_GENERATED	=
if BUILD_ASCIIDOC
DEPRECATED_GENERATED	+= $(DEPRECATED_ORIGINAL:%.txt=%.html)
endif
DEPRECATED_ALL		= $(DEPRECATED_ORIGINAL) $(DEPRECATED_GENERATED)

# Current documentation based on asciidoc, DocBook, and pandoc
BOOKS		=

doc_DATA		= $(DEPRECATED_ALL)
noinst_SCRIPTS		= abi-check

# The sphinx docs are not yet built by default, but we still want to distribute
# them so configure can build the Makefile in a distribution.
DIST_SUBDIRS	= sphinx

EXTRA_DIST	= $(DEPRECATED_ORIGINAL) $(SHARED_TXT)
EXTRA_DIST	+= $(CFS_TXT) $(CFS_XML_ONLY)
EXTRA_DIST	+= $(PA_TXT) $(PA_XML_ONLY)
EXTRA_DIST	+= $(PD_TXT) $(PD_XML_ONLY)
EXTRA_DIST	+= $(PE_TXT) $(PE_XML_ONLY)
EXTRA_DIST	+= $(PR_TXT) $(PR_XML_ONLY)
EXTRA_DIST	+= pcs-crmsh-quick-ref.md

# toplevel rsync destination for www targets (without trailing slash)
RSYNC_DEST      ?= root@www.clusterlabs.org:/var/www/html

# recursive, preserve symlinks/permissions/times, verbose, compress,
# don't cross filesystems, sparse, show progress
RSYNC_OPTS      = -rlptvzxS --progress

LAST_RELEASE	?= Pacemaker-$(VERSION)
TAG		?= $(shell [ -n "`git tag --points-at HEAD | head -1`" ]	\
		           && ( git tag --points-at HEAD | head -1 )		\
			   || git log --pretty=format:%H -n 1 HEAD)

# What formats to build by default: pdf,html,html-single,html-desktop,epub
DOCBOOK_FORMATS := html-desktop

# What languages to build and upload to website by default
# (currently only en-US because translations are out of date)
DOCBOOK_LANGS   := en-US

if IS_ASCIIDOC
ASCIIDOC_HTML_ARGS	= --unsafe --backend=xhtml11
ASCIIDOC_DBOOK_ARGS	= -b docbook -d book
else
ASCIIDOC_HTML_ARGS	= --backend=html5
ASCIIDOC_DBOOK_ARGS	= -b docbook45 -d book
endif

%.html: %.txt
	$(AM_V_GEN)$(ASCIIDOC_CONV) $(ASCIIDOC_HTML_ARGS) --out-file=$@ $< $(PCMK_quiet)

# 
# Generate DocBook XML from asciidoc text.
#
# Build each chapter as a book (since the numbering isn't right for
# articles and only books can have appendices) and then strip out the
# bits we don't want or need.
#
# XXX Sequence of tr/sed commands should be replaced with a single XSLT
#
%.xml:  %.txt
	$(AM_V_at)$(MKDIR_P) $(shell dirname $@)     # might not exist in VPATH build
	$(AM_V_at)$(ASCIIDOC_CONV) $(ASCIIDOC_DBOOK_ARGS) -o - $< | tr -d '\036\r' >$@-t # Convert, fix line endings
	$(AM_V_at)sed -i 's/\ lang="en"//' $@-t      # Never specify a language in the chapters
	$(AM_V_at)sed -i 's/simpara/para/g' $@-t     # publican doesn't correctly render footnotes with simpara
	$(AM_V_at)sed -i 's/.*<date>.*//g' $@-t      # Remove dangling tag
	$(AM_V_at)sed -i 's/.*preface>//g' $@-t      # Remove preface elements
	$(AM_V_at)sed -i 's:<title></title>::g' $@-t # Remove empty title
	$(AM_V_at)sed -i 's/chapter/section/g' $@-t  # Chapters become sections, so that books can become chapters
	$(AM_V_at)sed -i 's/<.*bookinfo.*>//g' $@-t  # Strip out bookinfo, we don't need it
	$(AM_V_at)! grep -q "<appendix" $@-t || sed -i \
	  's/.*book>//;tb;bf;:b;N;s/.*<title>.*<\/title>.*//;tb;/<appendix/{:i;n;/<\/appendix/{p;d};bi};bb;:f;p;d' \
	  $@-t  # We just want the appendix tag (asciidoctor adds non-empty book-level title)
	$(AM_V_at)sed -i 's/book>/chapter>/g' $@-t   # Rename to chapter (won't trigger if previous sed did)
	$(AM_V_GEN)mv $@-t $@

# For Makefile debugging
.PHONY: vars
vars:
	@echo DEPRECATED_ORIGINAL=\'$(DEPRECATED_ORIGINAL)\'
	@echo DEPRECATED_GENERATED=\'$(DEPRECATED_GENERATED)\'
	@echo BOOKS=\'$(BOOKS)\'
	@echo LAST_RELEASE=\'$(LAST_RELEASE)\'
	@echo TAG=\'$(TAG)\'


.PHONY: deprecated-upload
deprecated-upload: $(DEPRECATED_ALL)
	rsync $(RSYNC_OPTS) $(DEPRECATED_ALL) "$(RSYNC_DEST)/$(PACKAGE)/doc/"

.PHONY: deprecated-clean
deprecated-clean:
	-rm -f $(DEPRECATED_GENERATED)

# publican-clusterlabs/xsl/{html,html-single,pdf}.xsl refer to URIs
# requiring Internet access, hence we shadow that with a XML catalog-based
# redirect to local files brought with Publican installation;
# this is what newer Publican normally does with the system-wide catalog
# upon its installation, but let's provide a compatibility for older
# or badly installed instances (via adding the created file into
# XML_CATALOG_FILES for libxml2 backing Publican as a fallback);
# note that nextCatalog arrangement needed so as to overcome
# https://rt.cpan.org/Public/Bug/Display.html?id=113781
publican-catalog-fallback:
	@exec >$@-t \
	&& echo '<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">' \
	&& echo '<rewriteURI uriStartString="https://fedorahosted.org/released/publican/xsl/docbook4/" rewritePrefix="file:///usr/share/publican/xsl/"/>' \
	&& echo '</catalog>'
	$(AM_V_GEN)mv $@-t $@
publican-catalog: publican-catalog-fallback
	@exec >$@-t \
	&& echo '<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">' \
	&& echo '<nextCatalog catalog="file:///etc/xml/catalog"/>' \
	&& echo '<nextCatalog catalog="file://$(CURDIR)/$<"/>' \
	&& echo '</catalog>'
	$(AM_V_GEN)mv $@-t $@

COMMON_XML = Author_Group.xml Book_Info.xml Revision_History.xml

SHARED_TXT=$(wildcard shared/en-US/*.txt)
SHARED_XML=$(SHARED_TXT:%.txt=%.xml)

if PUBLICAN_INTREE_BRAND
PUBLICAN_INTREE_DEPS	= publican-catalog
PUBLICAN_INTREE_ENV	= XML_CATALOG_FILES="$(CURDIR)/publican-catalog"
PUBLICAN_INTREE_OPT	= --brand_dir="$(top_srcdir)/publican-clusterlabs"
else
PUBLICAN_INTREE_DEPS	=
PUBLICAN_INTREE_ENV	=
PUBLICAN_INTREE_OPT	=
endif


# Clusters From Scratch

CFS_SHARED_TXT	= $(addprefix shared/en-US/,pacemaker-intro.txt)
CFS_SHARED_XML	= $(CFS_SHARED_TXT:%.txt=%.xml)
CFS_TXT		= $(wildcard Clusters_from_Scratch/en-US/*.txt)
CFS_XML_GEN	= $(CFS_TXT:%.txt=%.xml)
CFS_XML_ONLY	= $(addprefix $(srcdir)/Clusters_from_Scratch/en-US/,$(COMMON_XML) \
		  Clusters_from_Scratch.ent \
		  Clusters_from_Scratch.xml \
		  Preface.xml)
CFS_DEPS	= $(PNGS) $(CFS_SHARED_XML) $(CFS_XML_ONLY) $(CFS_XML_GEN)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Clusters_from_Scratch.build: $(CFS_DEPS) $(PUBLICAN_INTREE_DEPS)
	@echo "Building $(@:%.build=%) because of $?"
	rm -rf "$(@:%.build=%)/publish"/* "$(@:%.build=%)/tmp"
	$(AM_V_PUB)cd $(@:%.build=%) && RPM_BUILD_DIR="" $(PUBLICAN_INTREE_ENV)	\
	  $(PUBLICAN) build --src_dir="$(srcdir)" --publish 			\
	    --langs="$(DOCBOOK_LANGS)" --formats="$(DOCBOOK_FORMATS)"		\
	    $(PUBLICAN_INTREE_OPT) $(PCMK_quiet)
	rm -rf "$(@:%.build=%)/tmp"
	touch "$@"


# Pacemaker Administration

PA_TXT		= $(wildcard Pacemaker_Administration/en-US/*.txt)
PA_XML_GEN	= $(PA_TXT:%.txt=%.xml)
PA_XML_ONLY	= $(addprefix $(srcdir)/Pacemaker_Administration/en-US/,$(COMMON_XML) \
		  Pacemaker_Administration.ent \
		  Pacemaker_Administration.xml \
		  Preface.xml)
PA_DEPS		= $(PA_XML_ONLY) $(PA_XML_GEN)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Pacemaker_Administration.build: $(PA_DEPS) $(PUBLICAN_INTREE_DEPS)
	@echo Building $(@:%.build=%) because of $?
	rm -rf $(@:%.build=%)/publish/*
	$(AM_V_PUB)cd $(@:%.build=%) && RPM_BUILD_DIR="" $(PUBLICAN_INTREE_ENV)	\
	  $(PUBLICAN) build --src_dir="$(srcdir)" --publish 			\
	    --langs="$(DOCBOOK_LANGS)" --formats="$(DOCBOOK_FORMATS)"		\
	    $(PUBLICAN_INTREE_OPT) $(PCMK_quiet)
	rm -rf $(@:%.build=%)/tmp
	touch "$@"


# Pacemaker Development

PD_TXT		= $(wildcard Pacemaker_Development/en-US/*.txt)
PD_XML_GEN	= $(PD_TXT:%.txt=%.xml)
PD_XML_ONLY	= $(addprefix $(srcdir)/Pacemaker_Development/en-US/,$(COMMON_XML) \
		  Pacemaker_Development.ent \
		  Pacemaker_Development.xml)
PD_DEPS		= $(PD_XML_ONLY) $(PD_XML_GEN)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Pacemaker_Development.build: $(PD_DEPS) $(PUBLICAN_INTREE_DEPS)
	@echo Building $(@:%.build=%) because of $?
	rm -rf $(@:%.build=%)/publish/* $(@:%.build=%)/tmp
	$(AM_V_PUB)cd $(@:%.build=%) && RPM_BUILD_DIR="" $(PUBLICAN_INTREE_ENV)	\
	  $(PUBLICAN) build --src_dir="$(srcdir)" --publish 			\
	    --langs="$(DOCBOOK_LANGS)" --formats="$(DOCBOOK_FORMATS)"		\
	    $(PUBLICAN_INTREE_OPT) $(PCMK_quiet)
	rm -rf $(@:%.build=%)/tmp
	touch "$@"


# Pacemaker Explained

PE_SHARED_TXT	= $(addprefix shared/en-US/,pacemaker-intro.txt)
PE_SHARED_XML	= $(PE_SHARED_TXT:%.txt=%.xml)
PE_TXT		= $(wildcard Pacemaker_Explained/en-US/*.txt)
PE_XML_GEN	= $(PE_TXT:%.txt=%.xml)
PE_XML_ONLY	= $(addprefix $(srcdir)/Pacemaker_Explained/en-US/,$(COMMON_XML) \
		  Pacemaker_Explained.ent \
		  Pacemaker_Explained.xml \
		  Preface.xml)
PE_DEPS		= $(PNGS) $(PE_SHARED_XML) $(PE_XML_ONLY) $(PE_XML_GEN)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Pacemaker_Explained.build: $(PE_DEPS) $(PUBLICAN_INTREE_DEPS)
	@echo Building $(@:%.build=%) because of $?
	rm -rf $(@:%.build=%)/publish/* $(@:%.build=%)/tmp
	$(AM_V_PUB)cd $(@:%.build=%) && RPM_BUILD_DIR="" $(PUBLICAN_INTREE_ENV)	\
	  $(PUBLICAN) build --src_dir="$(srcdir)" --publish 			\
	    --langs="$(DOCBOOK_LANGS)" --formats="$(DOCBOOK_FORMATS)"		\
	    $(PUBLICAN_INTREE_OPT) $(PCMK_quiet)
	rm -rf $(@:%.build=%)/tmp
	touch "$@"


# Pacemaker Remote

PR_TXT		= $(wildcard Pacemaker_Remote/en-US/*.txt)
PR_XML_GEN	= $(PR_TXT:%.txt=%.xml)
PR_XML_ONLY	= $(addprefix $(srcdir)/Pacemaker_Remote/en-US/,$(COMMON_XML) \
		  Pacemaker_Remote.ent \
		  Pacemaker_Remote.xml)
PR_DEPS		= $(PNGS) $(PR_XML_ONLY) $(PR_XML_GEN)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Pacemaker_Remote.build: $(PR_DEPS) $(PUBLICAN_INTREE_DEPS)
	@echo Building $(@:%.build=%) because of $?
	rm -rf $(@:%.build=%)/publish/* $(@:%.build=%)/tmp
	$(AM_V_PUB)cd $(@:%.build=%) && RPM_BUILD_DIR="" $(PUBLICAN_INTREE_ENV)	\
	  $(PUBLICAN) build --src_dir="$(srcdir)" --publish 			\
	    --langs="$(DOCBOOK_LANGS)" --formats="$(DOCBOOK_FORMATS)"		\
	    $(PUBLICAN_INTREE_OPT) $(PCMK_quiet)
	rm -rf $(@:%.build=%)/tmp
	touch "$@"


# Build all books for upload to ClusterLabs
.PHONY: books
books: books-clean
if BUILD_DOCBOOK
	for book in $(BOOKS); do 							\
		sed -i.sed 's@^brand:.*@brand: clusterlabs@' $$book/publican.cfg;	\
	done
	$(MAKE) $(AM_MAKEFLAGS) DOCBOOK_FORMATS="pdf,html,html-single,epub"		\
		DOCBOOK_LANGS="$(DOCBOOK_LANGS)" all-local
endif

.PHONY: books-upload
books-upload: books
if BUILD_DOCBOOK
	@echo Uploading current $(PACKAGE_SERIES) documentation set to clusterlabs.org
	@for book in $(BOOKS); do 									\
		echo Uploading $$book...;								\
		echo "Generated on `date` from version: $(shell git log --pretty="format:%h %d" -n 1)"	\
			>> $$book/publish/build-$(PACKAGE_SERIES).txt;					\
		rsync $(RSYNC_OPTS) $$book/publish/* "$(RSYNC_DEST)/$(PACKAGE)/doc/";			\
	done
endif

.PHONY: books-clean
books-clean:
	-for book in $(BOOKS); do			\
		rm -rf $$book/tmp $$book/publish;	\
	done
	-rm -f  $(PNGS_GENERATED)		\
		$(SHARED_XML)			\
		$(CFS_XML_GEN)			\
		$(PA_XML_GEN)			\
		$(PD_XML_GEN)			\
		$(PE_XML_GEN)			\
		$(PR_XML_GEN)			\
		publican-catalog-fallback	\
		publican-catalog


if BUILD_DOCBOOK
all-local: $(BOOKS:%=%.build) */publican.cfg

install-data-local: all-local
	for book in $(BOOKS); do 							\
	    filelist=`find $$book/publish/* -print`;					\
	    for f in $$filelist; do							\
		p=`echo $$f | sed s:publish/:: | sed s:Pacemaker/::`;			\
		if [ -d $$f ]; then							\
			$(INSTALL) -d -m 775 $(DESTDIR)$(docdir)/$$p;			\
		else									\
			$(INSTALL) -m 644 $$f $(DESTDIR)$(docdir)/$$p;			\
		fi									\
	    done;									\
	done
endif

BRAND_DEPS =	$(wildcard publican-clusterlabs/en-US/*.png)	\
		$(wildcard publican-clusterlabs/en-US/*.xml)

brand-build: $(BRAND_DEPS)
	cd publican-clusterlabs && publican build --formats=xml --langs=all --publish

brand: brand-build
	@echo "Installing branded content..."
	cd publican-clusterlabs && sudo publican install_brand --path=$(datadir)/publican/Common_Content

brand-rpm-clean:
	-find publican-clusterlabs -name "*.noarch.rpm" -exec rm -f \{\} \;

brand-rpm-build: brand-rpm-clean brand-build
	cd publican-clusterlabs && \
		$(PUBLICAN) --src_dir="$(srcdir)" package --binary

brand-rpm-install: brand-rpm-build
	find publican-clusterlabs -name "*.noarch.rpm" -exec sudo rpm -Uvh --force \{\} \;

pdf:
	$(MAKE) $(AM_MAKEFLAGS) DOCBOOK_FORMATS="pdf" all-local


# Annotated source code as HTML

global:
	$(MAKE) $(AM_MAKEFLAGS) -C .. clean-generic
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


# All HTML documentation (except ABI compatibility, which is run separately)
.PHONY: www
www: clean-local deprecated-upload manhtml-upload global-upload doxygen-upload books-upload


clean-local: brand-rpm-clean global-clean manhtml-clean doxygen-clean abi-clean books-clean deprecated-clean
