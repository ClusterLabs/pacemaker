#
# Copyright 2003-2019 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
include $(top_srcdir)/Makefile.common

helpdir		= $(datadir)/$(PACKAGE)

ascii		= crm_fencing.txt acls.txt
docbook		=	Clusters_from_Scratch		\
			Pacemaker_Administration	\
			Pacemaker_Development		\
			Pacemaker_Explained		\
			Pacemaker_Remote
doc_DATA	= $(ascii) $(generated_docs)

# toplevel rsync destination for www targets (without trailing slash)
RSYNC_DEST      ?= root@www.clusterlabs.org:/var/www/html

# recursive, preserve symlinks/permissions/times, verbose, compress,
# don't cross filesystems, sparse, show progress
RSYNC_OPTS      = -rlptvzxS --progress

LAST_RELEASE	?= Pacemaker-$(VERSION)
TAG		?= $(shell git log --pretty=format:%H -n 1 HEAD)

publican_docs   =
generated_docs	=
generated_mans	=

# What formats to build: pdf,html,html-single,html-desktop,epub
DOCBOOK_FORMATS := html-desktop

# What languages to build
DOCBOOK_LANGS   := en-US

# What languages to build for uploading to website
# (currently only en-US because translations aren't up-to-date)
UPLOAD_LANGS    = en-US

noinst_SCRIPTS	= abi-check

# @TODO We could simplify this (and .gitignore) by establishing a convention
# that original image source begins with an uppercase letter and generated
# files with lowercase.

# Scheduler transition graphs
# @TODO Add original XML, and generate DOTs via crm_simulate
DOTS = $(wildcard shared/en-US/images/*.dot)

# Vector sources for images
# @TODO Generate transition SVGs from DOTs via dot
SVGS =	$(wildcard shared/en-US/images/pcmk-*.svg)	\
	$(DOTS:%.dot=%.svg)

# Final images
PNGS_ORIGINAL =	Pacemaker_Remote/en-US/images/pcmk-ha-cluster-stack.png	\
		Pacemaker_Remote/en-US/images/pcmk-ha-remote-stack.png	\
		shared/en-US/images/Console.png				\
		shared/en-US/images/Editing-eth0.png			\
		shared/en-US/images/Installer.png			\
		shared/en-US/images/Network.png				\
		shared/en-US/images/Partitioning.png			\
		shared/en-US/images/Welcome.png				\
		shared/en-US/images/resource-set.png			\
		shared/en-US/images/three-sets.png			\
		shared/en-US/images/two-sets.png
PNGS_GENERATED =	$(SVGS:%.svg=%-small.png)	\
			$(SVGS:%.svg=%.png)		\
			$(SVGS:%.svg=%-large.png)
PNGS = $(PNGS_ORIGINAL) $(PNGS_GENERATED)

graphics: $(PNGS)

%.png: %.svg
	$(AM_V_GEN)$(INKSCAPE) --file=$< --export-dpi=90 -C --export-png=$@ $(PCMK_quiet)

%-small.png: %.svg
	$(AM_V_GEN)$(INKSCAPE) --file=$< --export-dpi=45 -C --export-png=$@ $(PCMK_quiet)

%-large.png: %.svg
	$(AM_V_GEN)$(INKSCAPE) --file=$< --export-dpi=180 -C --export-png=$@ $(PCMK_quiet)

if BUILD_ASCIIDOC
generated_docs	+= $(ascii:%.txt=%.html)

if BUILD_DOCBOOK
publican_docs	+= $(docbook)
endif
endif

EXTRA_DIST	= $(ascii) $(SHARED_TXT) $(PNGS_ORIGINAL) $(DOTS) $(SVGS)
EXTRA_DIST	+= $(CFS_TXT) $(CFS_XML_ONLY)
EXTRA_DIST	+= $(PA_TXT) $(PA_XML_ONLY)
EXTRA_DIST	+= $(PD_TXT) $(PD_XML_ONLY)
EXTRA_DIST	+= $(PE_TXT) $(PE_XML_ONLY)
EXTRA_DIST	+= $(PR_TXT) $(PR_XML_ONLY)
EXTRA_DIST	+= pcs-crmsh-quick-ref.md

if IS_ASCIIDOC
ASCIIDOC_HTML_ARGS	= --unsafe --backend=xhtml11
else
ASCIIDOC_HTML_ARGS	= --backend=html5
endif

%.html: %.txt
	$(AM_V_GEN)$(ASCIIDOC_CONV) $(ASCIIDOC_HTML_ARGS) --out-file=$@ $< $(PCMK_quiet)

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


CFS_SHARED_TXT=$(addprefix shared/en-US/,pacemaker-intro.txt)
CFS_SHARED_XML=$(CFS_SHARED_TXT:%.txt=%.xml)
CFS_TXT=$(wildcard Clusters_from_Scratch/en-US/*.txt)
CFS_XML=$(CFS_TXT:%.txt=%.xml)
CFS_XML_ONLY=$(addprefix Clusters_from_Scratch/en-US/,$(COMMON_XML) \
  Clusters_from_Scratch.ent Clusters_from_Scratch.xml Preface.xml)

$(CFS_XML): $(CFS_SHARED_XML)

PUBLICAN_INTREE_DEPS =
if PUBLICAN_INTREE_BRAND
PUBLICAN_INTREE_DEPS += publican-catalog
endif

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Clusters_from_Scratch.build: $(PNGS) $(CFS_XML_ONLY) $(CFS_XML) $(CFS_SHARED_XML) $(PUBLICAN_INTREE_DEPS)
	@echo Building $(@:%.build=%) because of $?
	rm -rf $(@:%.build=%)/publish/* $(@:%.build=%)/tmp
if PUBLICAN_INTREE_BRAND
	$(AM_V_PUB)cd $(@:%.build=%) \
	&& RPM_BUILD_DIR="" XML_CATALOG_FILES="$(CURDIR)/publican-catalog" \
	   $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS) --brand_dir=../publican-clusterlabs \
	   $(PCMK_quiet)
else
	$(AM_V_PUB)cd $(@:%.build=%) \
	&& RPM_BUILD_DIR="" \
	   $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS) \
	   $(PCMK_quiet)
endif
	rm -rf $(@:%.build=%)/tmp
	touch $@


PA_TXT=$(wildcard Pacemaker_Administration/en-US/*.txt)
PA_XML=$(PA_TXT:%.txt=%.xml)
PA_XML_ONLY=$(addprefix Pacemaker_Administration/en-US/,$(COMMON_XML) \
  Pacemaker_Administration.ent Pacemaker_Administration.xml Preface.xml)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Pacemaker_Administration.build: $(PA_XML_ONLY) $(PA_XML) $(PUBLICAN_INTREE_DEPS)
	@echo Building $(@:%.build=%) because of $?
	rm -rf $(@:%.build=%)/publish/*
if PUBLICAN_INTREE_BRAND
	$(AM_V_PUB)cd $(@:%.build=%) \
	&& RPM_BUILD_DIR="" XML_CATALOG_FILES="$(CURDIR)/publican-catalog" \
	   $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS) --brand_dir=../publican-clusterlabs \
	   $(PCMK_quiet)
else
	$(AM_V_PUB)cd $(@:%.build=%) \
	&& RPM_BUILD_DIR="" \
	   $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS) \
	   $(PCMK_quiet)
endif
	rm -rf $(@:%.build=%)/tmp
	touch $@


PD_TXT=$(wildcard Pacemaker_Development/en-US/*.txt)
PD_XML=$(PD_TXT:%.txt=%.xml)
PD_XML_ONLY=$(addprefix Pacemaker_Development/en-US/,$(COMMON_XML) \
  Pacemaker_Development.ent Pacemaker_Development.xml)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Pacemaker_Development.build: $(PD_XML_ONLY) $(PD_XML) $(PUBLICAN_INTREE_DEPS)
	@echo Building $(@:%.build=%) because of $?
	rm -rf $(@:%.build=%)/publish/* $(@:%.build=%)/tmp
if PUBLICAN_INTREE_BRAND
	$(AM_V_PUB)cd $(@:%.build=%) \
	&& RPM_BUILD_DIR="" XML_CATALOG_FILES="$(CURDIR)/publican-catalog" \
	   $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS) --brand_dir=../publican-clusterlabs \
	   $(PCMK_quiet)
else
	$(AM_V_PUB)cd $(@:%.build=%) \
	&& RPM_BUILD_DIR="" \
	   $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS) \
	   $(PCMK_quiet)
endif
	rm -rf $(@:%.build=%)/tmp
	touch $@


PE_SHARED_TXT=$(addprefix shared/en-US/,pacemaker-intro.txt)
PE_SHARED_XML=$(PE_SHARED_TXT:%.txt=%.xml)
PE_TXT=$(wildcard Pacemaker_Explained/en-US/*.txt)
PE_XML=$(PE_TXT:%.txt=%.xml)
PE_XML_ONLY=$(addprefix Pacemaker_Explained/en-US/,$(COMMON_XML) \
  Pacemaker_Explained.ent Pacemaker_Explained.xml Preface.xml)

$(PE_XML): $(PE_SHARED_XML)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Pacemaker_Explained.build: $(PNGS) $(PE_XML_ONLY) $(PE_XML) $(PE_SHARED_XML) $(PUBLICAN_INTREE_DEPS)
	@echo Building $(@:%.build=%) because of $?
	rm -rf $(@:%.build=%)/publish/* $(@:%.build=%)/tmp
if PUBLICAN_INTREE_BRAND
	$(AM_V_PUB)cd $(@:%.build=%) \
	&& RPM_BUILD_DIR="" XML_CATALOG_FILES="$(CURDIR)/publican-catalog" \
	   $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS) --brand_dir=../publican-clusterlabs \
	   $(PCMK_quiet)
else
	$(AM_V_PUB)cd $(@:%.build=%) \
	&& RPM_BUILD_DIR="" \
	   $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS) \
	   $(PCMK_quiet)
endif
	rm -rf $(@:%.build=%)/tmp
	touch $@


PR_TXT=$(wildcard Pacemaker_Remote/en-US/*.txt)
PR_XML=$(PR_TXT:%.txt=%.xml)
PR_XML_ONLY=$(addprefix Pacemaker_Remote/en-US/,$(COMMON_XML) \
  Pacemaker_Remote.ent Pacemaker_Remote.xml)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Pacemaker_Remote.build: $(PNGS) $(PR_XML_ONLY) $(PR_XML) $(PUBLICAN_INTREE_DEPS)
	@echo Building $(@:%.build=%) because of $?
	rm -rf $(@:%.build=%)/publish/* $(@:%.build=%)/tmp
if PUBLICAN_INTREE_BRAND
	$(AM_V_PUB)cd $(@:%.build=%) \
	&& RPM_BUILD_DIR="" XML_CATALOG_FILES="$(CURDIR)/publican-catalog" \
	   $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS) --brand_dir=../publican-clusterlabs \
	   $(PCMK_quiet)
else
	$(AM_V_PUB)cd $(@:%.build=%) \
	&& RPM_BUILD_DIR="" \
	   $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS) \
	   $(PCMK_quiet)
endif
	rm -rf $(@:%.build=%)/tmp
	touch $@

# Update the translation template
pot:
	for book in $(docbook); do 				      \
		echo "Updating translation templates in: $$book";     \
		( cd $$book && RPM_BUILD_DIR="" $(PUBLICAN) update_pot ); \
	done

# Update the actual translations
po: pot
	for book in $(docbook); do 				      \
		echo "Updating translations in: $$book";     \
		( cd $$book && RPM_BUILD_DIR="" $(PUBLICAN) update_po --langs=all );\
	done

if BUILD_DOCBOOK
docbook_build = $(docbook:%=%.build)

all-local: $(docbook_build) */publican.cfg

install-data-local: all-local
	for book in $(docbook); do 							\
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
	echo "Installing..."
	cd publican-clusterlabs && sudo publican install_brand --path=$(datadir)/publican/Common_Content

brand-rpm-clean:
	find publican-clusterlabs -name "*.noarch.rpm" -exec rm -f \{\} \;

brand-rpm-build: brand-rpm-clean brand-build
	cd publican-clusterlabs && $(PUBLICAN) package --binary

brand-rpm-install: brand-rpm-build
	find publican-clusterlabs -name "*.noarch.rpm" -exec sudo rpm -Uvh --force \{\} \;

pdf:
	$(MAKE) DOCBOOK_FORMATS="pdf" all-local


# Annotated source code as HTML

global:
	$(MAKE) -C .. clean-generic
	cd .. && gtags -q && htags -sanhIT doc

global-upload: global
	rsync $(RSYNC_OPTS) HTML/ "$(RSYNC_DEST)/$(PACKAGE)/global/$(TAG)/"


# Man pages as HTML

%.8.html: %.8
	groff -mandoc `man -w ./$<` -T html > $@

%.7.html: %.7
	groff -mandoc `man -w ./$<` -T html > $@

manhtml:
	$(MAKE) -C .. all
	find .. -name "[a-z]*.[78]" -exec $(MAKE) \{\}.html \;

manhtml-upload: manhtml
	find .. -name "[a-z]*.[78].html" -exec \
		rsync $(RSYNC_OPTS) \{\} "$(RSYNC_DEST)/$(PACKAGE)/man/" \;


# API documentation as HTML

doxygen: Doxyfile
	doxygen Doxyfile

doxygen-upload: doxygen
	rsync $(RSYNC_OPTS) api/html/ "$(RSYNC_DEST)/$(PACKAGE)/doxygen/$(TAG)/"


# ABI compatibility report as HTML

abi: abi-check
	./abi-check $(PACKAGE) $(LAST_RELEASE) $(TAG)

abi-www:
	export RSYNC_DEST=$(RSYNC_DEST); ./abi-check -u $(PACKAGE) $(LAST_RELEASE) $(TAG)


# All HTML documentation (except ABI compatibility, which is run separately)

www: clean-local $(generated_docs) $(ascii) manhtml-upload global-upload doxygen-upload
	for book in $(docbook); do 							\
		sed -i.sed 's@^brand:.*@brand: clusterlabs@' $$book/publican.cfg;	\
	done
	$(MAKE) DOCBOOK_FORMATS="pdf,html,html-single,epub" DOCBOOK_LANGS="$(UPLOAD_LANGS)" all-local
	echo Uploading current $(PACKAGE_SERIES) documentation set to clusterlabs.org
if BUILD_DOCBOOK
	for book in $(docbook); do 									\
		echo Uploading $$book...;								\
		echo "Generated on `date` from version: $(shell git log --pretty="format:%h %d" -n 1)" >> $$book/publish/build-$(PACKAGE_SERIES).txt;	\
		rsync $(RSYNC_OPTS) $$book/publish/* "$(RSYNC_DEST)/$(PACKAGE)/doc/";			\
	done
endif
	rsync $(RSYNC_OPTS) $(generated_docs) $(ascii) "$(RSYNC_DEST)/$(PACKAGE)/doc/"


clean-local:
	-rm -f $(PNGS_GENERATED)
	-rm -rf $(generated_docs) $(generated_mans) $(docbook_build)
	-rm -rf $(SHARED_XML) $(CFS_XML) $(PE_XML) $(PR_XML)
	-rm -rf  publican-catalog-fallback publican-catalog
	for book in $(docbook); do rm -rf $$book/tmp $$book/publish; done
