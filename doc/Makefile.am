#
# doc: Pacemaker code
#
# Copyright (C) 2008 Andrew Beekhof
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
include $(top_srcdir)/Makefile.common

# Deprecated plaintext documents (also dynamically converted to HTML)
ascii		= acls.txt			\
		  crm_fencing.txt
generated_docs	=
if BUILD_ASCIIDOC
generated_docs	+= $(ascii:%.txt=%.html)
endif

# Current Publican/docbook-based documentation
docbook		= Clusters_from_Scratch		\
		  Pacemaker_Development		\
		  Pacemaker_Explained		\
		  Pacemaker_Remote
docbook_build = $(docbook:%=%.build)

doc_DATA		= $(ascii) $(generated_docs)

EXTRA_DIST	= $(ascii) $(SHARED_TXT) $(PNGS_ORIGINAL) $(DOTS) $(SVGS)
EXTRA_DIST	+= $(CFS_TXT) $(CFS_XML_ONLY)
EXTRA_DIST	+= $(PD_TXT) $(PD_XML_ONLY)
EXTRA_DIST	+= $(PE_TXT) $(PE_XML_ONLY)
EXTRA_DIST	+= $(PR_TXT) $(PR_XML_ONLY)
EXTRA_DIST	+= pcs-crmsh-quick-ref.md

# toplevel rsync destination for www targets (without trailing slash)
RSYNC_DEST      ?= root@www.clusterlabs.org:/var/www/html

# recursive, preserve symlinks/permissions/times, verbose, compress,
# don't cross filesystems, sparse, show progress
RSYNC_OPTS      = -rlptvzxS --progress

# What formats to build by default: pdf,html,html-single,html-desktop,epub
DOCBOOK_FORMATS := html-desktop

# What languages to build and upload to website by default
# (currently only en-US because translations are out of date)
DOCBOOK_LANGS   := en-US

# @TODO We could simplify this (and .gitignore) by establishing a convention
# that original image source begins with an uppercase letter and generated
# files with lowercase.

# Scheduler transition graphs
# @TODO Add original XML, and generate DOTs via crm_simulate
DOTS	= $(wildcard Clusters_from_Scratch/en-US/images/*.dot)	\
	  $(wildcard Pacemaker_Explained/en-US/images/*.dot)

# Vector sources for images
# @TODO Generate transition SVGs from DOTs via dot
SVGS =	$(wildcard Clusters_from_Scratch/en-US/images/pcmk-*.svg)	\
	$(wildcard Pacemaker_Explained/en-US/images/pcmk-*.svg)	\
	$(DOTS:%.dot=%.svg)

# Final images (some originally in PNG, others generated from SVG)
PNGS_ORIGINAL =	Pacemaker_Remote/en-US/images/pcmk-ha-cluster-stack.png	\
		Pacemaker_Remote/en-US/images/pcmk-ha-remote-stack.png	\
		Clusters_from_Scratch/en-US/images/Console.png		\
		Clusters_from_Scratch/en-US/images/Editing-eth0.png	\
		Clusters_from_Scratch/en-US/images/Installer.png	\
		Clusters_from_Scratch/en-US/images/Network.png		\
		Clusters_from_Scratch/en-US/images/Partitioning.png	\
		Clusters_from_Scratch/en-US/images/Welcome.png		\
		Pacemaker_Explained/en-US/images/resource-set.png	\
		Pacemaker_Explained/en-US/images/three-sets-complex.png	\
		Pacemaker_Explained/en-US/images/three-sets.png		\
		Pacemaker_Explained/en-US/images/two-sets.png
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

if PUBLICAN_INTREE_BRAND
PUBLICAN_INTREE_DEPS	= publican-catalog
PUBLICAN_INTREE_ENV	= XML_CATALOG_FILES="$(CURDIR)/publican-catalog"
PUBLICAN_INTREE_OPT	= --brand_dir=../publican-clusterlabs 
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
CFS_XML_ONLY	= $(addprefix Clusters_from_Scratch/en-US/,$(COMMON_XML) \
		  Clusters_from_Scratch.ent \
		  Clusters_from_Scratch.xml \
		  Preface.xml)
CFS_DEPS	= $(PNGS) $(CFS_SHARED_XML) $(CFS_XML_ONLY) $(CFS_XML_GEN)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Clusters_from_Scratch.build: $(CFS_DEPS) $(PUBLICAN_INTREE_DEPS)
	@echo Building $(@:%.build=%) because of $?
	rm -rf $(@:%.build=%)/publish/* $(@:%.build=%)/tmp
	$(AM_V_PUB)cd $(@:%.build=%) && RPM_BUILD_DIR="" $(PUBLICAN_INTREE_ENV)	\
	  $(PUBLICAN) build --publish --langs="$(DOCBOOK_LANGS)"		\
	    --formats="$(DOCBOOK_FORMATS)" $(PUBLICAN_INTREE_OPT) $(PCMK_quiet)
	rm -rf $(@:%.build=%)/tmp
	touch $@


# Pacemaker Development

PD_TXT		= $(wildcard Pacemaker_Development/en-US/*.txt)
PD_XML_GEN	= $(PD_TXT:%.txt=%.xml)
PD_XML_ONLY	= $(addprefix Pacemaker_Development/en-US/,$(COMMON_XML) \
		  Pacemaker_Development.ent \
		  Pacemaker_Development.xml)
PD_DEPS		= $(PD_XML_ONLY) $(PD_XML_GEN)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Pacemaker_Development.build: $(PD_DEPS) $(PUBLICAN_INTREE_DEPS)
	@echo Building $(@:%.build=%) because of $?
	rm -rf $(@:%.build=%)/publish/* $(@:%.build=%)/tmp
	$(AM_V_PUB)cd $(@:%.build=%) && RPM_BUILD_DIR="" $(PUBLICAN_INTREE_ENV)	\
	  $(PUBLICAN) build --publish --langs="$(DOCBOOK_LANGS)"		\
	    --formats="$(DOCBOOK_FORMATS)" $(PUBLICAN_INTREE_OPT) $(PCMK_quiet)
	rm -rf $(@:%.build=%)/tmp
	touch $@


# Pacemaker Explained

PE_SHARED_TXT	= $(addprefix shared/en-US/,pacemaker-intro.txt)
PE_SHARED_XML	= $(PE_SHARED_TXT:%.txt=%.xml)
PE_TXT		= $(wildcard Pacemaker_Explained/en-US/*.txt)
PE_XML_GEN	= $(PE_TXT:%.txt=%.xml)
PE_XML_ONLY	= $(addprefix Pacemaker_Explained/en-US/,$(COMMON_XML) \
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
	  $(PUBLICAN) build --publish --langs="$(DOCBOOK_LANGS)"		\
	    --formats="$(DOCBOOK_FORMATS)" $(PUBLICAN_INTREE_OPT) $(PCMK_quiet)
	rm -rf $(@:%.build=%)/tmp
	touch $@


# Pacemaker Remote

PR_TXT		= $(wildcard Pacemaker_Remote/en-US/*.txt)
PR_XML_GEN	= $(PR_TXT:%.txt=%.xml)
PR_XML_ONLY	= $(addprefix Pacemaker_Remote/en-US/,$(COMMON_XML) \
		  Pacemaker_Remote.ent \
		  Pacemaker_Remote.xml)
PR_DEPS		= $(PR_XML_ONLY) $(PR_XML_GEN)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Pacemaker_Remote.build: $(PNGS) $(PR_DEPS) $(PUBLICAN_INTREE_DEPS)
	@echo Building $(@:%.build=%) because of $?
	rm -rf $(@:%.build=%)/publish/* $(@:%.build=%)/tmp
	$(AM_V_PUB)cd $(@:%.build=%) && RPM_BUILD_DIR="" $(PUBLICAN_INTREE_ENV)	\
	  $(PUBLICAN) build --publish --langs="$(DOCBOOK_LANGS)"		\
	    --formats="$(DOCBOOK_FORMATS)" $(PUBLICAN_INTREE_OPT) $(PCMK_quiet)
	rm -rf $(@:%.build=%)/tmp
	touch $@


# Update the translation template
pot:
	@for book in $(docbook); do 				      \
		echo "Updating translation templates in: $$book";     \
		( cd $$book && RPM_BUILD_DIR="" $(PUBLICAN) update_pot ); \
	done

# Update the actual translations
po: pot
	@for book in $(docbook); do 				      \
		echo "Updating translations in: $$book";     \
		( cd $$book && RPM_BUILD_DIR="" $(PUBLICAN) update_po --langs=all );\
	done

if BUILD_DOCBOOK
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
	@echo "Installing branded content..."
	cd publican-clusterlabs && sudo publican install_brand --path=$(datadir)/publican/Common_Content

brand-rpm-clean:
	find publican-clusterlabs -name "*.noarch.rpm" -exec rm -f \{\} \;

brand-rpm-build: brand-rpm-clean brand-build
	cd publican-clusterlabs && $(PUBLICAN) package --binary

brand-rpm-install: brand-rpm-build
	find publican-clusterlabs -name "*.noarch.rpm" -exec sudo rpm -Uvh --force \{\} \;

pdf:
	make DOCBOOK_FORMATS="pdf" all-local

www: clean-local $(doc_DATA)
if BUILD_DOCBOOK
	for book in $(docbook); do 							\
		sed -i.sed 's@^brand:.*@brand: clusterlabs@' $$book/publican.cfg;	\
	done
endif
	$(MAKE) DOCBOOK_FORMATS="pdf,html,html-single,epub" DOCBOOK_LANGS="$(DOCBOOK_LANGS)" all-local
	@echo Uploading current $(PACKAGE_SERIES) documentation set to clusterlabs.org
if BUILD_DOCBOOK
	@for book in $(docbook); do 									\
		echo Uploading $$book...;								\
		echo "Generated on `date` from version: $(shell git log --pretty="format:%h %d" -n 1)" >> $$book/publish/build-$(PACKAGE_SERIES).txt;	\
		rsync $(RSYNC_OPTS) $$book/publish/* "$(RSYNC_DEST)/$(PACKAGE)/doc/";			\
	done
endif
	rsync $(RSYNC_OPTS) $(doc_DATA) "$(RSYNC_DEST)/$(PACKAGE)/doc/"


clean-local:
	-rm -f $(PNGS_GENERATED)
	-rm -rf $(generated_docs) $(generated_mans) $(docbook_build)
	-rm -rf $(SHARED_XML) $(CFS_XML_GEN) $(PD_XML_GEN) $(PE_XML_GEN) $(PR_XML_GEN)
	-rm -rf  publican-catalog-fallback publican-catalog
	for book in $(docbook); do rm -rf $$book/tmp $$book/publish; done
