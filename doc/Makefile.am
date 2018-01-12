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

helpdir		= $(datadir)/$(PACKAGE)

ascii		= crm_fencing.txt acls.txt
docbook		= Clusters_from_Scratch \
	Pacemaker_Development \
	Pacemaker_Explained \
	Pacemaker_Remote
doc_DATA	= $(ascii) $(generated_docs)

# toplevel rsync destination for www targets (without trailing slash)
RSYNC_DEST      ?= root@www.clusterlabs.org:/var/www/html

# recursive, preserve symlinks/permissions/times, verbose, compress,
# don't cross filesystems, sparse, show progress
RSYNC_OPTS      = -rlptvzxS --progress

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

DOTs = $(wildcard */en-US/images/*.dot)
SVG = $(wildcard */en-US/images/pcmk-*.svg) $(DOTs:%.dot=%.svg)

generated_PNGS = $(SVG:%.svg=%-small.png) $(SVG:%.svg=%.png)  $(SVG:%.svg=%-large.png) 	\
	Pacemaker_Explained/en-US/images/Policy-Engine-big.png  \
	Pacemaker_Explained/en-US/images/Policy-Engine-small.png
PNGS = $(generated_PNGS) \
	Pacemaker_Remote/en-US/images/pcmk-ha-cluster-stack.png \
	Pacemaker_Remote/en-US/images/pcmk-ha-remote-stack.png

BRAND_PNGS = publican-clusterlabs/en-US/images/title_logo.png			\
	publican-clusterlabs/en-US/images/image_left.png			\
	publican-clusterlabs/en-US/images/image_right.png			\
	publican-clusterlabs/en-US/images/h1-bg.png

graphics: $(PNGS)

%.png: %.svg
	$(AM_V_IMG)$(INKSCAPE) --file=$< --export-dpi=90 -C --export-png=$@

%-small.png: %.svg
	$(AM_V_IMG)$(INKSCAPE) --file=$< --export-dpi=45 -C --export-png=$@

%-large.png: %.svg
	$(AM_V_IMG)$(INKSCAPE) --file=$< --export-dpi=180 -C --export-png=$@

if BUILD_ASCIIDOC
generated_docs	+= $(ascii:%.txt=%.html)

if BUILD_DOCBOOK
publican_docs	+= $(docbook)
endif
endif

EXTRA_DIST	= $(docbook:%=%.xml)

%.html: %.txt
	$(AM_V_ASCII)$(ASCIIDOC) --unsafe --backend=xhtml11 $<

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

SHARED_TXT=$(wildcard shared/en-US/*.txt)
SHARED_XML=$(SHARED_TXT:%.txt=%.xml)


CFS_SHARED_TXT=$(addprefix shared/en-US/,pacemaker-intro.txt)
CFS_SHARED_XML=$(CFS_SHARED_TXT:%.txt=%.xml)
CFS_TXT=$(wildcard Clusters_from_Scratch/en-US/*.txt)
CFS_XML=$(CFS_TXT:%.txt=%.xml)

$(CFS_XML): $(CFS_SHARED_XML)

PUBLICAN_INTREE_DEPS =
if PUBLICAN_INTREE_BRAND
PUBLICAN_INTREE_DEPS += publican-catalog
endif

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Clusters_from_Scratch.build: $(PNGS) $(wildcard Clusters_from_Scratch/en-US/*.xml) $(CFS_XML) $(CFS_SHARED_XML) $(PUBLICAN_INTREE_DEPS)
	$(PCMK_V) @echo Building $(@:%.build=%) because of $?
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

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Pacemaker_Development.build: $(wildcard Pacemaker_Development/en-US/*.xml) $(PD_XML) $(PUBLICAN_INTREE_DEPS)
	$(PCMK_V) @echo Building $(@:%.build=%) because of $?
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


PE_SHARED_TXT=$(addprefix shared/en-US/,pacemaker-intro.txt)
PE_SHARED_XML=$(PE_SHARED_TXT:%.txt=%.xml)
PE_TXT=$(wildcard Pacemaker_Explained/en-US/*.txt)
PE_XML=$(PE_TXT:%.txt=%.xml)

$(PE_XML): $(PE_SHARED_XML)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Pacemaker_Explained.build: $(PNGS) $(wildcard Pacemaker_Explained/en-US/*.xml) $(PE_XML) $(PE_SHARED_XML) $(PUBLICAN_INTREE_DEPS)
	$(PCMK_V) @echo Building $(@:%.build=%) because of $?
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


PR_TXT=$(wildcard Pacemaker_Remote/en-US/*.txt)
PR_XML=$(PR_TXT:%.txt=%.xml)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Pacemaker_Remote.build: $(PNGS) $(wildcard Pacemaker_Remote/en-US/*.xml) $(PR_XML) $(PUBLICAN_INTREE_DEPS)
	$(PCMK_V) @echo Building $(@:%.build=%) because of $?
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

brand:  $(BRAND_PNGS) $(wildcard publican-clusterlabs/en-US/*.xml)
	cd publican-clusterlabs && publican build --formats=xml --langs=all --publish
	echo "Installing..."
	cd publican-clusterlabs && sudo publican install_brand --path=$(datadir)/publican/Common_Content

#	find publican-clusterlabs -name "*.noarch.rpm" -exec rm -f \{\} \;
#	cd publican-clusterlabs && $(PUBLICAN) package --binary
#	find publican-clusterlabs -name "*.noarch.rpm" -exec sudo rpm -Uvh --force \{\} \;

pdf:
	make DOCBOOK_FORMATS="pdf" all-local

www: clean-local $(generated_docs) $(ascii)
	for book in $(docbook); do 							\
		sed -i.sed 's@^brand:.*@brand: clusterlabs@' $$book/publican.cfg;	\
	done
	make DOCBOOK_FORMATS="pdf,html,html-single,epub" DOCBOOK_LANGS="$(UPLOAD_LANGS)" all-local
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
	-rm -rf $(generated_docs) $(generated_mans) $(docbook_build) $(generated_PNGS)
	-rm -rf $(SHARED_XML) $(CFS_XML) $(PE_XML) $(PR_XML)
	-rm -rf  publican-catalog-fallback publican-catalog
	for book in $(docbook); do rm -rf $$book/tmp $$book/publish; done
