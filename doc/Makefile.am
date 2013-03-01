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
MAINTAINERCLEANFILES    = Makefile.in

helpdir		= $(datadir)/$(PACKAGE)

ascii		= crm_fencing.txt acls.txt
docbook		= Pacemaker_Explained Clusters_from_Scratch
doc_DATA	= README.hb2openais $(ascii) $(generated_docs)

publican_docs   =
generated_docs	=
generated_mans	=

DOCBOOK_FORMATS := html-desktop
DOCBOOK_LANGS   := en-US
DOTs = $(wildcard */en-US/images/*.dot)
SVG = $(wildcard */en-US/images/pcmk-*.svg) $(DOTs:%.dot=%.svg)

PNGS = $(SVG:%.svg=%-small.png) $(SVG:%.svg=%.png)  $(SVG:%.svg=%-large.png) 	\
	Pacemaker_Explained/en-US/images/Policy-Engine-big.png
	Pacemaker_Explained/en-US/images/Policy-Engine-small.png

BRAND_PNGS = publican-clusterlabs/en-US/images/title_logo.png			\
	publican-clusterlabs/en-US/images/image_left.png			\
	publican-clusterlabs/en-US/images/image_right.png			\
	publican-clusterlabs/en-US/images/h1-bg.png

graphics: $(PNGS)

%.png: %.svg
	$(INKSCAPE) --file=$< --export-dpi=90 -C --export-png=$@

%-small.png: %.svg
	$(INKSCAPE) --file=$< --export-dpi=45 -C --export-png=$@

%-large.png: %.svg
	$(INKSCAPE) --file=$< --export-dpi=180 -C --export-png=$@

if BUILD_ASCIIDOC
generated_docs	+= $(ascii:%.txt=%.html)

if BUILD_DOCBOOK
publican_docs	+= $(docbook)
endif
endif

EXTRA_DIST	= $(docbook:%=%.xml)

%.html: %.txt
	$(ASCIIDOC) --unsafe --backend=xhtml11 $<
%.8: %.8.txt
	a2x -L -f manpage $<

# Build docbook from asciidoc because XML is a PITA to edit
#
# Build each chapter as a book (since the numbering isn't right for
# articles and only books can have appendicies) and then strip out the
# bits we don't want/need
#
%.xml:  %.txt
	asciidoc -b docbook -a cli_name=$(ASCIIDOC_CLI_TYPE) -a $(ASCIIDOC_CLI_TYPE)=true -d book -o $@ $<
	sed -i.sed 's///' $@
	sed -i.sed 's///' $@                 # Fix line endings
	sed -i.sed 's/\ lang="en"//' $@        # Never specify a language in the chapters
	sed -i.sed 's/simpara/para/g' $@       # publican doesn't correctly render footnotes with simpara
	sed -i.sed 's/.*<date>.*//g' $@	       # Remove dangling tag
	sed -i.sed 's/.*preface>//g' $@        # Remove preface elements
	sed -i.sed 's:<title></title>::g' $@   # Remove empty title
	sed -i.sed 's/chapter/section/g' $@    # Chapters become sections, so that books can become chapters
	sed -i.sed 's/<.*bookinfo.*>//g' $@    # Strip out bookinfo, we don't need it
	-grep -qis "<appendix" $@ && sed -i.sed 's/.*book>//' $@         # We just want the appendix tag
	-grep -vqis "<appendix" $@ && sed -i.sed 's/book>/chapter>/g' $@ # Rename to chapter
	echo Rebuilt $@ from $<

CFS_TXT=$(wildcard Clusters_from_Scratch/en-US/*.txt)
CFS_XML=$(CFS_TXT:%.txt=%.xml)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Clusters_from_Scratch.build: $(PNGS) $(wildcard Clusters_from_Scratch/en-US/*.xml) $(CFS_XML)
	@echo Building $(@:%.build=%) because of $?
	rm -rf $(@:%.build=%)/publish/*
	cd $(@:%.build=%) && RPM_BUILD_DIR="" $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS)
	rm -rf $(@:%.build=%)/tmp
	touch $@

PE_TXT=$(wildcard Pacemaker_Explained/en-US/*.txt)
PE_XML=$(PE_TXT:%.txt=%.xml)

# We have to hardcode the book name
# With '%' the test for 'newness' fails
Pacemaker_Explained.build: $(PNGS) $(wildcard Pacemaker_Explained/en-US/*.xml) $(PE_XML)
	@echo Building $(@:%.build=%) because of $?
	rm -rf $(@:%.build=%)/publish/*
	cd $(@:%.build=%) && RPM_BUILD_DIR="" $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS)
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

#install-data-local: all-local
install-data-local: all-local
	for book in $(docbook); do 							\
	    filelist=`find $$book/publish/* -print`;					\
	    for f in $$filelist; do							\
		p=`echo $$f | sed s:publish/:: | sed s:Pacemaker/::`;			\
		if [ -d $$f ]; then							\
			$(INSTALL) -d 775 $(DESTDIR)$(docdir)/$$p;			\
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
	make DOCBOOK_FORMATS="pdf" ASCIIDOC_CLI_TYPE=$(ASCIIDOC_CLI_TYPE) all-local

# Make sure www-(pcs|crmsh) happen in serial
www:
	make www-pcs
	make www-crmsh
	make $(generated_docs) $(ascii)
	rsync -rtz --progress $(generated_docs) $(ascii) $(asciiman) root@www.clusterlabs.org:/var/www/html/doc/

www-crmsh:
	make ASCIIDOC_CLI_TYPE=crmsh clean-local www-cli

www-pcs:
	make ASCIIDOC_CLI_TYPE=pcs clean-local www-cli

www-cli:
	for book in $(docbook); do 										\
		sed -i.sed 's@brand:.*@brand: clusterlabs@' $$book/publican.cfg;				\
		sed -i.sed 's@version:.*@version: $(PACKAGE_SERIES)-$(ASCIIDOC_CLI_TYPE)@' $$book/publican.cfg;	\
	done
	make DOCBOOK_FORMATS="pdf,html,html-single,epub" DOCBOOK_LANGS="all" ASCIIDOC_CLI_TYPE=$(ASCIIDOC_CLI_TYPE) all-local
	echo Uploading current $(PACKAGE_SERIES)-$(ASCIIDOC_CLI_TYPE) documentation set to clusterlabs.org
if BUILD_DOCBOOK
	for book in $(docbook); do 									\
		echo Uploading $$book...;								\
		echo "Generated on `date` from version: $(shell git log --pretty="format:%h %d" -n 1)" >> $$book/publish/build-$(PACKAGE_SERIES)-$(ASCIIDOC_CLI_TYPE).txt;	\
		for lang in `ls -1 $$book/publish | grep [a-z][a-z]-[A-Z][A-Z]`; do							\
			mv $$book/publish/$$lang/Pacemaker/$(PACKAGE_SERIES)-$(ASCIIDOC_CLI_TYPE)/epub/$$book/Pacemaker-1.1{-$(ASCIIDOC_CLI_TYPE),}-$$book-$$lang.epub;	\
			mv $$book/publish/$$lang/Pacemaker/$(PACKAGE_SERIES)-$(ASCIIDOC_CLI_TYPE)/pdf/$$book/Pacemaker-1.1{-$(ASCIIDOC_CLI_TYPE),}-$$book-$$lang.pdf;	\
		done;											\
		rsync -rtz --progress $$book/publish/* root@www.clusterlabs.org:/var/www/html/doc/;	\
		sed -i.sed 's@version:.*@version: $(PACKAGE_SERIES)@' $$book/publican.cfg;		\
	done
endif

clean-local:
	-rm -rf $(generated_docs) $(generated_mans) $(docbook_build) $(CFS_XML) $(PE_XML)
	for book in $(docbook); do rm -rf $$book/tmp $$book/publish; done

foo:
	rm -f $(CFS_XML)
