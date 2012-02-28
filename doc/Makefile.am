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
asciiman	= crm.8.txt
help_DATA	= crm.8.txt
docbook		= Pacemaker_Explained Clusters_from_Scratch
doc_DATA	= README.hb2openais $(ascii) $(generated_docs)

publican_docs   =
generated_docs	= 
generated_mans	= 

DOCBOOK_FORMATS := html-desktop,txt
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
generated_docs	+= $(ascii:%.txt=%.html) $(asciiman:%.txt=%.html)
generated_mans	+= $(asciiman:%.8.txt=%.8)
$(generated_mans): $(asciiman)
man8_MANS	= $(generated_mans)

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
	asciidoc -b docbook -d book -o $@ $<
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
Clusters_from_Scratch.txt: $(PNGS) $(wildcard Clusters_from_Scratch/en-US/*.xml) $(CFS_XML)
	@echo Building $(@:%.txt=%) because of $?
	rm -rf $(@:%.txt=%)/publish/*
	cd $(@:%.txt=%) && RPM_BUILD_DIR="" $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS)
	rm -rf $(@:%.txt=%)/tmp
	touch $@

PE_TXT=$(wildcard Pacemaker_Explained/en-US/*.txt)
PE_XML=$(PE_TXT:%.txt=%.xml)

# We have to hardcode the book name
# With '%' the test for 'newness' fails 
Pacemaker_Explained.txt: $(PNGS) $(wildcard Pacemaker_Explained/en-US/*.xml) $(PE_XML)
	@echo Building $(@:%.txt=%) because of $?
	rm -rf $(@:%.txt=%)/publish/*
	cd $(@:%.txt=%) && RPM_BUILD_DIR="" $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS)
	rm -rf $(@:%.txt=%)/tmp
	touch $@

# Update the translation template
pot:
	for book in $(docbook); do 				      \
		echo "Updating translation templates in: $$book";     \
		( cd $$book && RPM_BUILD_DIR="" $(PUBLICAN) update_pot ); \
	done

# Update the actual translations
po:
	for book in $(docbook); do 				      \
		echo "Updating translations in: $$book";     \
		( cd $$book && RPM_BUILD_DIR="" $(PUBLICAN) update_po --langs=$(DOCBOOK_LANGS) );\
	done

if BUILD_DOCBOOK
docbook_txt = $(docbook:%=%.txt)

all-local: $(docbook_txt) */publican.cfg

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

www:    $(generated_docs)
	echo rsync -rtz --progress $(generated_docs) $(ascii) $(asciiman) root@www.clusterlabs.org:/var/www/html/doc/
	rsync -rtz --progress $(generated_docs) $(ascii) $(asciiman) root@www.clusterlabs.org:/var/www/html/doc/
	rm -f $(docbook_txt)
	make DOCBOOK_FORMATS="pdf,html,html-single,txt,epub" DOCBOOK_LANGS="all" all-local $(generated_docs) $(ascii)
	echo Uploading current documentation set to clusterlabs.org
	rsync -rtz --progress $(generated_docs) $(ascii) $(asciiman) root@www.clusterlabs.org:/var/www/html/doc/
if BUILD_DOCBOOK
	for book in $(docbook); do 									\
		echo Uploading $$book...;								\
		echo "Generated on `date` from version: $(shell git log --pretty="format:%h %d" -n 1)" > $$book/publish/build-$(PACKAGE_SERIES).txt;	\
		rsync -rtz --progress $$book/publish/* root@www.clusterlabs.org:/var/www/html/doc/;	\
	done
endif

clean-local:
	-rm -rf $(generated_docs) $(generated_mans) $(docbook_txt) $(CFS_XML) $(PE_XML)
	for book in $(docbook); do rm -rf $$book/tmp $$book/publish; done

foo:
	rm -f $(CFS_XML)
