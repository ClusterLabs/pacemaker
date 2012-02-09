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
endif

if BUILD_DOCBOOK
publican_docs	+= $(docbook)
endif

EXTRA_DIST	= $(docbook:%=%.xml) 

%.html: %.txt
	$(ASCIIDOC) --unsafe --backend=xhtml11 $<
%.8: %.8.txt
	a2x -L -f manpage $<

Clusters_from_Scratch_SRCS := $(wildcard Clusters_from_Scratch/*/*.xml)

# We have to hardcode the book name
# With '%' the test for 'newness' fails 
CFS_TXT=$(wildcard Clusters_from_Scratch/en-US/*.txt)
CFS_XML=$(CFS_TXT:%.txt=%.xml)
%.xml:  %.txt
	asciidoc -b docbook -d article -o $@ $<
	sed -i.sed 's/lang="en"//' $@     # Never specify a language here
	sed -i.sed 's/simpara/para/g' $@  # publican doesn't correctly render footnotes with simpara 
	sed -i.sed 's///' $@            # Fix line endings
	echo Rebuilt $@ from $<

Clusters_from_Scratch.txt: $(PNGS) $(wildcard Clusters_from_Scratch/en-US/*.xml) $(CFS_XML)
	@echo Building $(@:%.txt=%) because of $?
	rm -rf $(@:%.txt=%)/publish/*
	cd $(@:%.txt=%) && RPM_BUILD_DIR="" $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS)
	rm -rf $(@:%.txt=%)/tmp
	touch $@

Pacemaker_Explained.txt: $(PNGS) $(wildcard Pacemaker_Explained/en-US/*.xml)
	@echo Building $(@:%.txt=%) because of $?
	rm -rf $(@:%.txt=%)/publish/*
	cd $(@:%.txt=%) && RPM_BUILD_DIR="" $(PUBLICAN) build --publish --langs=$(DOCBOOK_LANGS) --formats=$(DOCBOOK_FORMATS)
	rm -rf $(@:%.txt=%)/tmp
	touch $@

pot:
	for book in Clusters_from_Scratch; do		 \
		cd $$book && RPM_BUILD_DIR="" $(PUBLICAN) update_pot; \
	done

po:
	for book in $(docbook); do 						\
		cd $$book && RPM_BUILD_DIR="" $(PUBLICAN) update_po --langs=$(DOCBOOK_LANGS);\
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
	-rm -rf $(generated_docs) $(generated_mans) $(docbook_txt)
	for book in $(docbook); do rm -rf $$book/tmp $$book/publish; done
