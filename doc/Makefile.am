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

ascii		= crm_cli.txt crm_fencing.txt
help_DATA	= crm_cli.txt
docbook		= Pacemaker_Explained Clusters_from_Scratch
doc_DATA	= README.hb2openais $(ascii) $(generated_docs)

publican_docs   =
generated_docs	= 

DOCBOOK_FORMATS := html,txt

SVG := $(wildcard */en-US/images/pcmk-*.svg)

PNGS = $(SVG:%.svg=%-small.png) $(SVG:%.svg=%.png)  $(SVG:%.svg=%-large.png)	\
	publican-clusterlabs/en-US/images/image_left.png			\
	publican-clusterlabs/en-US/images/image_right.png			\
	publican-clusterlabs/en-US/images/h1-bg.png

graphics: $(PNGS)

%.png: %.svg
	inkscape --file=$< --export-dpi=90 -C --export-png=$@

%-small.png: %.svg
	inkscape --file=$< --export-dpi=45 -C --export-png=$@

%-large.png: %.svg
	inkscape --file=$< --export-dpi=180 -C --export-png=$@

XML_FILES := $(wildcard *.xml)
PNG_FILES := $(wildcard images/*.png)

if BUILD_ASCIIDOC
generated_docs	+= $(ascii:%.txt=%.html)
endif

if BUILD_DOCBOOK
publican_docs	+= $(docbook)
endif

EXTRA_DIST	= $(docbook:%=%.xml) 

%.html: %.txt
	$(ASCIIDOC) --unsafe --backend=xhtml11 $<

%.txt: %/en-US/*.xml
	@echo Building $*
	cd $* && $(PUBLICAN) build --publish --langs=all --formats=$(DOCBOOK_FORMATS)
	touch $@

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

brand:
	cd publican-clusterlabs && publican build --formats=xml --langs=all --publish
	cd publican-clusterlabs && publican install_brand --path=$(datadir)/publican/Common_Content

#	find publican-clusterlabs -name "*.noarch.rpm" -exec rm -f \{\} \;
#	cd publican-clusterlabs && $(PUBLICAN) package --binary
#	find publican-clusterlabs -name "*.noarch.rpm" -exec sudo rpm -Uvh --force \{\} \;


push:   
	rm -f $(docbook_txt)
	make DOCBOOK_FORMATS="pdf,html,html-single,txt" all-local $(generated_docs)
	echo Uploading current documentation set to clusterlabs.org
	rsync -rtz --progress $(generated_docs) $(ascii) root@oss.clusterlabs.org:/var/www/html/doc/
if BUILD_DOCBOOK
	for book in $(docbook); do 									\
		echo Uploading $$book...;								\
		echo "Generated on `date` from version: $(BUILD_VERSION)" > $$book/publish/build-$(PACKAGE_SERIES).txt;	\
		rsync -rtz --progress $$book/publish/* root@oss.clusterlabs.org:/var/www/html/doc/;	\
	done
endif

clean-local:
	-rm -rf $(generated_docs) $(docbook_txt)
	for book in $(docbook); do rm -rf $$book/tmp $$book/publish; done
