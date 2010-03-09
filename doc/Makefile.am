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
docbook		= Pacemaker_Explained
man_MANS	= cibadmin.8 crm_resource.8
doc_DATA	= README.hb2openais $(ascii) $(generated_docs)

publican_docs    =
generated_docs	= 


XML_FILES := $(wildcard *.xml)
PNG_FILES := $(wildcard images/*.png)

if BUILD_ASCIIDOC
generated_docs	+= $(ascii:%.txt=%.html)
endif

if BUILD_DOCBOOK
publican_docs	+= $(docbook)
endif

EXTRA_DIST	= $(man_MANS) $(docbook:%=%.xml) 

index.html: 
	echo "Building documentation index"
	echo "<html><body><p>The following <a href=\"http://www.clusterlabs.org/wiki/Pacemaker\">Pacemaker</a> documentation was generated on `date` from version: $(BUILD_VERSION)</p>" > index.html	
	echo "<ol>" >> index.html
	for doc in $(generated_docs); do 					\
		echo "<li><a href=\"$$doc\">$$doc</a></li>" >> index.html; 	\
	done
if BUILD_DOCBOOK
	for book in $(docbook); do 					\
	    for lang in `ls -1 $(docbook)/publish`; do 			\
	      echo "<li>$$book ($$lang)<ul>" >> index.html; 	\
	      find $$book/publish/$$lang -name "*.pdf" -exec echo -n "<li><a href=\"{}\">" \; -exec basename {} \; -exec echo "</a></li>" \; | sed s:$$book/publish/:: >> index.html ;		\
	      find $$book/publish/$$lang -name "*.txt" -exec echo -n "<li><a href=\"{}\">" \; -exec basename {} \; -exec echo "</a></li>" \; | sed s:$$book/publish/:: >> index.html ;		\
	      find $$book/publish/$$lang -name html -exec echo "<li><a href=\"{}/$$book/index.html\">$$book HTML</a></li>" \; | sed s:$$book/publish/:: >> index.html ;		 		\
	      find $$book/publish/$$lang -name html-single -exec echo "<li><a href=\"{}/$$book/index.html\">$$book HTML (single page)</a></li>" \; | sed s:$$book/publish/:: >> index.html ;	\
	      echo "</ul></li>" >> index.html; 				\
	    done;							\
	done
endif
	echo "</ol>" >> index.html	
	echo "<p>You can find <a href=\"http://www.clusterlabs.org/wiki/Documentation\">additional documentation</a> and details about the Pacemaker project at <a href=\"http://www.clusterlabs.org\">http://www.clusterlabs.org</a></p>" >> index.html	
	echo "</body></html>" >> index.html	


%.html: %.txt
	$(ASCIIDOC) --unsafe --backend=xhtml11 $<

%.txt: %/en-US/*.xml
	cd $* && $(PUBLICAN) build --publish --langs=all --formats=pdf,html,html-single,txt
	touch $@

if BUILD_DOCBOOK
docbook_txt = $(docbook:%=%.txt)

all-local: $(docbook_txt)

#install-data-local: all-local
install-data-local: all-local 
	for book in $(docbook); do 							\
	    filelist=`find $$book/publish -print`;					\
	    for f in $$filelist; do							\
		p=`echo $$f | sed s:publish/:: | sed s:Pacemaker/::`;			\
		if [ -d $$f ]; then							\
			echo $(INSTALL) -d 775 $(DESTDIR)/$(docdir)/$$p;		\
		else									\
			echo $(INSTALL) -m 644 $$f $(DESTDIR)/$(docdir)/$$p;		\
		fi									\
	    done;									\
	done
endif

push:   all-local $(generated_docs)
	echo Uploading current documentation set to clusterlabs.org
	rsync -rtz --progress $(generated_docs) root@oss.clusterlabs.org:/srv/www/extras/doc/
if BUILD_DOCBOOK
	for book in $(docbook); do 							\
		echo Uploading $$book...;						\
		echo "Generated on `date` from version: $(BUILD_VERSION)" > $$book/publish/build-$(PACKAGE_SERIES).txt;	\
		rsync -rtz --progress $$book/publish/* root@oss.clusterlabs.org:/srv/www/extras/doc/;	\
	done
endif

clean-local:
	-rm -rf $(generated_docs) $(docbook)/tmp $(docbook)/publish $(docbook_txt)
