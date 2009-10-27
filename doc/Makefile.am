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

docdir 		= $(datadir)/doc/packages/@PACKAGE@

ascii		= crm_cli.txt crm_fencing.txt
docbook		= pacemaker-explained
man_MANS	= cibadmin.8 crm_resource.8
doc_DATA	= README.hb2openais index.html $(generated_docs)

generated_docs	= 


XML_FILES := $(wildcard *.xml)
PNG_FILES := $(wildcard images/*.png)
FOP_CONFIG = pacemaker-fop.xml

# Paths to Norm Walsh's DocBook XSL stylesheets.  
# Fetching these from the web on every run is probably dead slow, so
# make sure you have a local copy of these stylesheets installed, and
# XML catalogs set up correctly. On most systems, this is a simple
# matter of installing the docbook-xsl package.
#Web:  STYLESHEET_PREFIX ?= http://docbook.sourceforge.net/release/xsl/current
#OSX:  STYLESHEET_PREFIX=/opt/local/share/xsl/docbook-xsl
#F-12: STYLESHEET_PREFIX=/usr/share/sgml/docbook/xsl-stylesheets
STYLESHEET_PREFIX=http://docbook.sourceforge.net/release/xsl/current

HTML_STYLESHEET ?= $(STYLESHEET_PREFIX)/xhtml/docbook.xsl
PROFILING_HTML_STYLESHEET ?= $(STYLESHEET_PREFIX)/xhtml/profile-docbook.xsl
CHUNKED_HTML_STYLESHEET ?= $(STYLESHEET_PREFIX)/xhtml/chunk.xsl
CHUNKED_PROFILING_HTML_STYLESHEET ?= $(STYLESHEET_PREFIX)/xhtml/profile-chunk.xsl
TITLEPAGE_STYLESHEET ?= $(STYLESHEET_PREFIX)/template/titlepage.xsl

FO_STYLESHEET ?= $(STYLESHEET_PREFIX)/fo/docbook.xsl
PROFILING_FO_STYLESHEET ?= $(STYLESHEET_PREFIX)/fo/profile-docbook.xsl
CHUNKED_FO_STYLESHEET ?= $(STYLESHEET_PREFIX)/fo/chunk.xsl
CHUNKED_PROFILING_FO_STYLESHEET ?= $(STYLESHEET_PREFIX)/fo/profile-chunk.xsl

# For HTML output, define the name of the frame where 
# <ulink> URLs should open
ULINK_TARGET ?= offsite-link
XSLTPROC_PROFILING_OPTIONS = 

PAPER_SIZE=A4
#FO_BODY_FONT_FAMILY  = --stringparam body.font.family "serif"
#FO_TITLE_FONT_FAMILY = --stringparam title.font.family "serif"

#XSLTPROC_PROFILING_OPTIONS += --stringparam profile.arch $(ARCH)
#XSLTPROC_PROFILING_OPTIONS += --stringparam profile.condition $(CONDITION)
#XSLTPROC_PROFILING_OPTIONS += --stringparam profile.userlevel $(USERLEVEL)
#XSLTPROC_PROFILING_OPTIONS += --stringparam profile.vendor $(VENDOR)

# For "status", use a slightly different logic. Unless set otherwise,
# always assume "current".
#STATUS ?= current
#XSLTPROC_PROFILING_OPTIONS += --stringparam profile.status $(STATUS)

XSLTPROC_HTML_OPTIONS = --xinclude \
			$(XSLTPROC_PROFILING_OPTIONS) \
			--param use.id.as.filename 1 \
			--param generate.index 1 \
			--param admon.graphics 1 \
			--stringparam admon.graphics.path ../images/ \
			--stringparam admon.graphics.extension .png \
			--stringparam ulink.target $(ULINK_TARGET) \
			--stringparam html.stylesheet pacemaker.css \
			--stringparam toc.section.depth 2 \
			--stringparam chunk.first.sections 0 \
			--stringparam graphic.default.extension .png

XSLTPROC_FO_OPTIONS ?=  --xinclude \
			$(XSLTPROC_PROFILING_OPTIONS) \
			--stringparam paper.type $(PAPER_SIZE) \
			$(FO_BODY_FONT_FAMILY) \
			$(FO_TITLE_FONT_FAMILY) \
			--stringparam insert.link.page.number yes \
			--stringparam insert.xref.page.number yes \
			--stringparam graphic.default.extension png \
			--param section.autolabel 1 \
			--param section.autolabel.max.depth 2 \
			--param section.label.includes.component.label 1 \
			--stringparam generate.toc "/set toc,title /book toc,title /article toc.title" \
			--param use.extensions 1 \
			--param fop1.extensions 1 \
			--param tablecolumns.extension 0 \
			--param admon.graphics 1 \
			--stringparam admon.graphics.path images/ \
			--stringparam admon.graphics.extension .png

if BUILD_ASCIIDOC
generated_docs	+= $(ascii:%.txt=%.html)
endif

if BUILD_DOCBOOK
generated_docs	+= $(docbook:%=%/index.html) $(docbook:%=%.html)
endif

if BUILD_FOP
generated_docs	+= $(docbook:%=%.pdf)
endif

EXTRA_DIST	= $(man_MANS) $(docbook:%=%.xml) pacemaker.css

%.html: %.txt
	$(ASCIIDOC) --unsafe --backend=xhtml11 $<

%.html: %.xml
	xsltproc -o $*.html $(XSLTPROC_HTML_OPTIONS) $(HTML_STYLESHEET) $<

%/index.html: %.xml images pacemaker.css
	-mkdir $*
	cp -r $(srcdir)/pacemaker.css $(srcdir)/images $*/
	xsltproc -o $*/ $(XSLTPROC_HTML_OPTIONS) $(CHUNKED_HTML_STYLESHEET) $<

%.fo: %.xml $(PNG_FILES)
	xsltproc -o $@ $(XSLTPROC_FO_OPTIONS) $(FO_STYLESHEET) $<

%.pdf: %.fo 
	$(FOP) $< -pdf $@
#fop -c $(FOP_CONFIG) $< -pdf $@

index.html: $(generated_docs)
	echo "Building documentation index"
	echo "<html><body><p>The following <a href=\"http://www.clusterlabs.org/wiki/Pacemaker\">Pacemaker</a> documentation was generated on `date` from version: $(BUILD_VERSION)</p>" > index.html	
	echo "<ol>" >> index.html	
	for doc in $(generated_docs:%/index.html=%); do 			\
		echo "<li><a href=\"$$doc\">$$doc</a></li>" >> index.html; 	\
	done
	echo "</ol>" >> index.html	
	echo "<p>You can find <a href=\"http://www.clusterlabs.org/wiki/Documentation\">additional documentation</a> and details about the Pacemaker project at <a href=\"http://www.clusterlabs.org\">http://www.clusterlabs.org</a></p>" >> index.html	
	echo "</body></html>" >> index.html	

push: index.html $(generated_docs:%/index.html=%) images pacemaker.css
	echo Uploading current documentation set to clusterlabs.org
	scp -r $^ root@oss.clusterlabs.org:/srv/www/extras/doc/

clean-local:
	-rm -rf $(generated_docs) $(docbook) $(docbook:%=%.fo)
