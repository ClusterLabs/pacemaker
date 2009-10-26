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

man_MANS	= cibadmin.8 crm_resource.8
doc_DATA	= AUTHORS COPYING COPYING.LGPL README README.hb2openais crm_cli.txt crm_fencing.txt

XSLTPROC_HTML_STYLE=/opt/local/share/xsl/docbook-xsl/xhtml
XSLTPROC_HTML_OPTIONS = --xinclude \
			--param use.id.as.filename 1 \
			--param generate.index 1 \
			--param admon.graphics 1 \
			--stringparam admon.graphics.path images/ \
			--stringparam admon.graphics.extension .png \
			--stringparam ulink.target offsite-link \
			--stringparam html.stylesheet pacemaker.css \
			--stringparam toc.section.depth 2 \
			--stringparam chunk.first.sections 0 \
			--stringparam graphic.default.extension png

XSLTPROC_FO_OPTIONS ?=  --xinclude \
			$(XSLTPROC_PROFILING_OPTIONS) \
			--stringparam paper.type $(PAPER_SIZE) \
			--stringparam body.font.family "$(FO_BODY_FONT_FAMILY)" \
			--stringparam title.font.family "$(FO_TITLE_FONT_FAMILY)" \
			--stringparam insert.link.page.number yes \
			--stringparam insert.xref.page.number yes \
			--stringparam graphic.default.extension svg \
			--param section.autolabel 1 \
			--param section.autolabel.max.depth 2 \
			--param section.label.includes.component.label 1 \
			--stringparam generate.toc "/set toc,title /book toc,title /article toc.title" \
			--param use.extensions 1 \
			--param fop1.extensions 1 \
			--param tablecolumns.extension 0 \
			--param admon.graphics 1 \
			--stringparam admon.graphics.path images/ \
			--stringparam admon.graphics.extension .svg

%.fo: %.xml
	xsltproc -o $@ $(XSLTPROC_FO_OPTIONS) $(PROFILING_FO_STYLESHEET) $<

%.pdf: %.fo
	fop -c $(FOP_CONFIG) $< -pdf $@

if BUILD_HTML
doc_DATA	+= crm_cli.html crm_fencing.html
endif

EXTRA_DIST	= $(doc_DATA) $(man_MANS)

%.html: %.txt
	$(ASCIIDOC) --unsafe --backend=xhtml11 $<

%: %.xml
	-mkdir -p $@/images/
	cp *.png $@/images/ 
	cp pacemaker.css $@/ 
	xsltproc -o $@/ $(XSLTPROC_HTML_OPTIONS) $(XSLTPROC_HTML_STYLE)/chunk.xsl $<

push: pacemaker-explained
	scp -r pacemaker-explained root@oss.clusterlabs.org:/srv/www/extras/doc/

clean-local:
	-rm -rf pacemaker-explained
