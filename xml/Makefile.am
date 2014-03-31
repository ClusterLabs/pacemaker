#
# Copyright (C) 2004 Andrew Beekhof
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

dtddir			= $(CRM_DTD_DIRECTORY)
dtd_SCRIPTS		= crm.dtd crm-transitional.dtd

xsltdir			= $(dtddir)
xslt_SCRIPTS		= upgrade06.xsl upgrade11.xsl

RNGdir			= $(dtddir)

# See Readme.md for details on updating schema files
RNG_versions		= 1.0 1.2 next
RNG_generated		= pacemaker.rng $(foreach base,$(RNG_versions),pacemaker-$(base).rng)

RNG_cfg_base	 	= options nodes resources constraints fencing acls
RNG_base	 	= cib $(RNG_cfg_base) status versions score rule nvset
RNG_files	 	= $(foreach base,$(RNG_base),$(wildcard $(base)*.rng))

RNG_SCRIPTS		= $(RNG_files) $(RNG_generated)

EXTRA_DIST		= best-match.sh

best_match		= $(shell $(top_srcdir)/xml/best-match.sh $(1) $(2))

versions.rng: Makefile.am
	echo "<?xml version='1.0' encoding='UTF-8'?>" > $@
	echo "<grammar xmlns='http://relaxng.org/ns/structure/1.0' datatypeLibrary='http://www.w3.org/2001/XMLSchema-datatypes'>" >> $@
	echo "  <start>" >> $@
	echo "    <optional>" >> $@
	echo "    <attribute name='validate-with'>" >> $@
	echo "      <choice>" >> $@
	echo "        <value>none</value>" >> $@
	echo "        <value>pacemaker-0.6</value>" >> $@
	echo "        <value>transitional-0.6</value>" >> $@
	echo "        <value>pacemaker-0.7</value>" >> $@
	echo "        <value>pacemaker-1.1</value>" >> $@
	for rng in $(RNG_versions); do echo "        <value>pacemaker-$$rng</value>" >> $@; done
	echo "      </choice>" >> $@
	echo "    </attribute>" >> $@
	echo "    </optional>" >> $@
	echo "    <attribute name='admin_epoch'><data type='nonNegativeInteger'/></attribute>" >> $@
	echo "    <attribute name='epoch'><data type='nonNegativeInteger'/></attribute>" >> $@
	echo "    <attribute name='num_updates'><data type='nonNegativeInteger'/></attribute>" >> $@
	echo "  </start>" >> $@
	echo "</grammar>" >> $@
	echo "Built $@"

pacemaker.rng: pacemaker-$(CRM_DTD_VERSION).rng
	cp $(top_builddir)/xml/$< $@

pacemaker-%.rng: $(RNG_files) best-match.sh Makefile.am 
	echo "<?xml version='1.0' encoding='UTF-8'?>" > $@
	echo "<grammar xmlns='http://relaxng.org/ns/structure/1.0' datatypeLibrary='http://www.w3.org/2001/XMLSchema-datatypes'>" >> $@
	echo "  <start>" >> $@
	echo "    <element name='cib'>" >> $@
	$(top_srcdir)/xml/best-match.sh cib $(*) $(@) "      "
	echo "      <element name='configuration'>" >> $@
	echo "        <interleave>" >> $@
	for rng in $(RNG_cfg_base); do $(top_srcdir)/xml/best-match.sh $$rng $(*) $(@) "          "; done
	echo "        </interleave>" >> $@
	echo "      </element>" >> $@
	echo "      <element name='status'>" >> $@
	$(top_srcdir)/xml/best-match.sh status $(*) $(@) "        "
	echo "      </element>" >> $@
	echo "    </element>" >> $@
	echo "  </start>" >> $@
	echo "</grammar>" >> $@
	echo "Built $@"

rng_next = $(shell echo $(wildcard *-next.rng) | sed 's/-next.rng//g')
diff:
	echo "Comparing changes to: $(rng_next)"
	for rng in $(rng_next); do echo "### $${rng}"; diff -u $${rng}-$(CRM_DTD_VERSION).rng $${rng}-next.rng; done
	echo "Done"

sync:
	git rm -f $(wildcard *-next.rng)
	make pacemaker-next.rng

clean:
	rm -f $(RNG_generated)
