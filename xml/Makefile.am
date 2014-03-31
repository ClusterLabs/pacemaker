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

schema_VERSIONS		= 1.2 next
schema_GENERATED	= pacemaker.rng $(foreach base,$(schema_VERSIONS),pacemaker-$(base).rng)

schemadir		= $(CRM_DTD_DIRECTORY)
RNG_cfg_files	 	= options nodes resources constraints fencing acls unused
RNG_files	 	= cib $(RNG_cfg_files) status versions score rule nvset
schema_SCRIPTS		= $(foreach base,$(RNG_files),$(wildcard $(base)*.rng)) $(schema_GENERATED) \
			  pacemaker-1.0.rng upgrade06.xsl upgrade11.xsl

EXTRA_DIST		= $(schema_SCRIPTS) $(dtd_SCRIPTS)

# See Readme.md for details on updating schema files

best_match		= $(shell $(top_srcdir)/xml/best-match.sh $(1) $(2))

pacemaker.rng: pacemaker-$(CRM_DTD_VERSION).rng
	cp $(top_builddir)/xml/$< $@

pacemaker-%.rng:
	echo "<?xml version='1.0' encoding='UTF-8'?>" > $@
	echo "<grammar xmlns='http://relaxng.org/ns/structure/1.0' datatypeLibrary='http://www.w3.org/2001/XMLSchema-datatypes'>" >> $@
	echo "  <start>" >> $@
	echo "    <element name='cib'>" >> $@
	echo "      <externalRef href=\"$(call best_match,cib,$*)\"/>" >> $@
	echo "      <element name='configuration'>" >> $@
	echo "        <interleave>" >> $@
	echo -e " "$(foreach rng,$(RNG_cfg_files),"         <externalRef href=\"$(call best_match,$(rng),$*)\"/>\n") >> $@
	echo "        </interleave>" >> $@
	echo "      </element>" >> $@
	echo "      <element name='status'>" >> $@
	echo "        <externalRef href=\"$(call best_match,status,$*)\"/>" >> $@
	echo "      </element>" >> $@
	echo "    </element>" >> $@
	echo "  </start>" >> $@
	echo "</grammar>" >> $@

	echo "Created $@"

rng_next = $(shell echo $(wildcard *-next.rng) | sed 's/-next.rng//g')
diff:
	echo "Comparing changes to: $(rng_next)"
	for rng in $(rng_next); do echo "### $${rng}"; diff -u $${rng}-$(CRM_DTD_VERSION).rng $${rng}-next.rng; done
	echo "Done"

sync:
	git rm -f $(wildcard *-next.rng)
	make pacemaker-next.rng

clean:
	rm -f $(schema_GENERATED)
