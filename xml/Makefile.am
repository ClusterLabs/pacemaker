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
xslt_SCRIPTS		= upgrade06.xsl upgrade-*.xsl

RNGdir			= $(dtddir)

# See Readme.md for details on updating schema files

# Sorted list of available numeric RNG versions,
# extracted from filenames like NAME-MAJOR[.MINOR][.MINOR-MINOR].rng
RNG_numeric_versions    = $(shell ls -1 *.rng \
			  | sed -E -n -e 's/^.*-([0-9.]+).rng$$/\1/p' \
			  | sort -u -t. -k 1,1n -k 2,2n -k 3,3n)

# The highest numeric version
RNG_max			?= $(lastword $(RNG_numeric_versions))

# A sorted list of all RNG versions (numeric and "next")
RNG_versions		= next $(RNG_numeric_versions)
RNG_version_pairs	= $(join \
			    ${RNG_numeric_versions},$(addprefix \
			      -,$(wordlist \
			        2,$(words ${RNG_numeric_versions}),${RNG_numeric_versions} \
			      ) next \
			    ) \
			  )
RNG_version_pairs_cnt	= $(words ${RNG_version_pairs})
RNG_version_pairs_last  = $(wordlist \
			    $(words \
			      $(wordlist \
			        2,${RNG_version_pairs_cnt},${RNG_version_pairs} \
			      ) \
			    ),${RNG_version_pairs_cnt},${RNG_version_pairs} \
			  )

RNG_generated		= pacemaker.rng $(foreach base,$(RNG_versions),pacemaker-$(base).rng) versions.rng

RNG_cfg_base	 	= options nodes resources constraints fencing acls tags
RNG_base	 	= cib $(RNG_cfg_base) status score rule nvset
RNG_files	 	= $(foreach base,$(RNG_base),$(wildcard $(base)*.rng))

# List of non-Pacemaker RNGs
RNG_extra		= crm_mon.rng

RNG_SCRIPTS		= $(RNG_files) $(RNG_generated) $(RNG_extra)

EXTRA_DIST		= best-match.sh Reference.md

versions:
	echo "Max: $(RNG_max)"
	echo "Available: $(RNG_versions)"

versions.rng: Makefile.am
	echo "  RNG      $@"
	echo "<?xml version='1.0' encoding='UTF-8'?>" > $@
	echo "<grammar xmlns='http://relaxng.org/ns/structure/1.0' datatypeLibrary='http://www.w3.org/2001/XMLSchema-datatypes'>" >> $@
	echo "  <start>" >> $@
	echo "   <interleave>" >> $@
	echo "    <optional>" >> $@
	echo "      <attribute name='validate-with'>" >> $@
	echo "        <choice>" >> $@
	echo "          <value>none</value>" >> $@
	echo "          <value>pacemaker-0.6</value>" >> $@
	echo "          <value>transitional-0.6</value>" >> $@
	echo "          <value>pacemaker-0.7</value>" >> $@
	echo "          <value>pacemaker-1.1</value>" >> $@
	for rng in $(RNG_versions); do echo "          <value>pacemaker-$$rng</value>" >> $@; done
	echo "        </choice>" >> $@
	echo "      </attribute>" >> $@
	echo "    </optional>" >> $@
	echo "    <attribute name='admin_epoch'><data type='nonNegativeInteger'/></attribute>" >> $@
	echo "    <attribute name='epoch'><data type='nonNegativeInteger'/></attribute>" >> $@
	echo "    <attribute name='num_updates'><data type='nonNegativeInteger'/></attribute>" >> $@
	echo "   </interleave>" >> $@
	echo "  </start>" >> $@
	echo "</grammar>" >> $@

pacemaker.rng: pacemaker-$(RNG_max).rng
	echo "  RNG      $@"
	cp $(top_builddir)/xml/$< $@

pacemaker-%.rng: $(RNG_files) best-match.sh Makefile.am 
	echo "  RNG      $@"
	echo "<?xml version='1.0' encoding='UTF-8'?>" > $@
	echo "<grammar xmlns='http://relaxng.org/ns/structure/1.0' datatypeLibrary='http://www.w3.org/2001/XMLSchema-datatypes'>" >> $@
	echo "  <start>" >> $@
	echo "    <element name='cib'>" >> $@
	./best-match.sh cib $(*) $(@) "      "
	echo "      <element name='configuration'>" >> $@
	echo "        <interleave>" >> $@
	for rng in $(RNG_cfg_base); do ./best-match.sh $$rng $(*) $(@) "          " || :; done
	echo "        </interleave>" >> $@
	echo "      </element>" >> $@
	echo "      <element name='status'>" >> $@
	./best-match.sh status $(*) $(@) "        "
	echo "      </element>" >> $@
	echo "    </element>" >> $@
	echo "  </start>" >> $@
	echo "</grammar>" >> $@

# diff fails with ec=2 if no predecessor is found;
# this uses '=' GNU extension to sed, if that's not available,
# one can use: hline=`echo "$${p}" | grep -Fn "$${hunk}" | cut -d: -f1`;
# XXX: use line information from hunk to avoid "not detected" for ambiguity
version_diff = \
	@for p in $(1); do \
	  set `echo "$${p}" | tr '-' ' '`; \
	  echo "\#\#\# *-$$2.rng vs. predecessor"; \
	  for v in *-$$2.rng; do \
	    echo "\#\#\#\# $${v} vs. predecessor"; b=`echo "$${v}" | cut -d- -f1`; \
	    old=`./best-match.sh $${b} $$1`; \
	    p=`diff -u "$${old}" "$${v}" 2>/dev/null`; \
	    case $$? in \
	    1) echo "$${p}" | sed -n -e '/^@@ /!d;=;p' \
	       -e ':l;n;/^\([- ]\|+.*<[^ />]\+\([^/>]\+="ID\|>$$\)\)/bl;s/^[+ ]\(.*\)/\1/p' \
	       | while read hline; do \
	           read h && read i || break; \
	           iline=`grep -Fn "$${i}" "$${v}" | cut -d: -f1`; \
	           ctxt="(not detected)"; \
	           if test `echo "$${iline}" | wc -l` -eq 1; then \
	             ctxt=`{ sed -n -e "1,$$(($${iline}-1))p" "$${v}"; \
	                     echo "<inject id=\"GOAL\"/>$${i}"; \
	                     sed -n -e "$$(($${iline}+1)),$$ p" "$${v}"; \
	                   } | $(XSLTPROC) --param skip 1 context-of.xsl -`; \
	           fi; \
	           echo "$${p}" | sed -n -e "$$(($${hline}-2)),$${hline}!d" \
	             -e '/^\(+++\|---\)/p'; \
	           echo "$${h} context: $${ctxt}"; \
	           echo "$${p}" | sed -n -e "1,$${hline}d" \
	             -e '/^\(---\|@@ \)/be;p;d;:e;n;be'; \
	           done; \
	       ;; \
	    2) echo "\#\#\#\#\# $${v} has no predecessor";; \
	    esac; \
	  done; \
	done

diff: best-match.sh
	@echo "#  Comparing changes in + since $(RNG_max)"
	$(call version_diff,${RNG_version_pairs_last})

fulldiff: best-match.sh
	@echo "#  Comparing all changes across all the subsequent increments"
	$(call version_diff,${RNG_version_pairs})

sync:
	git rm -f $(wildcard *-next.rng)
	make pacemaker-next.rng

CLEANFILES = $(RNG_generated)
