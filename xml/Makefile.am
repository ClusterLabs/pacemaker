#
# Copyright 2004-2019 the Pacemaker project contributors
#
# The version control history for this file may have further details.
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

APIdir 			= $(CRM_SCHEMA_DIRECTORY)/api
RNGdir			= $(CRM_SCHEMA_DIRECTORY)

xsltdir			= $(RNGdir)
dist_xslt_DATA		= $(top_srcdir)/xml/upgrade-1.3.xsl \
			  $(top_srcdir)/xml/upgrade-2.10.xsl \
			  $(top_srcdir)/xml/upgrade-*enter.xsl \
			  $(top_srcdir)/xml/upgrade-*leave.xsl

noinst_DATA		= context-of.xsl

# See Readme.md for details on updating schema files

# Sorted list of available numeric RNG versions,
# extracted from filenames like NAME-MAJOR[.MINOR][.MINOR-MINOR].rng
numeric_versions = $(shell ls -1 $(1) \
			  | sed -n -e 's/^.*-\([0-9][0-9.]*\).rng$$/\1/p' \
			  | sort -u -t. -k 1,1n -k 2,2n -k 3,3n)

version_pairs = $(join \
			    $(1),$(addprefix \
			      -,$(wordlist \
			        2,$(words $(1)),$(1) \
			      ) next \
			    ) \
			  )

version_pairs_last = $(wordlist \
			    $(words \
			      $(wordlist \
			        2,$(1),$(2) \
			      ) \
			    ),$(1),$(2) \
			  )

API_numeric_versions = $(call numeric_versions,${API_files})
RNG_numeric_versions = $(call numeric_versions,${RNG_files})

# The highest numeric version
API_max 		?= $(lastword $(API_numeric_versions))
RNG_max			?= $(lastword $(RNG_numeric_versions))

# A sorted list of all API and RNG versions (numeric and "next")
API_versions 		= next $(API_numeric_versions)
API_request_base 	= command-output stonith_admin
API_base		= $(API_request_base) item status
API_files 		= $(foreach base,$(API_base),$(wildcard api/$(base)*.rng))

RNG_versions		= next $(RNG_numeric_versions)
RNG_version_pairs	= $(call version_pairs,${RNG_numeric_versions})
RNG_version_pairs_cnt	= $(words ${RNG_version_pairs})
RNG_version_pairs_last  = $(call version_pairs_last,${RNG_version_pairs_cnt},${RNG_version_pairs})

API_generated 		= api/api-result.rng $(foreach base,$(API_versions),api/api-result-$(base).rng)
RNG_generated		= pacemaker.rng $(foreach base,$(RNG_versions),pacemaker-$(base).rng) versions.rng

RNG_cfg_base		= options nodes resources constraints fencing acls tags alerts
RNG_base		= cib $(RNG_cfg_base) status score rule nvset
RNG_files		= $(foreach base,$(RNG_base),$(wildcard $(base).rng $(base)-*.rng))

# List of non-Pacemaker RNGs
RNG_extra		= crm_mon.rng

dist_API_DATA 		= $(API_files)
dist_RNG_DATA		= $(RNG_files) $(RNG_extra)
nodist_API_DATA 	= $(API_generated)
nodist_RNG_DATA		= $(RNG_generated)

EXTRA_DIST		= best-match.sh

versions:
	echo "Max: $(RNG_max)"
	echo "Available: $(RNG_versions)"

api-versions:
	echo "Max: $(API_max)"
	echo "Available: $(API_versions)"

versions.rng: Makefile.am
	echo "  RNG      $@"
	echo '<?xml version="1.0" encoding="UTF-8"?>' > $@
	echo '<grammar xmlns="http://relaxng.org/ns/structure/1.0" datatypeLibrary="http://www.w3.org/2001/XMLSchema-datatypes">' >> $@
	echo '  <start>' >> $@
	echo '   <interleave>' >> $@
	echo '    <optional>' >> $@
	echo '      <attribute name="validate-with">' >> $@
	echo '        <choice>' >> $@
	echo '          <value>none</value>' >> $@
	echo '          <value>pacemaker-0.6</value>' >> $@
	echo '          <value>transitional-0.6</value>' >> $@
	echo '          <value>pacemaker-0.7</value>' >> $@
	echo '          <value>pacemaker-1.1</value>' >> $@
	for rng in $(RNG_versions); do echo "          <value>pacemaker-$$rng</value>" >> $@; done
	echo '        </choice>' >> $@
	echo '      </attribute>' >> $@
	echo '    </optional>' >> $@
	echo '    <attribute name="admin_epoch"><data type="nonNegativeInteger"/></attribute>' >> $@
	echo '    <attribute name="epoch"><data type="nonNegativeInteger"/></attribute>' >> $@
	echo '    <attribute name="num_updates"><data type="nonNegativeInteger"/></attribute>' >> $@
	echo '   </interleave>' >> $@
	echo '  </start>' >> $@
	echo '</grammar>' >> $@

api/api-result.rng: api/api-result-$(API_max).rng
	echo "  RNG      $@"
	cp $(top_builddir)/xml/$< $@

pacemaker.rng: pacemaker-$(RNG_max).rng
	echo "  RNG      $@"
	cp $(top_builddir)/xml/$< $@

api/api-result-%.rng: $(API_files) Makefile.am
	echo "  RNG      $@"
	echo '<?xml version="1.0" encoding="UTF-8"?>' > $@
	echo '<grammar xmlns="http://relaxng.org/ns/structure/1.0" datatypeLibrary="http://www.w3.org/2001/XMLSchema-datatypes">' >> $@
	echo '  <start>' >> $@
	echo '    <element name="pacemaker-result">' >> $@
	echo '      <attribute name="api-version"> <text /> </attribute>' >> $@
	echo '      <attribute name="request"> <text /> </attribute>' >> $@
	echo '      <optional>' >> $@
	echo '        <choice>' >> $@
	for rng in $(API_request_base); do $(top_srcdir)/xml/best-match.sh api/$$rng $(*) $(@) "          " || :; done
	echo '        </choice>' >> $@
	echo '      </optional>' >> $@
	$(top_srcdir)/xml/best-match.sh api/status $(*) $(@) "      " || :
	echo '    </element>' >> $@
	echo '  </start>' >> $@
	echo '</grammar>' >> $@

pacemaker-%.rng: $(RNG_files) best-match.sh Makefile.am
	echo "  RNG      $@"
	echo '<?xml version="1.0" encoding="UTF-8"?>' > $@
	echo '<grammar xmlns="http://relaxng.org/ns/structure/1.0" datatypeLibrary="http://www.w3.org/2001/XMLSchema-datatypes">' >> $@
	echo '  <start>' >> $@
	echo '    <element name="cib">' >> $@
	$(top_srcdir)/xml/best-match.sh cib $(*) $(@) "      "
	echo '      <element name="configuration">' >> $@
	echo '        <interleave>' >> $@
	for rng in $(RNG_cfg_base); do $(top_srcdir)/xml/best-match.sh $$rng $(*) $(@) "          " || :; done
	echo '        </interleave>' >> $@
	echo '      </element>' >> $@
	echo '      <optional>' >> $@
	echo '        <element name="status">' >> $@
	$(top_srcdir)/xml/best-match.sh status $(*) $(@) "          "
	echo '        </element>' >> $@
	echo '      </optional>' >> $@
	echo '    </element>' >> $@
	echo '  </start>' >> $@
	echo '</grammar>' >> $@

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

CLEANFILES = $(API_generated) $(RNG_generated)
