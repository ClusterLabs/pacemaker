#
# Copyright (C) 2004 Andrew Beekhof
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
MAINTAINERCLEANFILES    = Makefile.in

# Pacemaker 1.1 has 2 schemas: the CIB schema, and a schema for
# crm_mon --as-xml.
#
# See Readme.md for details on updating CIB schema files

# The CIB and crm_mon schemas are installed directly in CRM_DTD_DIRECTORY.
CIBdir	= $(CRM_DTD_DIRECTORY)
MONdir	= $(CRM_DTD_DIRECTORY)

# Extract a sorted list of available numeric schema versions
# from filenames like NAME-MAJOR[.MINOR][.MINOR-MINOR].rng
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

# Names of CIB schemas that form the choices for cib/configuration content
CIB_cfg_base		= options nodes resources constraints fencing acls tags alerts

# Names of all schemas (including top level and those included by others)
CIB_base		= cib $(CIB_cfg_base) status score rule nvset

# All static schema files
CIB_files		= $(foreach base,$(CIB_base),$(wildcard $(srcdir)/$(base).rng $(srcdir)/$(base)-*.rng))
MON_files		= crm_mon.rng

# Sorted lists of all numeric schema versions
CIB_numeric_versions	= $(call numeric_versions,${CIB_files})

# The highest numeric schema version
CIB_max			?= $(lastword $(CIB_numeric_versions))

# Sorted lists of all schema versions (including "next")
CIB_versions		= next $(CIB_numeric_versions)

# Dynamically generated schema files
CIB_generated		= pacemaker.rng $(foreach base,$(CIB_versions),pacemaker-$(base).rng) versions.rng

CIB_version_pairs	= $(call version_pairs,${CIB_numeric_versions})
CIB_version_pairs_cnt	= $(words ${CIB_version_pairs})
CIB_version_pairs_last  = $(call version_pairs_last,${CIB_version_pairs_cnt},${CIB_version_pairs})

dist_CIB_DATA		= $(CIB_files)					\
			  upgrade06.xsl					\
			  upgrade-1.3.xsl				\
			  crm.dtd					\
			  crm-transitional.dtd
dist_MON_DATA		= $(MON_files)

nodist_CIB_DATA		= $(CIB_generated)

EXTRA_DIST		= Readme.md			\
			  best-match.sh			\
			  context-of.xsl		\
			  ocf-meta2man.xsl		\
			  regression.core.sh		\
			  regression.sh

cib-versions:
	@echo "Max: $(CIB_max)"
	@echo "Available: $(CIB_versions)"


# Dynamically generated top-level CIB schema
pacemaker.rng: pacemaker-$(CIB_max).rng
	echo "  RNG      $@"
	cp $(top_builddir)/xml/$< $@

pacemaker-%.rng: $(CIB_files) best-match.sh Makefile.am
	echo "  RNG      $@"
	echo '<?xml version="1.0" encoding="UTF-8"?>' > $@
	echo '<grammar xmlns="http://relaxng.org/ns/structure/1.0" datatypeLibrary="http://www.w3.org/2001/XMLSchema-datatypes">' >> $@
	echo '  <start>' >> $@
	echo '    <element name="cib">' >> $@
	$(srcdir)/best-match.sh cib $(*) $(@) "      "
	echo '      <element name="configuration">' >> $@
	echo '        <interleave>' >> $@
	for rng in $(CIB_cfg_base); do $(srcdir)/best-match.sh $$rng $(*) $(@) "          " || :; done
	echo '        </interleave>' >> $@
	echo '      </element>' >> $@
	echo '      <optional>' >> $@
	echo '        <element name="status">' >> $@
	$(srcdir)/best-match.sh status $(*) $(@) "          "
	echo '        </element>' >> $@
	echo '      </optional>' >> $@
	echo '    </element>' >> $@
	echo '  </start>' >> $@
	echo '</grammar>' >> $@

# Dynamically generated CIB schema listing all pacemaker versions
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
	for rng in $(CIB_versions); do echo "          <value>pacemaker-$$rng</value>" >> $@; done
	echo '        </choice>' >> $@
	echo '      </attribute>' >> $@
	echo '    </optional>' >> $@
	echo '    <attribute name="admin_epoch"><data type="nonNegativeInteger"/></attribute>' >> $@
	echo '    <attribute name="epoch"><data type="nonNegativeInteger"/></attribute>' >> $@
	echo '    <attribute name="num_updates"><data type="nonNegativeInteger"/></attribute>' >> $@
	echo '   </interleave>' >> $@
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
	@echo "#  Comparing changes in + since $(CIB_max)"
	$(call version_diff,${CIB_version_pairs_last})

fulldiff: best-match.sh
	@echo "#  Comparing all changes across all the subsequent increments"
	$(call version_diff,${CIB_version_pairs})

CLEANFILES = $(CIB_generated)
