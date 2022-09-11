#
# Copyright 2004-2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk

noarch_pkgconfig_DATA	= $(builddir)/pacemaker-schemas.pc

# Pacemaker has 3 schemas: the CIB schema, the API schema (for command-line
# tool XML output), and a legacy schema for crm_mon --as-xml.
#
# See README.md for details on updating CIB schema files (API is similar)

# The CIB and crm_mon schemas are installed directly in CRM_SCHEMA_DIRECTORY
# for historical reasons, while the API schema is installed in a subdirectory.
APIdir	= $(CRM_SCHEMA_DIRECTORY)/api
CIBdir	= $(CRM_SCHEMA_DIRECTORY)
MONdir	= $(CRM_SCHEMA_DIRECTORY)

basexsltdir		= $(CRM_SCHEMA_DIRECTORY)/base
dist_basexslt_DATA	= $(srcdir)/base/access-render-2.xsl

# Extract a sorted list of available numeric schema versions
# from filenames like NAME-MAJOR[.MINOR][.MINOR-MINOR].rng
numeric_versions = $(shell ls -1 $(1) \
			  | sed -n -e 's/^.*-\([0-9][0-9.]*\).rng$$/\1/p' \
			  | sort -u -t. -k 1,1n -k 2,2n -k 3,3n)

# @COMPAT: pacemaker-next is deprecated since 2.1.5
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

# NOTE: All files in API_request_base, CIB_cfg_base, API_base, and CIB_base
# need to start with a unique prefix.  These variables all get iterated over
# and globbed, and two files starting with the same prefix will cause
# problems.

# Names of API schemas that form the choices for pacemaker-result content
API_request_base	= command-output	\
			  crm_attribute 	\
			  crm_mon		\
			  crm_resource		\
			  crm_rule \
			  crm_simulate		\
			  crmadmin		\
			  digests		\
			  pacemakerd 		\
			  stonith_admin		\
			  version

# Names of CIB schemas that form the choices for cib/configuration content
CIB_cfg_base		= options nodes resources constraints fencing acls tags alerts

# Names of all schemas (including top level and those included by others)
API_base		= $(API_request_base)	\
			  failure		\
			  fence-event 		\
			  generic-list		\
			  item			\
			  node-attrs		\
			  node-history		\
			  nodes			\
			  resources		\
			  status		\
			  subprocess-output
CIB_base		= cib $(CIB_cfg_base) status score rule nvset

# Static schema files and transforms (only CIB has transforms)
# 
# This is more complicated than it should be due to the need to support
# VPATH builds and "make distcheck". We need the absolute paths for reliable
# substitution back and forth, and relative paths for distributed files.
API_abs_files		= $(foreach base,$(API_base),$(wildcard $(abs_srcdir)/api/$(base)-*.rng))
CIB_abs_files		= $(foreach base,$(CIB_base),$(wildcard $(abs_srcdir)/$(base).rng $(abs_srcdir)/$(base)-*.rng))
CIB_abs_xsl		= $(abs_srcdir)/upgrade-1.3.xsl			\
			  $(abs_srcdir)/upgrade-2.10.xsl		\
			  $(wildcard $(abs_srcdir)/upgrade-*enter.xsl)	\
			  $(wildcard $(abs_srcdir)/upgrade-*leave.xsl)
MON_abs_files 		= $(abs_srcdir)/crm_mon.rng
API_files		= $(foreach base,$(API_base),$(wildcard $(srcdir)/api/$(base)-*.rng))
CIB_files		= $(foreach base,$(CIB_base),$(wildcard $(srcdir)/$(base).rng $(srcdir)/$(base)-*.rng))
CIB_xsl			= $(srcdir)/upgrade-1.3.xsl			\
			  $(srcdir)/upgrade-2.10.xsl		\
			  $(wildcard $(srcdir)/upgrade-*enter.xsl)	\
			  $(wildcard $(srcdir)/upgrade-*leave.xsl)
MON_files 		= $(srcdir)/crm_mon.rng

# Sorted lists of all numeric schema versions
API_numeric_versions	= $(call numeric_versions,${API_files})
CIB_numeric_versions	= $(call numeric_versions,${CIB_files})
MON_numeric_versions 	= $(call numeric_versions,$(wildcard $(srcdir)/api/crm_mon*.rng))

# The highest numeric schema version
API_max			?= $(lastword $(API_numeric_versions))
CIB_max			?= $(lastword $(CIB_numeric_versions))
MON_max 			?= $(lastword $(MON_numeric_versions))

# Sorted lists of all schema versions (including "next")
# @COMPAT: pacemaker-next is deprecated since 2.1.5
API_versions		= next $(API_numeric_versions)
CIB_versions		= next $(CIB_numeric_versions)

# Build tree locations of static schema files and transforms (for VPATH builds)
API_build_copies	= $(foreach f,$(API_abs_files),$(subst $(abs_srcdir),$(abs_builddir),$(f)))
CIB_build_copies	= $(foreach f,$(CIB_abs_files) $(CIB_abs_xsl),$(subst $(abs_srcdir),$(abs_builddir),$(f)))
MON_build_copies 	= $(foreach f,$(MON_abs_files),$(subst $(abs_srcdir),$(abs_builddir),$(f)))

# Dynamically generated schema files
API_generated		= api/api-result.rng $(foreach base,$(API_versions),api/api-result-$(base).rng)
CIB_generated		= pacemaker.rng $(foreach base,$(CIB_versions),pacemaker-$(base).rng) versions.rng
MON_generated 		= crm_mon.rng

CIB_version_pairs	= $(call version_pairs,${CIB_numeric_versions})
CIB_version_pairs_cnt	= $(words ${CIB_version_pairs})
CIB_version_pairs_last  = $(call version_pairs_last,${CIB_version_pairs_cnt},${CIB_version_pairs})

dist_API_DATA		= $(API_files)
dist_CIB_DATA		= $(CIB_files) $(CIB_xsl)

nodist_API_DATA		= $(API_generated)
nodist_CIB_DATA		= $(CIB_generated)
nodist_MON_DATA		= $(MON_generated)

EXTRA_DIST		= README.md			\
			  best-match.sh			\
			  cibtr-2.rng			\
			  context-of.xsl		\
			  ocf-meta2man.xsl		\
			  regression.sh			\
			  upgrade-2.10-roundtrip.xsl	\
			  upgrade-detail.xsl		\
			  xslt_cibtr-2.rng		\
			  assets			\
			  test-2			\
			  test-2-enter			\
			  test-2-leave			\
			  test-2-roundtrip

cib-versions:
	@echo "Max: $(CIB_max)"
	@echo "Available: $(CIB_versions)"

api-versions:
	@echo "Max: $(API_max)"
	@echo "Available: $(API_versions)"

# Dynamically generated top-level API schema
api/api-result.rng: api/api-result-$(API_max).rng
	$(AM_V_at)$(MKDIR_P) api # might not exist in VPATH build
	$(AM_V_SCHEMA)cp $(top_builddir)/xml/$< $@

api/api-result-%.rng: $(API_build_copies) best-match.sh Makefile.am
	$(AM_V_at)echo '<?xml version="1.0" encoding="UTF-8"?>' > $@
	$(AM_V_at)echo '<grammar xmlns="http://relaxng.org/ns/structure/1.0" datatypeLibrary="http://www.w3.org/2001/XMLSchema-datatypes">' >> $@
	$(AM_V_at)echo '  <start>' >> $@
	$(AM_V_at)echo '    <element name="pacemaker-result">' >> $@
	$(AM_V_at)echo '      <attribute name="api-version"> <text /> </attribute>' >> $@
	$(AM_V_at)echo '      <attribute name="request"> <text /> </attribute>' >> $@
	$(AM_V_at)echo '      <optional>' >> $@
	$(AM_V_at)echo '        <choice>' >> $@
	$(AM_V_at)for rng in $(API_request_base); do $(srcdir)/best-match.sh api/$$rng $(*) $(@) "          " || :; done
	$(AM_V_at)echo '        </choice>' >> $@
	$(AM_V_at)echo '      </optional>' >> $@
	$(AM_V_at)$(srcdir)/best-match.sh api/status $(*) $(@) "      " || :
	$(AM_V_at)echo '    </element>' >> $@
	$(AM_V_at)echo '  </start>' >> $@
	$(AM_V_SCHEMA)echo '</grammar>' >> $@

crm_mon.rng: api/crm_mon-$(MON_max).rng
	$(AM_V_at)echo '<?xml version="1.0" encoding="UTF-8"?>' > $@
	$(AM_V_at)echo '<grammar xmlns="http://relaxng.org/ns/structure/1.0"' >> $@
	$(AM_V_at)echo '         datatypeLibrary="http://www.w3.org/2001/XMLSchema-datatypes">' >> $@
	$(AM_V_at)echo '    <start>' >> $@
	$(AM_V_at)echo '        <ref name="element-crm_mon-old"/>' >> $@
	$(AM_V_at)echo '    </start>' >> $@
	$(AM_V_at)echo '    <define name="element-crm_mon-old">' >> $@
	$(AM_V_at)echo '        <element name="crm_mon">' >> $@
	$(AM_V_at)echo '            <attribute name="version"> <text/> </attribute>' >> $@
	$(AM_V_at)echo '            <externalRef href="$(<)" />' >> $@
	$(AM_V_at)echo '        </element>' >> $@
	$(AM_V_at)echo '    </define>' >> $@
	$(AM_V_SCHEMA)echo '</grammar>' >> $@

# Dynamically generated top-level CIB schema
pacemaker.rng: pacemaker-$(CIB_max).rng
	$(AM_V_SCHEMA)cp $(top_builddir)/xml/$< $@

pacemaker-%.rng: $(CIB_build_copies) best-match.sh Makefile.am
	$(AM_V_at)echo '<?xml version="1.0" encoding="UTF-8"?>' > $@
	$(AM_V_at)echo '<grammar xmlns="http://relaxng.org/ns/structure/1.0" datatypeLibrary="http://www.w3.org/2001/XMLSchema-datatypes">' >> $@
	$(AM_V_at)echo '  <start>' >> $@
	$(AM_V_at)echo '    <element name="cib">' >> $@
	$(AM_V_at)$(srcdir)/best-match.sh cib $(*) $(@) "      "
	$(AM_V_at)echo '      <element name="configuration">' >> $@
	$(AM_V_at)echo '        <interleave>' >> $@
	$(AM_V_at)for rng in $(CIB_cfg_base); do $(srcdir)/best-match.sh $$rng $(*) $(@) "          " || :; done
	$(AM_V_at)echo '        </interleave>' >> $@
	$(AM_V_at)echo '      </element>' >> $@
	$(AM_V_at)echo '      <optional>' >> $@
	$(AM_V_at)echo '        <element name="status">' >> $@
	$(AM_V_at)$(srcdir)/best-match.sh status $(*) $(@) "          "
	$(AM_V_at)echo '        </element>' >> $@
	$(AM_V_at)echo '      </optional>' >> $@
	$(AM_V_at)echo '    </element>' >> $@
	$(AM_V_at)echo '  </start>' >> $@
	$(AM_V_SCHEMA)echo '</grammar>' >> $@

# Dynamically generated CIB schema listing all pacemaker versions
versions.rng: pacemaker-$(CIB_max).rng Makefile.am
	$(AM_V_at)echo '<?xml version="1.0" encoding="UTF-8"?>' > $@
	$(AM_V_at)echo '<grammar xmlns="http://relaxng.org/ns/structure/1.0" datatypeLibrary="http://www.w3.org/2001/XMLSchema-datatypes">' >> $@
	$(AM_V_at)echo '  <start>' >> $@
	$(AM_V_at)echo '   <interleave>' >> $@
	$(AM_V_at)echo '    <optional>' >> $@
	$(AM_V_at)echo '      <attribute name="validate-with">' >> $@
	$(AM_V_at)echo '        <choice>' >> $@
	$(AM_V_at)echo '          <value>none</value>' >> $@
	$(AM_V_at)echo '          <value>pacemaker-0.6</value>' >> $@
	$(AM_V_at)echo '          <value>transitional-0.6</value>' >> $@
	$(AM_V_at)echo '          <value>pacemaker-0.7</value>' >> $@
	$(AM_V_at)echo '          <value>pacemaker-1.1</value>' >> $@
	$(AM_V_at)for rng in $(CIB_versions); do echo "          <value>pacemaker-$$rng</value>" >> $@; done
	$(AM_V_at)echo '        </choice>' >> $@
	$(AM_V_at)echo '      </attribute>' >> $@
	$(AM_V_at)echo '    </optional>' >> $@
	$(AM_V_at)echo '    <attribute name="admin_epoch"><data type="nonNegativeInteger"/></attribute>' >> $@
	$(AM_V_at)echo '    <attribute name="epoch"><data type="nonNegativeInteger"/></attribute>' >> $@
	$(AM_V_at)echo '    <attribute name="num_updates"><data type="nonNegativeInteger"/></attribute>' >> $@
	$(AM_V_at)echo '   </interleave>' >> $@
	$(AM_V_at)echo '  </start>' >> $@
	$(AM_V_SCHEMA)echo '</grammar>' >> $@

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

CLEANFILES = $(API_generated) $(CIB_generated) $(MON_generated)

# Remove pacemaker schema files generated by *any* source version. This allows
# "make -C xml clean" to have the desired effect when checking out an earlier
# revision in a source tree.
clean-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then					\
		rm -f $(API_build_copies) $(CIB_build_copies) $(MON_build_copies);	\
	fi
	rm -f $(builddir)/pacemaker-[0-9]*.[0-9]*.rng

# Enable ability to use $@ in prerequisite
.SECONDEXPANSION:

# For VPATH builds, copy the static schema files into the build tree
$(API_build_copies) $(CIB_build_copies) $(MON_build_copies): $$(subst $(abs_builddir),$(srcdir),$$(@))
	$(AM_V_GEN)if [ "x$(srcdir)" != "x$(builddir)" ]; then	\
		$(MKDIR_P) "$(dir $(@))";			\
		cp "$(<)" "$(@)";				\
	fi
