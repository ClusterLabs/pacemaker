#
# Copyright 2004-2026 the Pacemaker project contributors
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

# The CIB and crm_mon schemas are installed directly in PCMK_SCHEMA_DIR
# for historical reasons, while the API schema is installed in a subdirectory.
APIdir	= $(PCMK_SCHEMA_DIR)/api
CIBdir	= $(PCMK_SCHEMA_DIR)
MONdir	= $(PCMK_SCHEMA_DIR)

basexsltdir		= $(PCMK_SCHEMA_DIR)/base
dist_basexslt_DATA	= $(srcdir)/base/access-render-2.xsl

# Extract a sorted list of available numeric schema versions
# from filenames like NAME-MAJOR[.MINOR][.MINOR-MINOR].rng
numeric_versions = $(shell ls -1 $(1) \
			  | sed -n -e 's/^.*-\([0-9][0-9.]*\).rng$$/\1/p' \
			  | sort -u -t. -k 1,1n -k 2,2n -k 3,3n)

version_pairs = $(join \
			    $(1),$(addprefix \
			      -,$(wordlist \
			        2,$(words $(1)),$(1) \
			      ) \
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
API_request_base = cibadmin
API_request_base += cibsecret
API_request_base += command-output
API_request_base += crm_attribute
API_request_base += crm_diff
API_request_base += crm_error
API_request_base += crm_mon
API_request_base += crm_node
API_request_base += crm_resource
API_request_base += crm_rule
API_request_base += crm_shadow
API_request_base += crm_simulate
API_request_base += crm_ticket
API_request_base += crmadmin
API_request_base += digests
API_request_base += iso8601
API_request_base += pacemakerd
API_request_base += stonith_admin
API_request_base += version

# Names of CIB schemas that form the choices for cib/configuration content
CIB_cfg_base = options
CIB_cfg_base += nodes
CIB_cfg_base += resources
CIB_cfg_base += constraints
CIB_cfg_base += fencing
CIB_cfg_base += acls
CIB_cfg_base += tags
CIB_cfg_base += alerts

# Names of all schemas (including top level and those included by others)
API_base = $(API_request_base)
API_base += any-element
API_base += failure
API_base += fence-event
API_base += generic-list
API_base += instruction
API_base += item
API_base += node-attrs
API_base += node-history
API_base += nodes
API_base += ocf-ra
API_base += options
API_base += patchset
API_base += resources
API_base += status
API_base += subprocess-output
API_base += ticket

CIB_base = cib
CIB_base += $(CIB_cfg_base)
CIB_base += status
CIB_base += score
CIB_base += rule
CIB_base += nvset

# Static schema files and transforms (only CIB has transforms)
#
# This is more complicated than it should be due to the need to support
# VPATH builds and "make distcheck". We need the absolute paths for reliable
# substitution back and forth, and relative paths for distributed files.
API_abs_files		= $(foreach base,$(API_base),$(wildcard $(abs_srcdir)/api/$(base)-*.rng))
CIB_abs_files		= $(foreach base,$(CIB_base),$(wildcard $(abs_srcdir)/$(base).rng $(abs_srcdir)/$(base)-*.rng))
CIB_abs_xsl = $(abs_srcdir)/upgrade-1.3-0.xsl
CIB_abs_xsl += $(wildcard $(abs_srcdir)/upgrade-2.10-[0-2].xsl)
CIB_abs_xsl += $(wildcard $(abs_srcdir)/upgrade-3.10-*.xsl)
MON_abs_files 		= $(abs_srcdir)/crm_mon.rng
API_files		= $(foreach base,$(API_base),$(wildcard $(srcdir)/api/$(base)-*.rng))
CIB_files		= $(foreach base,$(CIB_base),$(wildcard $(srcdir)/$(base).rng $(srcdir)/$(base)-*.rng))
CIB_xsl = $(srcdir)/upgrade-1.3-0.xsl
CIB_xsl += $(wildcard $(srcdir)/upgrade-2.10-[0-2].xsl)
CIB_xsl += $(wildcard $(srcdir)/upgrade-3.10-*.xsl)
MON_files 		= $(srcdir)/crm_mon.rng

# Sorted lists of all schema versions
API_versions	= $(call numeric_versions,${API_files})
CIB_versions	= $(call numeric_versions,${CIB_files})
MON_versions 	= $(call numeric_versions,$(wildcard $(srcdir)/api/crm_mon*.rng))

# The highest numeric schema version
API_max			?= $(lastword $(API_versions))
CIB_max			?= $(lastword $(CIB_versions))
MON_max 		?= $(lastword $(MON_versions))

# Build tree locations of static schema files and transforms (for VPATH builds)
API_build_copies	= $(foreach f,$(API_abs_files),$(subst $(abs_srcdir),$(abs_builddir),$(f)))
CIB_build_copies	= $(foreach f,$(CIB_abs_files) $(CIB_abs_xsl),$(subst $(abs_srcdir),$(abs_builddir),$(f)))
MON_build_copies 	= $(foreach f,$(MON_abs_files),$(subst $(abs_srcdir),$(abs_builddir),$(f)))

# Dynamically generated schema files
API_generated		= api/api-result.rng $(foreach base,$(API_versions),api/api-result-$(base).rng)
CIB_generated = pacemaker.rng
CIB_generated += $(foreach base,$(CIB_versions),pacemaker-$(base).rng)
CIB_generated += versions.rng
MON_generated 		= crm_mon.rng

CIB_version_pairs	= $(call version_pairs,${CIB_versions})
CIB_version_pairs_cnt	= $(words ${CIB_version_pairs})
CIB_version_pairs_last  = $(call version_pairs_last,${CIB_version_pairs_cnt},${CIB_version_pairs})

dist_API_DATA		= $(API_files)
dist_CIB_DATA = $(CIB_files)
dist_CIB_DATA += $(CIB_xsl)

nodist_API_DATA		= $(API_generated)
nodist_CIB_DATA		= $(CIB_generated)
nodist_MON_DATA		= $(MON_generated)

EXTRA_DIST = README.md
EXTRA_DIST += cibtr-2.rng
EXTRA_DIST += context-of.xsl
EXTRA_DIST += rng-helper
EXTRA_DIST += ocf-meta2man.xsl
EXTRA_DIST += upgrade-detail.xsl
EXTRA_DIST += xslt_cibtr-2.rng

.PHONY: cib-versions
cib-versions:
	@echo "Max: $(CIB_max)"
	@echo "Available: $(CIB_versions)"

.PHONY: api-versions
api-versions:
	@echo "Max: $(API_max)"
	@echo "Available: $(API_versions)"

# Dynamically generated top-level API schema
api/api-result.rng: api/api-result-$(API_max).rng
	$(AM_V_at)$(MKDIR_P) api # might not exist in VPATH build
	$(AM_V_SCHEMA)cp $(top_builddir)/xml/$< $@

api/api-result-%.rng: $(API_build_copies) rng-helper Makefile.am
	$(AM_V_SCHEMA)$(builddir)/rng-helper build_api_rng "$@" "$*" \
		$(API_request_base)

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

pacemaker-%.rng: $(CIB_build_copies) rng-helper Makefile.am
	$(AM_V_SCHEMA)$(builddir)/rng-helper build_cib_rng "$@" "$*" \
		$(CIB_cfg_base)

# Dynamically generated CIB schema listing all pacemaker versions
#
# @COMPAT "none" is deprecated since 2.1.8
versions.rng: pacemaker-$(CIB_max).rng Makefile.am
	$(AM_V_at)echo '<?xml version="1.0" encoding="UTF-8"?>' > $@
	$(AM_V_at)echo '<grammar xmlns="http://relaxng.org/ns/structure/1.0" datatypeLibrary="http://www.w3.org/2001/XMLSchema-datatypes">' >> $@
	$(AM_V_at)echo '  <start>' >> $@
	$(AM_V_at)echo '    <group>' >> $@
	$(AM_V_at)echo '      <attribute name="validate-with">' >> $@
	$(AM_V_at)echo '        <choice>' >> $@
	$(AM_V_at)echo '          <value>none</value>' >> $@
	$(AM_V_at)for rng in $(CIB_versions); do echo "          <value>pacemaker-$$rng</value>" >> $@; done
	$(AM_V_at)echo '        </choice>' >> $@
	$(AM_V_at)echo '      </attribute>' >> $@
	$(AM_V_at)echo '      <attribute name="admin_epoch"><data type="nonNegativeInteger"/></attribute>' >> $@
	$(AM_V_at)echo '      <attribute name="epoch"><data type="nonNegativeInteger"/></attribute>' >> $@
	$(AM_V_at)echo '      <attribute name="num_updates"><data type="nonNegativeInteger"/></attribute>' >> $@
	$(AM_V_at)echo '    </group>' >> $@
	$(AM_V_at)echo '  </start>' >> $@
	$(AM_V_SCHEMA)echo '</grammar>' >> $@

schemas:
	@if [ -z "$$SCHEMAS" ]; then \
		ls *.rng; \
		ls *.rng | sort -V | awk 'gsub("-[0-9.]+.rng", ""){if (last != $$0) {print; last=$$0} }'; \
		printf "\nusage: make schemas SCHEMAS=\"<schema1 schema2 ...>\" [NEW_VERSION=\"<new-version>\"]\n \
			\nNot specifying NEW_VERSION will increase the last field of the newest version of the schema(s).\n"; \
	else \
		if [ -z "$$NEW_VERSION" ]; then \
			OLD_VERSION=$$(ls *[0-9].rng | awk -F'-' 'gsub(".rng$$", "") {print $$NF}' | sort -Vu | tail -1); \
			lf=$$(echo "$$OLD_VERSION" | awk -F"." '{print $$NF}'); \
			! echo "$$lf" | grep -q "^[[:digit:]]\+$$" && echo "Unable to detect version. Use NEW_VERSION= to specify version." && exit 1; \
			lf=$$((lf+1)); \
			NEW_VERSION=$$(echo "$$OLD_VERSION" | sed "s/[0-9]\+$$/$$lf/"); \
		fi; \
		for schema in $$SCHEMAS; do \
			old_schema=$$(ls $$schema-[0-9]*.rng | sort -V | tail -1); \
			new_schema=$$schema-$$NEW_VERSION.rng; \
			echo "Copying $$old_schema to $$new_schema"; \
			cp -n "$$old_schema" "$$new_schema"; \
		done \
	fi


.PHONY: diff
diff: rng-helper
	@echo "#  Comparing changes in + since $(CIB_max)"
	@$(builddir)/rng-helper diff ${CIB_version_pairs_last}

.PHONY: fulldiff
fulldiff: rng-helper
	@echo "#  Comparing all changes across all the subsequent increments"
	@$(builddir)/rng-helper diff ${CIB_version_pairs}

CLEANFILES = $(API_generated)
CLEANFILES += $(CIB_generated)
CLEANFILES += $(MON_generated)

# Remove pacemaker schema files generated by *any* source version. This allows
# "make -C xml clean" to have the desired effect when checking out an earlier
# revision in a source tree.
.PHONY: clean-local
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
