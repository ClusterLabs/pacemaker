#
# Copyright 2023 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/tap.mk
include $(top_srcdir)/mk/unittest.mk

CFLAGS += -DPCMK__TEST_SCHEMA_DIR='"$(abs_builddir)/schemas"'

# Add "_test" to the end of all test program names to simplify .gitignore.

# These tests share a schema subdirectory
SHARED_SCHEMA_TESTS =	crm_schema_init_test			\
			get_schema_name_test			\
			get_schema_version_test			\
			pcmk__build_schema_xml_node_test	\
			pcmk__schema_files_later_than_test

# This test has its own schema directory
FIND_X_0_SCHEMA_TEST =	pcmk__find_x_0_schema_index_test

check_PROGRAMS =	$(SHARED_SCHEMA_TESTS) $(FIND_X_0_SCHEMA_TEST)

TESTS = $(check_PROGRAMS)

$(SHARED_SCHEMA_TESTS): setup-schema-dir

$(FIND_X_0_SCHEMA_TEST): setup-find_x_0-schema-dir

# Set up a temporary schemas/ directory containing only some of the full set of
# pacemaker schema files.  This lets us know exactly how many schemas are present,
# allowing us to write tests without having to make changes when new schemas are
# added.
#
# This directory contains the following:
#
# * pacemaker-next.rng   - Used to verify that this sorts before all versions
# * upgrade-*.xsl        - Required by various schema versions
# * pacemaker-[0-9]*.rng - We're only pulling in 15 schemas, which is enough
#                          to get everything through pacemaker-3.0.rng.  This
#                          includes 2.10, needed so we can check that versions
#                          are compared as numbers instead of strings.
# * other RNG files      - This catches everything except the pacemaker-*rng
#                          files.  These files are included by the top-level
#                          pacemaker-*rng files, so we need them for tests.
#                          This will glob more than we need, but the extra ones
#                          won't get in the way.

LINK_SOURCES =	$(abs_top_builddir)/xml/pacemaker-next.rng	\
		$(abs_top_builddir)/xml/upgrade-*.xsl
ROOT_RNGS = 	$(shell ls -1v $(abs_top_builddir)/xml/pacemaker-[0-9]*.rng | head -15)
INCLUDED_RNGS = $(shell ls -1 $(top_srcdir)/xml/*.rng | grep -v pacemaker-[0-9])

# Most tests share a common, read-only schema directory
.PHONY: setup-schema-dir
setup-schema-dir:
	$(MKDIR_P) schemas
	( cd schemas ; \
	  ln -sf $(LINK_SOURCES) . ; \
	  for f in $(ROOT_RNGS); do \
		ln -sf $$f $$(basename $$f); \
	  done ; \
	  for f in $(INCLUDED_RNGS); do \
		ln -sf ../$$f $$(basename $$f); \
	  done )

# pcmk__find_x_0_schema_index_test moves schema files around, so it needs its
# own directory, otherwise other tests run in parallel could fail.
.PHONY: setup-find_x_0-schema-dir
setup-find_x_0-schema-dir:
	$(MKDIR_P) schemas/find_x_0
	( cd schemas/find_x_0 ; \
	  ln -sf $(LINK_SOURCES) . ; \
	  for f in $(ROOT_RNGS); do \
		ln -sf $$f $$(basename $$f); \
	  done ; \
	  for f in $(INCLUDED_RNGS); do \
		ln -sf ../$$f $$(basename $$f); \
	  done )

.PHONY: clean-local
clean-local:
	-rm -rf schemas
