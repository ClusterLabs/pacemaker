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
check_PROGRAMS = get_schema_version_test 		\
		 pcmk__build_schema_xml_node_test 	\
		 pcmk__schema_files_later_than_test 	\
		 pcmk__xml_find_x_0_schema_index_test

TESTS = $(check_PROGRAMS)

$(TESTS): setup-schema-dir

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
.PHONY: setup-schema-dir
setup-schema-dir:
	$(MKDIR_P) schemas
	( cd schemas ; \
	  ln -sf $(abs_top_builddir)/xml/pacemaker-next.rng . ; \
	  ln -sf $(abs_top_builddir)/xml/upgrade-*.xsl . ; \
	  for f in $(shell ls -1v $(abs_top_builddir)/xml/pacemaker-[0-9]*.rng | head -15); do \
		ln -sf $$f $$(basename $$f); \
	  done ; \
	  for f in $(shell ls -1 $(top_srcdir)/xml/*.rng | grep -v pacemaker); do \
		ln -sf ../$$f $$(basename $$f); \
	  done )

.PHONY: clean-local
clean-local:
	-rm -rf schemas
