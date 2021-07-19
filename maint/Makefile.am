#
# Copyright 2019-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

TESTCC_TARGETS          = testcc_common_acl_h testcc_common_ipc_h \
    testcc_common_iso8601_h testcc_common_mainloop_h testcc_common_nvpair_h \
    testcc_common_results_h testcc_common_util_h testcc_common_xml_h \
    testcc_compatibility_h testcc_pengine_common_h testcc_pengine_complex_h \
    testcc_pe_types_h testcc_cib_types_h testcc_cib_util_h testcc_crm_h \
    testcc_cib_h testcc_cluster_h testcc_lrmd_h testcc_msg_xml_h \
    testcc_services_h testcc_stonith_ng_h testcc_pengine_status_h \
    testcc_pengine_rules_h testcc_common_logging_h
CLEANFILES		= $(TESTCC_TARGETS) testcc_helper.cc

noinst_SCRIPTS		= bumplibs

EXTRA_PROGRAMS		= $(TESTCC_TARGETS)
EXTRA_DIST		= README

testcc_helper.cc:
	echo "int main() { return 0; }" > $@

nodist_testcc_common_acl_h_SOURCES = testcc_helper.cc
testcc_common_acl_h_CXXFLAGS = -include "crm/common/acl.h"

nodist_testcc_common_ipc_h_SOURCES = testcc_helper.cc
testcc_common_ipc_h_CXXFLAGS = -include "crm/common/ipc.h"

nodist_testcc_common_iso8601_h_SOURCES = testcc_helper.cc
testcc_common_iso8601_h_CXXFLAGS = -include "crm/common/iso8601.h"

nodist_testcc_common_mainloop_h_SOURCES = testcc_helper.cc
testcc_common_mainloop_h_CXXFLAGS = -include "crm/common/mainloop.h"

nodist_testcc_common_nvpair_h_SOURCES = testcc_helper.cc
testcc_common_nvpair_h_CXXFLAGS = -include "crm/common/nvpair.h"

nodist_testcc_common_results_h_SOURCES = testcc_helper.cc
testcc_common_results_h_CXXFLAGS = -include "crm/common/results.h"

nodist_testcc_common_util_h_SOURCES = testcc_helper.cc
testcc_common_util_h_CXXFLAGS = -include "crm/common/util.h"

nodist_testcc_common_xml_h_SOURCES = testcc_helper.cc
testcc_common_xml_h_CXXFLAGS = -include "crm/common/xml.h"

nodist_testcc_compatibility_h_SOURCES = testcc_helper.cc
testcc_compatibility_h_CXXFLAGS = -include "crm/compatibility.h"

nodist_testcc_pengine_common_h_SOURCES = testcc_helper.cc
testcc_pengine_common_h_CXXFLAGS = -include "crm/pengine/common.h"

nodist_testcc_pengine_complex_h_SOURCES = testcc_helper.cc
testcc_pengine_complex_h_CXXFLAGS = -include "crm/pengine/complex.h"

nodist_testcc_pe_types_h_SOURCES = testcc_helper.cc
testcc_pe_types_h_CXXFLAGS = -include "crm/pengine/pe_types.h"

nodist_testcc_cib_types_h_SOURCES = testcc_helper.cc
testcc_cib_types_h_CXXFLAGS = -include "crm/cib/cib_types.h"

nodist_testcc_cib_util_h_SOURCES = testcc_helper.cc
testcc_cib_util_h_CXXFLAGS = -include "crm/cib/util.h"

nodist_testcc_common_logging_h_SOURCES = testcc_helper.cc
testcc_common_logging_h_CXXFLAGS = -include "crm/common/logging.h"

# ones previously in testcc.cc except election.h not packaged

nodist_testcc_crm_h_SOURCES = testcc_helper.cc
testcc_crm_h_CXXFLAGS = -include "crm/crm.h"

nodist_testcc_cib_h_SOURCES = testcc_helper.cc
testcc_cib_h_CXXFLAGS = -include "crm/cib.h"

nodist_testcc_cluster_h_SOURCES = testcc_helper.cc
testcc_cluster_h_CXXFLAGS = -include "crm/cluster.h"

nodist_testcc_lrmd_h_SOURCES = testcc_helper.cc
testcc_lrmd_h_CXXFLAGS = -include "crm/lrmd.h"

nodist_testcc_msg_xml_h_SOURCES = testcc_helper.cc
testcc_msg_xml_h_CXXFLAGS = -include "crm/msg_xml.h"

nodist_testcc_services_h_SOURCES = testcc_helper.cc
testcc_services_h_CXXFLAGS = -include "crm/services.h"

nodist_testcc_stonith_ng_h_SOURCES = testcc_helper.cc
testcc_stonith_ng_h_CXXFLAGS = -include "crm/stonith-ng.h"

nodist_testcc_pengine_status_h_SOURCES = testcc_helper.cc
testcc_pengine_status_h_CXXFLAGS = -include "crm/pengine/status.h"

nodist_testcc_pengine_rules_h_SOURCES = testcc_helper.cc
testcc_pengine_rules_h_CXXFLAGS = -include "crm/pengine/rules.h"

# c++-headers but not packaged
# daemons/controld/controld_membership.h
# include/crm/pengine/remote_internal.h
# include/crm/common/cmdline_internal.h
# include/crm/common/output.h
# include/crm/common/ipcs_internal.h
# include/crm/common/attrd_internal.h
# include/pacemaker.h
# include/pcmki/pcmki_output.h
# include/pcmki/pcmki_transition.h
# include/crm/cluster/election.h
# lib/gnu/md5.h
# tools/crm_resource_controller.h

testcc: $(TESTCC_TARGETS)
