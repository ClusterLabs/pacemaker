/*
 * Copyright 2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <crm/common/util.h>
#include <crm/common/internal.h>
#include <crm/common/xml.h>

/* A minimal but realistic CIB structure that the patchset will be applied to.
 * This provides enough structure for XPath operations to have meaningful
 * targets (nodes, resources, constraints, status).
 */
static const char *BASE_CIB =
    "<cib admin_epoch=\"1\" epoch=\"1\" num_updates=\"0\">"
    "  <configuration>"
    "    <crm_config>"
    "      <cluster_property_set id=\"cib-bootstrap-options\">"
    "        <nvpair id=\"opt1\" name=\"stonith-enabled\" value=\"false\"/>"
    "      </cluster_property_set>"
    "    </crm_config>"
    "    <nodes>"
    "      <node id=\"node1\" uname=\"pcmk-1\"/>"
    "      <node id=\"node2\" uname=\"pcmk-2\"/>"
    "    </nodes>"
    "    <resources>"
    "      <primitive id=\"rsc1\" class=\"ocf\" provider=\"heartbeat\""
    "                 type=\"Dummy\"/>"
    "    </resources>"
    "    <constraints/>"
    "  </configuration>"
    "  <status/>"
    "</cib>";

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *input = NULL;
    xmlNode *patchset = NULL;
    xmlNode *cib = NULL;

    if (size < 15) {
        return -1;
    }

    // Parse a fresh copy of the base CIB for each iteration
    cib = pcmk__xml_parse(BASE_CIB);
    if (cib == NULL) {
        return 0;
    }

    // Parse the fuzz input as a patchset
    input = pcmk__assert_alloc(size + 1, sizeof(char));
    memcpy(input, data, size);
    input[size] = '\0';

    patchset = pcmk__xml_parse(input);
    if (patchset == NULL) {
        pcmk__xml_free(cib);
        free(input);
        return 0;
    }

    // Apply the fuzz-generated patchset to the base CIB
    // Disable version checking to maximize code path exploration
    xml_apply_patchset(cib, patchset, false);

    pcmk__xml_free(patchset);
    pcmk__xml_free(cib);
    free(input);
    return 0;
}
