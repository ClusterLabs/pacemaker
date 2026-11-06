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

#include <glib.h>

#include <crm/common/xml.h>

#define BASE_CIB                                                              \
    "<cib crm_feature_set=\"3.19.0\" validate-with=\"pacemaker-3.10\""        \
    "     admin_epoch=\"0\" epoch=\"1\" num_updates=\"0\">"                   \
    "  <configuration>"                                                       \
    "    <crm_config>"                                                        \
    "      <cluster_property_set id=\"cib-bootstrap-options\">"               \
    "        <nvpair id=\"cib-bootstrap-options-stonith-enabled\""            \
    "               name=\"stonith-enabled\" value=\"false\"/>"               \
    "      </cluster_property_set>"                                           \
    "    </crm_config>"                                                       \
    "    <nodes>"                                                             \
    "      <node id=\"1\" uname=\"node1\"/>"                                  \
    "      <node id=\"2\" uname=\"node2\"/>"                                  \
    "    </nodes>"                                                            \
    "    <resources>"                                                         \
    "      <primitive id=\"r1\" class=\"ocf\" provider=\"heartbeat\""         \
    "                 type=\"Dummy\">"                                        \
    "        <operations>"                                                    \
    "          <op id=\"r1-monitor\" name=\"monitor\" interval=\"10s\"/>"     \
    "        </operations>"                                                   \
    "      </primitive>"                                                      \
    "      <primitive id=\"r2\" class=\"ocf\" provider=\"heartbeat\""         \
    "                 type=\"Stateful\"/>"                                    \
    "    </resources>"                                                        \
    "    <constraints>"                                                       \
    "      <rsc_location id=\"loc1\" rsc=\"r1\" node=\"node1\" score=\"100\"/>" \
    "    </constraints>"                                                      \
    "  </configuration>"                                                      \
    "  <status/>"                                                             \
    "</cib>"

static pcmk__output_t *text_out = NULL;

/*!
 * \internal
 * \brief Render a patchset through the text and XML output formats
 *
 * \param[in] patchset  XML patchset to display
 *
 * \note Rendering a patchset is what crm_diff and the CIB logging do with one
 *       that has just arrived, so it sees the same untrusted input as the
 *       apply path. The text output is created once and points at /dev/null;
 *       the XML output accumulates a tree, so it is finished each time rather
 *       than growing for the length of the fuzzing run.
 */
static void
show_patchset(const xmlNode *patchset)
{
    xmlNode *rendered = NULL;
    pcmk__output_t *xml_out = NULL;

    if (text_out != NULL) {
        text_out->message(text_out, "xml-patchset", patchset);
    }

    if (pcmk__xml_output_new(&xml_out, &rendered) == pcmk_rc_ok) {
        xml_out->message(xml_out, "xml-patchset", patchset);
        pcmk__xml_output_finish(xml_out, CRM_EX_OK, &rendered);
        pcmk__xml_free(rendered);
    }
}

/*!
 * \internal
 * \brief Apply a patchset to a freshly parsed copy of \c BASE_CIB
 *
 * \param[in] patchset      XML patchset to apply
 * \param[in] check_version  Whether to enforce the patchset's version fields
 *
 * \note Each call gets its own CIB because a patchset may free or reorder the
 *       nodes it matches, so applying two of them to one document would not be
 *       replaying what a peer sent.
 */
static void
apply_to_base(const xmlNode *patchset, bool check_version)
{
    xmlNode *cib = pcmk__xml_parse(BASE_CIB);

    if (cib == NULL) {
        return;
    }
    xml_apply_patchset(cib, patchset, check_version);
    pcmk__xml_free(cib);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *ns = NULL;
    xmlNode *input = NULL;
    xmlNode *source = NULL;
    xmlNode *patchset = NULL;
    bool config_changed = false;
    int source_version[] = { 0, 0, 0 };
    int target_version[] = { 0, 0, 0 };

    if (size < 5) {
        return 0;
    }

    if (text_out == NULL) {
        pcmk__text_output_new(&text_out, "/dev/null");
    }

    ns = pcmk__assert_alloc(size + 1, sizeof(char));
    memcpy(ns, data, size);

    input = pcmk__xml_parse(ns);
    if (input == NULL) {
        goto done;
    }

    apply_to_base(input, true);
    apply_to_base(input, false);

    source = pcmk__xml_parse(BASE_CIB);
    if (source == NULL) {
        goto done;
    }
    pcmk__xml_mark_changes(source, input);

    patchset = xml_create_patchset(0, source, input, &config_changed, true);
    if (patchset != NULL) {
        pcmk__xml_patchset_add_digest(patchset, input);
        pcmk__xml_patchset_versions(patchset, source_version, target_version);
        pcmk__cib_element_in_patchset(patchset, PCMK_XE_CONFIGURATION);
        show_patchset(patchset);
        apply_to_base(patchset, false);
    }

    pcmk__xml_commit_changes(input->doc);

done:
    pcmk__xml_free(patchset);
    pcmk__xml_free(source);
    pcmk__xml_free(input);
    free(ns);
    return 0;
}
