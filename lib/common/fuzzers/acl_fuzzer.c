/*
 * Copyright 2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>                // bool, false, true
#include <stdint.h>                 // uint8_t
#include <stdlib.h>                 // free()
#include <string.h>                 // memcpy()

#include <glib.h>                   // NULL

#include <crm/common/internal.h>
#include <crm/common/xml.h>

/*
 * ACL evaluation fuzzer
 *
 * Threat model: access control lists in the CIB decide what an unprivileged
 * connection may read or change. ACL rules arrive in the CIB itself (so their
 * content is attacker-influenced for any peer able to write configuration),
 * and the permission decision gates every operation a constrained user
 * performs. A wrong "allow" here is a privilege-escalation bug; a memory-
 * safety violation here is reachable by any such user.
 *
 * The input is an XML envelope:
 *
 *     <acl-fuzz user="alice">
 *       <cib-input> CIB with an <acls> section (roles, targets, rules) </cib-input>
 *       <probe> optional document to filter and probe instead of the CIB </probe>
 *     </acl-fuzz>
 *
 * For one input, this enables ACLs on the CIB document exactly as the CIB
 * manager does before an operation (pcmk__enable_acls()), takes an
 * ACL-filtered copy of the probe (pcmk__acl_filtered_copy()), and probes
 * read/write permission on every element and attribute of both documents
 * (pcmk__check_acl()).
 */

// Envelope element names
#define ENVELOPE_CIB        "cib-input"
#define ENVELOPE_PROBE      "probe"

// Evaluation bounds (large documents cost more to probe)
#define MAX_INPUT_SIZE      (1024 * 1024)
#define MIN_INPUT_SIZE      20
#define MAX_PROBES          500

static int num_probes = 0;

/*!
 * \internal
 * \brief Probe read/write permission on an element and each of its attributes
 */
static void
probe_element(xmlNode *xml)
{
    if ((xml == NULL) || (num_probes >= MAX_PROBES)) {
        return;
    }
    num_probes++;

    (void) pcmk__check_acl(xml, NULL, pcmk__xf_acl_read);
    (void) pcmk__check_acl(xml, NULL, pcmk__xf_acl_write);

    for (xmlAttr *attr = xml->properties; attr != NULL; attr = attr->next) {
        if (num_probes >= MAX_PROBES) {
            return;
        }
        (void) pcmk__check_acl(xml, (const char *) attr->name,
                               pcmk__xf_acl_read);
        (void) pcmk__check_acl(xml, (const char *) attr->name,
                               pcmk__xf_acl_write);
    }

    for (xmlNode *child = pcmk__xe_first_child(xml, NULL, NULL, NULL);
         child != NULL;
         child = pcmk__xe_next(child, NULL)) {
        probe_element(child);
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    xmlNode *envelope = NULL;
    xmlNode *cib = NULL;
    xmlNode *probe = NULL;
    const char *user = NULL;
    char *ns = NULL;

    // Have at least enough data for a minimal envelope
    if ((size < MIN_INPUT_SIZE) || (size > MAX_INPUT_SIZE)) {
        return -1; // Do not add input to testing corpus
    }

    // pcmk__assert_alloc() zeroes the memory, so the string is terminated
    ns = pcmk__assert_alloc(size + 1, sizeof(char));
    memcpy(ns, data, size);
    envelope = pcmk__xml_parse(ns);
    free(ns);
    if (envelope == NULL) {
        return 0;
    }

    cib = pcmk__xe_first_child(envelope, ENVELOPE_CIB, NULL, NULL);
    if (cib == NULL) {
        pcmk__xml_free(envelope);
        return 0;
    }

    // An unprivileged user forces the ACL path; privileged users bypass it
    user = pcmk__xe_get(envelope, "user");
    if (user == NULL) {
        user = "alice";
    }

    pcmk__enable_acls(cib->doc, cib->doc, user);
    num_probes = 0;
    probe_element(cib);

    probe = pcmk__xe_first_child(envelope, ENVELOPE_PROBE, NULL, NULL);
    if (probe != NULL) {
        xmlNode *filtered = pcmk__acl_filtered_copy(user, cib->doc, probe);

        probe_element(filtered);
        pcmk__xml_free(filtered);
    }

    pcmk__xml_free(envelope);
    return 0;
}
