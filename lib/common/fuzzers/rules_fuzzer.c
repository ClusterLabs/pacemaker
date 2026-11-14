/*
 * Copyright 2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <regex.h>                  // regcomp(), regexec(), regmatch_t
#include <stdbool.h>                // bool, false, true
#include <stdint.h>                 // uint8_t
#include <stdlib.h>                 // free()
#include <string.h>                 // memcpy()

#include <glib.h>                   // GHashTable, g_hash_table_*()

#include <crm/common/iso8601.h>
#include <crm/common/rules.h>
#include <crm/common/xml.h>

/*
 * Rule evaluation fuzzer
 *
 * Threat model: rule expressions come from the CIB (location constraints,
 * Alerts, fencing topology, ACLs...) and are evaluated against node
 * attributes and resource metadata that untrusted peer data feeds. The
 * evaluators parse comparison operators, typed values, regular-expression
 * submatch expansion, and date/time specifications. A memory-safety violation
 * or a mis-evaluation reachable here affects every consumer of rules.
 *
 * The input is an XML envelope:
 *
 *     <rules-fuzz now="2026-01-01 03:00:00" rsc-id="r1"
 *                 rsc-pattern="^r(\d)$" op-name="monitor" op-interval="10000">
 *       <node-attrs><nvpair name="#uname" value="node1"/>...</node-attrs>
 *       <rsc-params>...</rsc-params>
 *       <rsc-meta>...</rsc-meta>
 *       ... any number of <rule> trees at any depth ...
 *     </rules-fuzz>
 *
 * Every PCMK_XE_RULE element found in the envelope is evaluated with
 * pcmk_evaluate_rule() against a rule input built from the envelope. Date
 * expressions additionally drive the ISO-8601 parsing and comparison code.
 */

// Envelope element names
#define ENVELOPE_NODE_ATTRS "node-attrs"
#define ENVELOPE_RSC_PARAMS "rsc-params"
#define ENVELOPE_RSC_META   "rsc-meta"

// Evaluation bounds (deep or wide documents cost more to evaluate)
#define MAX_SUBMATCHES      10
#define MAX_RULES           64
#define MAX_DEPTH           32

// Fallback evaluation time (fixed, so runs are reproducible)
#define DEFAULT_NOW         "2026-01-01 00:00:00"

/*!
 * \internal
 * \brief Fill a string table from an envelope container of \c nvpair elements
 *
 * \param[in] container  Envelope element whose \c nvpair children supply the
 *                       entries (values point into the parsed envelope, which
 *                       outlives the table)
 * \param[in] table      String hash table to fill
 */
static void
fill_attrs(const xmlNode *container, GHashTable *table)
{
    if (container == NULL) {
        return;
    }
    for (const xmlNode *nvpair = pcmk__xe_first_child(container,
                                                      PCMK_XE_NVPAIR, NULL,
                                                      NULL);
         nvpair != NULL;
         nvpair = pcmk__xe_next(nvpair, PCMK_XE_NVPAIR)) {

        const char *name = pcmk__xe_get(nvpair, PCMK_XA_NAME);
        const char *value = pcmk__xe_get(nvpair, PCMK_XA_VALUE);

        if (name != NULL) {
            g_hash_table_replace(table, (gpointer) name, (gpointer) value);
        }
    }
}

/*!
 * \internal
 * \brief Evaluate every rule in a subtree, depth-first
 */
static void
evaluate_rules(const xmlNode *node, const pcmk_rule_input_t *rule_input,
               int depth, int *num_rules)
{
    if ((node == NULL) || (depth > MAX_DEPTH) || (*num_rules >= MAX_RULES)) {
        return;
    }

    if (pcmk__xe_is(node, PCMK_XE_RULE)) {
        (*num_rules)++;
        // A failed evaluation (rule does not pass) is as interesting as a pass
        (void) pcmk_evaluate_rule((xmlNode *) node, rule_input, NULL);
    }

    for (const xmlNode *child = pcmk__xe_first_child(node, NULL, NULL, NULL);
         child != NULL;
         child = pcmk__xe_next(child, NULL)) {
        evaluate_rules(child, rule_input, depth + 1, num_rules);
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    xmlNode *envelope = NULL;
    const char *now_s = NULL;
    const char *rsc_id = NULL;
    const char *rsc_pattern = NULL;
    const char *op_name = NULL;
    char *ns = NULL;
    crm_time_t *now = NULL;
    GHashTable *node_attrs = NULL;
    GHashTable *rsc_params = NULL;
    GHashTable *rsc_meta = NULL;
    regex_t re;
    bool re_valid = false;
    regmatch_t submatches[MAX_SUBMATCHES] = { { 0, }, };
    pcmk_rule_input_t rule_input = { 0, };
    int num_rules = 0;
    int nmatches = 0;
    int op_interval_ms = 0;

    // Have at least enough data for a minimal envelope
    if ((size < 20) || (size > (1024 * 1024))) {
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

    // Evaluation time: fuzz-provided when present and valid, else a fixed date
    now_s = pcmk__xe_get(envelope, "now");
    if (now_s != NULL) {
        now = crm_time_new(now_s);
    }
    if (now == NULL) {
        now = crm_time_new(DEFAULT_NOW);
    }

    node_attrs = pcmk__strkey_table(NULL, NULL);
    rsc_params = pcmk__strkey_table(NULL, NULL);
    rsc_meta = pcmk__strkey_table(NULL, NULL);
    fill_attrs(pcmk__xe_first_child(envelope, ENVELOPE_NODE_ATTRS, NULL, NULL),
               node_attrs);
    fill_attrs(pcmk__xe_first_child(envelope, ENVELOPE_RSC_PARAMS, NULL, NULL),
               rsc_params);
    fill_attrs(pcmk__xe_first_child(envelope, ENVELOPE_RSC_META, NULL, NULL),
               rsc_meta);

    // Optional regular expression over the resource ID, for %0-%9 expansion
    rsc_id = pcmk__xe_get(envelope, "rsc-id");
    if (rsc_id == NULL) {
        rsc_id = "rsc1";
    }
    rsc_pattern = pcmk__xe_get(envelope, "rsc-pattern");
    if (rsc_pattern != NULL) {
        re_valid = (regcomp(&re, rsc_pattern, 0) == 0);
        if (re_valid) {
            if (regexec(&re, rsc_id, MAX_SUBMATCHES, submatches, 0) == 0) {
                nmatches = MAX_SUBMATCHES;
            }
        }
    }

    op_name = pcmk__xe_get(envelope, "op-name");
    if (op_name == NULL) {
        op_name = "monitor";
    }
    pcmk__xe_get_int(envelope, "op-interval", &op_interval_ms);

    rule_input.now = now;
    rule_input.node_attrs = node_attrs;
    rule_input.rsc_params = rsc_params;
    rule_input.rsc_meta = rsc_meta;
    rule_input.rsc_id = rsc_id;
    rule_input.rsc_id_submatches = submatches;
    rule_input.rsc_id_nmatches = nmatches;
    rule_input.op_name = op_name;
    rule_input.op_interval_ms = (unsigned int) op_interval_ms;

    evaluate_rules(envelope, &rule_input, 0, &num_rules);

    if (re_valid) {
        regfree(&re);
    }
    g_hash_table_destroy(node_attrs);
    g_hash_table_destroy(rsc_params);
    g_hash_table_destroy(rsc_meta);
    crm_time_free(now);
    pcmk__xml_free(envelope);
    return 0;
}
