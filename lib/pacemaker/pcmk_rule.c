/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <libxml/xpath.h>           // xmlXPathObject, etc.

#include <crm/cib/internal.h>
#include <crm/common/cib.h>
#include <crm/common/iso8601.h>
#include <crm/common/xml.h>
#include <crm/pengine/internal.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

#define XPATH_NODE_RULE "//" PCMK_XE_RULE "[@" PCMK_XA_ID "='%s']"

/*!
 * \internal
 * \brief Check whether a given rule is in effect
 *
 * \param[in]     scheduler  Scheduler data
 * \param[in]     rule_id    The ID of the rule to check
 * \param[out]    error      Where to store a rule evaluation error message
 *
 * \return Standard Pacemaker return code
 */
static int
eval_rule(pcmk_scheduler_t *scheduler, const char *rule_id, const char **error)
{
    xmlNodePtr cib_constraints = NULL;
    xmlNodePtr match = NULL;
    xmlXPathObject *xpath_obj = NULL;
    char *xpath = NULL;
    int rc = pcmk_rc_ok;
    int num_results = 0;

    *error = NULL;

    /* Rules are under the constraints node in the XML, so first find that. */
    cib_constraints = pcmk_find_cib_element(scheduler->input,
                                            PCMK_XE_CONSTRAINTS);

    /* Get all rules matching the given ID that are also simple enough for us
     * to check. For the moment, these rules must only have a single
     * date_expression child and:
     * - Do not have a date_spec operation, or
     * - Have a date_spec operation that contains years=
     *
     * We do this in steps to provide better error messages. First, check that
     * there's any rule with the given ID.
     */
    xpath = pcmk__assert_asprintf(XPATH_NODE_RULE, rule_id);
    xpath_obj = pcmk__xpath_search(cib_constraints->doc, xpath);
    num_results = pcmk__xpath_num_results(xpath_obj);

    free(xpath);
    xmlXPathFreeObject(xpath_obj);

    if (num_results == 0) {
        *error = "Rule not found";
        return ENXIO;
    }

    if (num_results > 1) {
        // Should not be possible; schema prevents this
        *error = "Found more than one rule with matching ID";
        return pcmk_rc_duplicate_id;
    }

    /* Next, make sure it has exactly one date_expression. */
    xpath = pcmk__assert_asprintf(XPATH_NODE_RULE "//"
                                  PCMK_XE_DATE_EXPRESSION,
                                  rule_id);
    xpath_obj = pcmk__xpath_search(cib_constraints->doc, xpath);
    num_results = pcmk__xpath_num_results(xpath_obj);

    free(xpath);
    xmlXPathFreeObject(xpath_obj);

    if (num_results != 1) {
        if (num_results == 0) {
            *error = "Rule does not have a date expression";
        } else {
            *error = "Rule has more than one date expression";
        }
        return EOPNOTSUPP;
    }

    /* Then, check that it's something we actually support. */
    xpath = pcmk__assert_asprintf(XPATH_NODE_RULE
                                  "//" PCMK_XE_DATE_EXPRESSION
                                  "[@" PCMK_XA_OPERATION
                                      "!='" PCMK_VALUE_DATE_SPEC "']",
                                  rule_id);
    xpath_obj = pcmk__xpath_search(cib_constraints->doc, xpath);
    num_results = pcmk__xpath_num_results(xpath_obj);

    free(xpath);

    if (num_results == 0) {
        xmlXPathFreeObject(xpath_obj);

        xpath = pcmk__assert_asprintf(XPATH_NODE_RULE
                                      "//" PCMK_XE_DATE_EXPRESSION
                                      "[@" PCMK_XA_OPERATION
                                          "='" PCMK_VALUE_DATE_SPEC "' "
                                      "and " PCMK_XE_DATE_SPEC
                                          "/@" PCMK_XA_YEARS "]",
                                      rule_id);
        xpath_obj = pcmk__xpath_search(cib_constraints->doc, xpath);
        num_results = pcmk__xpath_num_results(xpath_obj);

        free(xpath);

        if (num_results == 0) {
            xmlXPathFreeObject(xpath_obj);
            *error = "Rule must either not use " PCMK_XE_DATE_SPEC ", or use "
                     PCMK_XE_DATE_SPEC " with " PCMK_XA_YEARS "=";
            return EOPNOTSUPP;
        }
    }

    match = pcmk__xpath_result(xpath_obj, 0);

    /* We should have ensured this with the xpath query above, but double-
     * checking can't hurt.
     */
    pcmk__assert((match != NULL)
                 && (pcmk__condition_type(match) == pcmk__condition_datetime));

    rc = pcmk__evaluate_date_expression(match, scheduler->priv->now, NULL);
    if ((rc != pcmk_rc_ok) && (rc != pcmk_rc_within_range)) {
        // Malformed or missing
        *error = "Error parsing rule";
    }

    xmlXPathFreeObject(xpath_obj);
    return rc;
}

/*!
 * \internal
 * \brief Check whether each rule in a list is in effect
 *
 * \param[in,out] out       Output object
 * \param[in]     input     The CIB XML to check (if \c NULL, use current CIB)
 * \param[in]     date      Check whether the rule is in effect at this date and
 *                          time (if \c NULL, use current date and time)
 * \param[in]     rule_ids  The IDs of the rules to check, as a <tt>NULL</tt>-
 *                          terminated list.
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__check_rules(pcmk__output_t *out, xmlNodePtr input, const crm_time_t *date,
                  const char *const *rule_ids)
{
    pcmk_scheduler_t *scheduler = NULL;
    int rc = pcmk_rc_ok;

    pcmk__assert(out != NULL);

    if (rule_ids == NULL) {
        // Trivial case; every rule specified is in effect
        return pcmk_rc_ok;
    }

    rc = pcmk__init_scheduler(out, input, date, &scheduler);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    for (const char *const *rule_id = rule_ids; *rule_id != NULL; rule_id++) {
        const char *error = NULL;
        int last_rc = eval_rule(scheduler, *rule_id, &error);

        out->message(out, "rule-check", *rule_id, last_rc, error);

        if (last_rc != pcmk_rc_ok) {
            rc = last_rc;
        }
    }

    pcmk_free_scheduler(scheduler);
    return rc;
}

// Documented in pacemaker.h
int
pcmk_check_rules(xmlNodePtr *xml, xmlNodePtr input, const crm_time_t *date,
                 const char **rule_ids)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    pcmk__register_lib_messages(out);

    rc = pcmk__check_rules(out, input, date, (const char *const *) rule_ids);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    return rc;
}
