/*
 * Copyright 2022-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/cib/internal.h>
#include <crm/common/cib.h>
#include <crm/common/iso8601.h>
#include <crm/common/xml.h>
#include <crm/pengine/internal.h>
#include <crm/pengine/rules_internal.h>
#include <pacemaker-internal.h>

/*!
 * \internal
 * \brief Evaluate a date expression for a specific time
 *
 * \param[in]  expr         date_expression XML
 * \param[in]  now          Time for which to evaluate expression
 *
 * \return Standard Pacemaker return code
 */
static int
eval_date_expression(const xmlNode *expr, crm_time_t *now)
{
    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .now = now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    return pe__eval_date_expr(expr, &rule_data, NULL);
}

/*!
 * \internal
 * \brief Initialize scheduler data for checking rules
 *
 * Make our own copies of the CIB XML and date/time object, if they're not
 * \c NULL. This way we don't have to take ownership of the objects passed via
 * the API.
 *
 * \param[in,out] out        Output object
 * \param[in]     input      The CIB XML to check (if \c NULL, use current CIB)
 * \param[in]     date       Check whether the rule is in effect at this date
 *                           and time (if \c NULL, use current date and time)
 * \param[out]    scheduler  Where to store initialized scheduler data
 *
 * \return Standard Pacemaker return code
 */
static int
init_rule_check(pcmk__output_t *out, xmlNodePtr input, const crm_time_t *date,
                pcmk_scheduler_t **scheduler)
{
    // Allows for cleaner syntax than dereferencing the scheduler argument
    pcmk_scheduler_t *new_scheduler = NULL;

    new_scheduler = pe_new_working_set();
    if (new_scheduler == NULL) {
        return ENOMEM;
    }

    pcmk__set_scheduler_flags(new_scheduler,
                              pcmk_sched_no_counts|pcmk_sched_no_compat);

    // Populate the scheduler data

    // Make our own copy of the given input or fetch the CIB and use that
    if (input != NULL) {
        new_scheduler->input = copy_xml(input);
        if (new_scheduler->input == NULL) {
            out->err(out, "Failed to copy input XML");
            pe_free_working_set(new_scheduler);
            return ENOMEM;
        }

    } else {
        int rc = cib__signon_query(out, NULL, &(new_scheduler->input));

        if (rc != pcmk_rc_ok) {
            pe_free_working_set(new_scheduler);
            return rc;
        }
    }

    // Make our own copy of the given crm_time_t object; otherwise
    // cluster_status() populates with the current time
    if (date != NULL) {
        // pcmk_copy_time() guarantees non-NULL
        new_scheduler->now = pcmk_copy_time(date);
    }

    // Unpack everything
    cluster_status(new_scheduler);
    *scheduler = new_scheduler;

    return pcmk_rc_ok;
}

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
    xmlXPathObjectPtr xpath_obj = NULL;
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
     * - Have a date_spec operation that contains years= but does not contain
     *   moon=.
     *
     * We do this in steps to provide better error messages. First, check that
     * there's any rule with the given ID.
     */
    xpath = crm_strdup_printf(XPATH_NODE_RULE, rule_id);
    xpath_obj = xpath_search(cib_constraints, xpath);
    num_results = numXpathResults(xpath_obj);

    free(xpath);
    freeXpathObject(xpath_obj);

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
    xpath = crm_strdup_printf(XPATH_NODE_RULE "//date_expression", rule_id);
    xpath_obj = xpath_search(cib_constraints, xpath);
    num_results = numXpathResults(xpath_obj);

    free(xpath);
    freeXpathObject(xpath_obj);

    if (num_results != 1) {
        if (num_results == 0) {
            *error = "Rule does not have a date expression";
        } else {
            *error = "Rule has more than one date expression";
        }
        return EOPNOTSUPP;
    }

    /* Then, check that it's something we actually support. */
    xpath = crm_strdup_printf(XPATH_NODE_RULE
                              "//" PCMK_XE_DATE_EXPRESSION
                              "[@" PCMK_XA_OPERATION
                                  "!='" PCMK_VALUE_DATE_SPEC "']",
                              rule_id);
    xpath_obj = xpath_search(cib_constraints, xpath);
    num_results = numXpathResults(xpath_obj);

    free(xpath);

    if (num_results == 0) {
        freeXpathObject(xpath_obj);

        xpath = crm_strdup_printf(XPATH_NODE_RULE
                                  "//" PCMK_XE_DATE_EXPRESSION
                                  "[@" PCMK_XA_OPERATION
                                      "='" PCMK_VALUE_DATE_SPEC "' "
                                  "and " PCMK_XE_DATE_SPEC
                                      "/@" PCMK_XA_YEARS " "
                                  "and not(" PCMK_XE_DATE_SPEC
                                      "/@" PCMK__XA_MOON ")]",
                                  rule_id);
        xpath_obj = xpath_search(cib_constraints, xpath);
        num_results = numXpathResults(xpath_obj);

        free(xpath);

        if (num_results == 0) {
            freeXpathObject(xpath_obj);
            *error = "Rule must either not use " PCMK_XE_DATE_SPEC ", or use "
                     PCMK_XE_DATE_SPEC " with " PCMK_XA_YEARS "= but not "
                     PCMK__XA_MOON "=";
            return EOPNOTSUPP;
        }
    }

    match = getXpathResult(xpath_obj, 0);

    /* We should have ensured this with the xpath query above, but double-
     * checking can't hurt.
     */
    CRM_ASSERT(match != NULL);
    CRM_ASSERT(find_expression_type(match) == pcmk__subexpr_datetime);

    rc = eval_date_expression(match, scheduler->now);
    if (rc == pcmk_rc_undetermined) {
        /* pe__eval_date_expr() should return this only if something is
         * malformed or missing
         */
        *error = "Error parsing rule";
    }

    freeXpathObject(xpath_obj);
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
                  const char **rule_ids)
{
    pcmk_scheduler_t *scheduler = NULL;
    int rc = pcmk_rc_ok;

    CRM_ASSERT(out != NULL);

    if (rule_ids == NULL) {
        // Trivial case; every rule specified is in effect
        return pcmk_rc_ok;
    }

    rc = init_rule_check(out, input, date, &scheduler);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    for (const char **rule_id = rule_ids; *rule_id != NULL; rule_id++) {
        const char *error = NULL;
        int last_rc = eval_rule(scheduler, *rule_id, &error);

        out->message(out, "rule-check", *rule_id, last_rc, error);

        if (last_rc != pcmk_rc_ok) {
            rc = last_rc;
        }
    }

    pe_free_working_set(scheduler);
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

    rc = pcmk__check_rules(out, input, date, rule_ids);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    return rc;
}
