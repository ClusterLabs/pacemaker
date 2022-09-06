/*
 * Copyright 2022 the Pacemaker project contributors
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
#include <crm/msg_xml.h>
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
eval_date_expression(xmlNodePtr expr, crm_time_t *now)
{
    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .role = RSC_ROLE_UNKNOWN,
        .now = now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    return pe__eval_date_expr(expr, &rule_data, NULL);
}

/*!
 * \internal
 * \brief Initialize the cluster working set for checking rules
 *
 * Make our own copies of the CIB XML and date/time object, if they're not
 * \c NULL. This way we don't have to take ownership of the objects passed via
 * the API.
 *
 * \param[in,out] out       Output object
 * \param[in]     input     The CIB XML to check (if \c NULL, use current CIB)
 * \param[in]     date      Check whether the rule is in effect at this date
 *                          and time (if \c NULL, use current date and time)
 * \param[out]    data_set  Where to store the cluster working set
 *
 * \return Standard Pacemaker return code
 */
static int
init_rule_check(pcmk__output_t *out, xmlNodePtr input, const crm_time_t *date,
                pe_working_set_t **data_set)
{
    // Allows for cleaner syntax than dereferencing the data_set argument
    pe_working_set_t *new_data_set = NULL;

    new_data_set = pe_new_working_set();
    if (new_data_set == NULL) {
        return ENOMEM;
    }

    pe__set_working_set_flags(new_data_set,
                              pe_flag_no_counts|pe_flag_no_compat);

    // Populate the working set instance

    // Make our own copy of the given input or fetch the CIB and use that
    if (input != NULL) {
        new_data_set->input = copy_xml(input);
        if (new_data_set->input == NULL) {
            out->err(out, "Failed to copy input XML");
            pe_free_working_set(new_data_set);
            return ENOMEM;
        }

    } else {
        int rc = cib__signon_query(NULL, &(new_data_set->input));

        if (rc != pcmk_rc_ok) {
            out->err(out, "CIB query failed: %s", pcmk_rc_str(rc));
            pe_free_working_set(new_data_set);
            return rc;
        }
    }

    // Make our own copy of the given crm_time_t object; otherwise
    // cluster_status() populates with the current time
    if (date != NULL) {
        // pcmk_copy_time() guarantees non-NULL
        new_data_set->now = pcmk_copy_time(date);
    }

    // Unpack everything
    cluster_status(new_data_set);
    *data_set = new_data_set;

    return pcmk_rc_ok;
}

#define XPATH_NODE_RULE "//" XML_TAG_RULE "[@" XML_ATTR_ID "='%s']"

/*!
 * \internal
 * \brief Check whether a given rule is in effect
 *
 * \param[in]     data_set  Cluster working set
 * \param[in]     rule_id   The ID of the rule to check
 * \param[out]    error     Where to store a rule evaluation error message
 *
 * \return Standard Pacemaker return code
 */
static int
eval_rule(pe_working_set_t *data_set, const char *rule_id, const char **error)
{
    xmlNodePtr cib_constraints = NULL;
    xmlNodePtr match = NULL;
    xmlXPathObjectPtr xpath_obj = NULL;
    char *xpath = NULL;
    int rc = pcmk_rc_ok;
    int num_results = 0;

    *error = NULL;

    /* Rules are under the constraints node in the XML, so first find that. */
    cib_constraints = pcmk_find_cib_element(data_set->input,
                                            XML_CIB_TAG_CONSTRAINTS);

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
    xpath = crm_strdup_printf(XPATH_NODE_RULE "//date_expression["
                              "@" XML_EXPR_ATTR_OPERATION "!='date_spec']",
                              rule_id);
    xpath_obj = xpath_search(cib_constraints, xpath);
    num_results = numXpathResults(xpath_obj);

    free(xpath);

    if (num_results == 0) {
        freeXpathObject(xpath_obj);

        xpath = crm_strdup_printf(XPATH_NODE_RULE "//date_expression["
                                  "@" XML_EXPR_ATTR_OPERATION "='date_spec' "
                                  "and date_spec/@years "
                                  "and not(date_spec/@moon)]", rule_id);
        xpath_obj = xpath_search(cib_constraints, xpath);
        num_results = numXpathResults(xpath_obj);

        free(xpath);

        if (num_results == 0) {
            freeXpathObject(xpath_obj);
            *error = "Rule must either not use date_spec, or use date_spec "
                     "with years= but not moon=";
            return EOPNOTSUPP;
        }
    }

    match = getXpathResult(xpath_obj, 0);

    /* We should have ensured this with the xpath query above, but double-
     * checking can't hurt.
     */
    CRM_ASSERT(match != NULL);
    CRM_ASSERT(find_expression_type(match) == time_expr);

    rc = eval_date_expression(match, data_set->now);
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
    pe_working_set_t *data_set = NULL;
    int rc = pcmk_rc_ok;

    CRM_ASSERT(out != NULL);

    if (rule_ids == NULL) {
        // Trivial case; every rule specified is in effect
        return pcmk_rc_ok;
    }

    rc = init_rule_check(out, input, date, &data_set);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    for (const char **rule_id = rule_ids; *rule_id != NULL; rule_id++) {
        const char *error = NULL;
        int last_rc = eval_rule(data_set, *rule_id, &error);

        out->message(out, "rule-check", *rule_id, last_rc, error);

        if (last_rc != pcmk_rc_ok) {
            rc = last_rc;
        }
    }

    pe_free_working_set(data_set);
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
    pcmk__xml_output_finish(out, xml);
    return rc;
}
