/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm_resource.h>

static char *
parse_cli_lifetime(pcmk__output_t *out, const char *move_lifetime)
{
    char *later_s = NULL;
    crm_time_t *now = NULL;
    crm_time_t *later = NULL;
    crm_time_t *duration = NULL;

    if (move_lifetime == NULL) {
        return NULL;
    }

    duration = crm_time_parse_duration(move_lifetime);
    if (duration == NULL) {
        out->err(out, "Invalid duration specified: %s\n"
                      "Please refer to https://en.wikipedia.org/wiki/ISO_8601#Durations "
                      "for examples of valid durations", move_lifetime);
        return NULL;
    }

    now = crm_time_new(NULL);
    later = crm_time_add(now, duration);
    if (later == NULL) {
        out->err(out, "Unable to add %s to current time\n"
                      "Please report to " PACKAGE_BUGREPORT " as possible bug",
                      move_lifetime);
        crm_time_free(now);
        crm_time_free(duration);
        return NULL;
    }

    crm_time_log(LOG_INFO, "now     ", now,
                 crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);
    crm_time_log(LOG_INFO, "later   ", later,
                 crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);
    crm_time_log(LOG_INFO, "duration", duration, crm_time_log_date | crm_time_log_timeofday);
    later_s = crm_time_as_string(later, crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);
    out->info(out, "Migration will take effect until: %s", later_s);

    crm_time_free(duration);
    crm_time_free(later);
    crm_time_free(now);
    return later_s;
}

static const char *
promoted_role_name(void)
{
    /* This is a judgment call for what string to use. @TODO Ideally we'd
     * use the legacy string if the DC only supports that, and the new one
     * otherwise. Basing it on --enable-compat-2.0 is a decent guess.
     */
#ifdef PCMK__COMPAT_2_0
        return RSC_ROLE_PROMOTED_LEGACY_S;
#else
        return RSC_ROLE_PROMOTED_S;
#endif
}

// \return Standard Pacemaker return code
int
cli_resource_ban(pcmk__output_t *out, const char *rsc_id, const char *host,
                 const char *move_lifetime, GList *allnodes, cib_t * cib_conn,
                 int cib_options, gboolean promoted_role_only)
{
    char *later_s = NULL;
    int rc = pcmk_rc_ok;
    xmlNode *fragment = NULL;
    xmlNode *location = NULL;

    if(host == NULL) {
        GList *n = allnodes;
        for(; n && rc == pcmk_rc_ok; n = n->next) {
            pe_node_t *target = n->data;

            rc = cli_resource_ban(out, rsc_id, target->details->uname, move_lifetime,
                                  NULL, cib_conn, cib_options, promoted_role_only);
        }
        return rc;
    }

    later_s = parse_cli_lifetime(out, move_lifetime);
    if(move_lifetime && later_s == NULL) {
        return EINVAL;
    }

    fragment = create_xml_node(NULL, XML_CIB_TAG_CONSTRAINTS);

    location = create_xml_node(fragment, XML_CONS_TAG_RSC_LOCATION);
    crm_xml_set_id(location, "cli-ban-%s-on-%s", rsc_id, host);

    out->info(out, "WARNING: Creating rsc_location constraint '%s' with a "
                   "score of -INFINITY for resource %s on %s.\n\tThis will "
                   "prevent %s from %s on %s until the constraint is removed "
                   "using the clear option or by editing the CIB with an "
                   "appropriate tool\n\tThis will be the case even if %s "
                   "is the last node in the cluster",
                   ID(location), rsc_id, host, rsc_id,
                   (promoted_role_only? "being promoted" : "running"),
                   host, host);

    crm_xml_add(location, XML_LOC_ATTR_SOURCE, rsc_id);
    if(promoted_role_only) {
        crm_xml_add(location, XML_RULE_ATTR_ROLE, promoted_role_name());
    } else {
        crm_xml_add(location, XML_RULE_ATTR_ROLE, RSC_ROLE_STARTED_S);
    }

    if (later_s == NULL) {
        /* Short form */
        crm_xml_add(location, XML_CIB_TAG_NODE, host);
        crm_xml_add(location, XML_RULE_ATTR_SCORE, CRM_MINUS_INFINITY_S);

    } else {
        xmlNode *rule = create_xml_node(location, XML_TAG_RULE);
        xmlNode *expr = create_xml_node(rule, XML_TAG_EXPRESSION);

        crm_xml_set_id(rule, "cli-ban-%s-on-%s-rule", rsc_id, host);
        crm_xml_add(rule, XML_RULE_ATTR_SCORE, CRM_MINUS_INFINITY_S);
        crm_xml_add(rule, XML_RULE_ATTR_BOOLEAN_OP, "and");

        crm_xml_set_id(expr, "cli-ban-%s-on-%s-expr", rsc_id, host);
        crm_xml_add(expr, XML_EXPR_ATTR_ATTRIBUTE, CRM_ATTR_UNAME);
        crm_xml_add(expr, XML_EXPR_ATTR_OPERATION, "eq");
        crm_xml_add(expr, XML_EXPR_ATTR_VALUE, host);
        crm_xml_add(expr, XML_EXPR_ATTR_TYPE, "string");

        expr = create_xml_node(rule, "date_expression");
        crm_xml_set_id(expr, "cli-ban-%s-on-%s-lifetime", rsc_id, host);
        crm_xml_add(expr, "operation", "lt");
        crm_xml_add(expr, "end", later_s);
    }

    crm_log_xml_notice(fragment, "Modify");
    rc = cib_conn->cmds->update(cib_conn, XML_CIB_TAG_CONSTRAINTS, fragment, cib_options);
    rc = pcmk_legacy2rc(rc);

    free_xml(fragment);
    free(later_s);
    return rc;
}

// \return Standard Pacemaker return code
int
cli_resource_prefer(pcmk__output_t *out,const char *rsc_id, const char *host,
                    const char *move_lifetime, cib_t * cib_conn, int cib_options,
                    gboolean promoted_role_only)
{
    char *later_s = parse_cli_lifetime(out, move_lifetime);
    int rc = pcmk_rc_ok;
    xmlNode *location = NULL;
    xmlNode *fragment = NULL;

    if(move_lifetime && later_s == NULL) {
        return EINVAL;
    }

    if(cib_conn == NULL) {
        free(later_s);
        return ENOTCONN;
    }

    fragment = create_xml_node(NULL, XML_CIB_TAG_CONSTRAINTS);

    location = create_xml_node(fragment, XML_CONS_TAG_RSC_LOCATION);
    crm_xml_set_id(location, "cli-prefer-%s", rsc_id);

    crm_xml_add(location, XML_LOC_ATTR_SOURCE, rsc_id);
    if(promoted_role_only) {
        crm_xml_add(location, XML_RULE_ATTR_ROLE, promoted_role_name());
    } else {
        crm_xml_add(location, XML_RULE_ATTR_ROLE, RSC_ROLE_STARTED_S);
    }

    if (later_s == NULL) {
        /* Short form */
        crm_xml_add(location, XML_CIB_TAG_NODE, host);
        crm_xml_add(location, XML_RULE_ATTR_SCORE, CRM_INFINITY_S);

    } else {
        xmlNode *rule = create_xml_node(location, XML_TAG_RULE);
        xmlNode *expr = create_xml_node(rule, XML_TAG_EXPRESSION);

        crm_xml_set_id(rule, "cli-prefer-rule-%s", rsc_id);
        crm_xml_add(rule, XML_RULE_ATTR_SCORE, CRM_INFINITY_S);
        crm_xml_add(rule, XML_RULE_ATTR_BOOLEAN_OP, "and");

        crm_xml_set_id(expr, "cli-prefer-expr-%s", rsc_id);
        crm_xml_add(expr, XML_EXPR_ATTR_ATTRIBUTE, CRM_ATTR_UNAME);
        crm_xml_add(expr, XML_EXPR_ATTR_OPERATION, "eq");
        crm_xml_add(expr, XML_EXPR_ATTR_VALUE, host);
        crm_xml_add(expr, XML_EXPR_ATTR_TYPE, "string");

        expr = create_xml_node(rule, "date_expression");
        crm_xml_set_id(expr, "cli-prefer-lifetime-end-%s", rsc_id);
        crm_xml_add(expr, "operation", "lt");
        crm_xml_add(expr, "end", later_s);
    }

    crm_log_xml_info(fragment, "Modify");
    rc = cib_conn->cmds->update(cib_conn, XML_CIB_TAG_CONSTRAINTS, fragment, cib_options);
    rc = pcmk_legacy2rc(rc);

    free_xml(fragment);
    free(later_s);
    return rc;
}

/* Nodes can be specified two different ways in the CIB, so we have two different
 * functions to try clearing out any constraints on them:
 *
 * (1) The node could be given by attribute=/value= in an expression XML node.
 * That's what resource_clear_node_in_expr handles.  That XML looks like this:
 *
 * <rsc_location id="cli-prefer-dummy" rsc="dummy" role="Started">
 *   <rule id="cli-prefer-rule-dummy" score="INFINITY" boolean-op="and">
 *     <expression id="cli-prefer-expr-dummy" attribute="#uname" operation="eq" value="test02" type="string"/>
 *     <date_expression id="cli-prefer-lifetime-end-dummy" operation="lt" end="2018-12-12 14:05:37 -05:00"/>
 *   </rule>
 * </rsc_location>
 *
 * (2) The mode could be given by node= in an rsc_location XML node.  That's
 * what resource_clear_node_in_location handles.  That XML looks like this:
 *
 * <rsc_location id="cli-prefer-dummy" rsc="dummy" role="Started" node="node1" score="INFINITY"/>
 *
 * \return Standard Pacemaker return code
 */
static int
resource_clear_node_in_expr(const char *rsc_id, const char *host, cib_t * cib_conn,
                            int cib_options)
{
    int rc = pcmk_rc_ok;
    char *xpath_string = NULL;

    xpath_string = crm_strdup_printf("//rsc_location[@id='cli-prefer-%s'][rule[@id='cli-prefer-rule-%s']/expression[@attribute='#uname' and @value='%s']]",
                                     rsc_id, rsc_id, host);

    rc = cib_conn->cmds->remove(cib_conn, xpath_string, NULL, cib_xpath | cib_options);
    if (rc == -ENXIO) {
        rc = pcmk_rc_ok;
    } else {
        rc = pcmk_legacy2rc(rc);
    }

    free(xpath_string);
    return rc;
}

// \return Standard Pacemaker return code
static int
resource_clear_node_in_location(const char *rsc_id, const char *host, cib_t * cib_conn,
                                int cib_options, bool clear_ban_constraints, gboolean force)
{
    int rc = pcmk_rc_ok;
    xmlNode *fragment = NULL;
    xmlNode *location = NULL;

    fragment = create_xml_node(NULL, XML_CIB_TAG_CONSTRAINTS);

    if (clear_ban_constraints == TRUE) {
        location = create_xml_node(fragment, XML_CONS_TAG_RSC_LOCATION);
        crm_xml_set_id(location, "cli-ban-%s-on-%s", rsc_id, host);
    }

    location = create_xml_node(fragment, XML_CONS_TAG_RSC_LOCATION);
    crm_xml_set_id(location, "cli-prefer-%s", rsc_id);
    if (force == FALSE) {
        crm_xml_add(location, XML_CIB_TAG_NODE, host);
    }

    crm_log_xml_info(fragment, "Delete");
    rc = cib_conn->cmds->remove(cib_conn, XML_CIB_TAG_CONSTRAINTS, fragment, cib_options);
    if (rc == -ENXIO) {
        rc = pcmk_rc_ok;
    } else {
        rc = pcmk_legacy2rc(rc);
    }

    free_xml(fragment);
    return rc;
}

// \return Standard Pacemaker return code
int
cli_resource_clear(const char *rsc_id, const char *host, GList *allnodes, cib_t * cib_conn,
                   int cib_options, bool clear_ban_constraints, gboolean force)
{
    int rc = pcmk_rc_ok;

    if(cib_conn == NULL) {
        return ENOTCONN;
    }

    if (host) {
        rc = resource_clear_node_in_expr(rsc_id, host, cib_conn, cib_options);

        /* rc does not tell us whether the previous operation did anything, only
         * whether it failed or not.  Thus, as long as it did not fail, we need
         * to try the second clear method.
         */
        if (rc == pcmk_rc_ok) {
            rc = resource_clear_node_in_location(rsc_id, host, cib_conn,
                                                 cib_options, clear_ban_constraints,
                                                 force);
        }

    } else {
        GList *n = allnodes;

        /* Iterate over all nodes, attempting to clear the constraint from each.
         * On the first error, abort.
         */
        for(; n; n = n->next) {
            pe_node_t *target = n->data;

            rc = cli_resource_clear(rsc_id, target->details->uname, NULL,
                                    cib_conn, cib_options, clear_ban_constraints,
                                    force);
            if (rc != pcmk_rc_ok) {
                break;
            }
        }
    }

    return rc;
}

static char *
build_clear_xpath_string(xmlNode *constraint_node, const char *rsc, const char *node, gboolean promoted_role_only)
{
    char *xpath_string = NULL;
    GString *first_half = NULL;
    char *rsc_role_substr = NULL;
    char *date_substr = NULL;

    if (pcmk__starts_with(ID(constraint_node), "cli-ban-")) {
        date_substr = crm_strdup_printf("//date_expression[@id='%s-lifetime']",
                                        ID(constraint_node));

    } else if (pcmk__starts_with(ID(constraint_node), "cli-prefer-")) {
        date_substr = crm_strdup_printf("//date_expression[@id='cli-prefer-lifetime-end-%s']",
                                        crm_element_value(constraint_node, "rsc"));
    } else {
        return NULL;
    }

    first_half = g_string_sized_new(1024);
    g_string_append(first_half, "//" XML_CONS_TAG_RSC_LOCATION);

    if (node != NULL || rsc != NULL || promoted_role_only == TRUE) {
        g_string_append_c(first_half, '[');

        if (node != NULL) {
            pcmk__g_strcat(first_half,
                           "@" XML_CIB_TAG_NODE "='", node, "'", NULL);

            if (rsc != NULL || promoted_role_only == TRUE) {
                g_string_append(first_half, " and ");
            }
        }

        if (rsc != NULL && promoted_role_only == TRUE) {
            rsc_role_substr = crm_strdup_printf("@rsc='%s' and @role='%s'",
                                                rsc, promoted_role_name());
            pcmk__g_strcat(first_half,
                           "@" XML_LOC_ATTR_SOURCE "='", rsc, "' "
                           "and @" XML_RULE_ATTR_ROLE "='",
                           promoted_role_name(), "']", NULL);

        } else if (rsc != NULL) {
            rsc_role_substr = crm_strdup_printf("@rsc='%s'", rsc);
            pcmk__g_strcat(first_half,
                           "@" XML_LOC_ATTR_SOURCE "='", rsc, "']", NULL);

        } else if (promoted_role_only == TRUE) {
            rsc_role_substr = crm_strdup_printf("@role='%s'",
                                                promoted_role_name());
            pcmk__g_strcat(first_half,
                           "@" XML_RULE_ATTR_ROLE "='", promoted_role_name(),
                           "']", NULL);

        } else {
            g_string_append_c(first_half, ']');
        }
    }

#define XPATH_FMT_START "%s|//" XML_CONS_TAG_RSC_LOCATION

#define XPATH_FMT_END   "/" XML_TAG_RULE "[" XML_TAG_EXPRESSION \
                        "[@" XML_EXPR_ATTR_ATTRIBUTE "='" CRM_ATTR_UNAME \
                        "' and @" XML_EXPR_ATTR_VALUE "='%s']]%s"

    if (node != NULL) {
        if (rsc_role_substr != NULL) {
            xpath_string = crm_strdup_printf(XPATH_FMT_START "[%s]"
                                             XPATH_FMT_END,
                                             (const char *) first_half->str,
                                             rsc_role_substr, node,
                                             date_substr);
        } else {
            xpath_string = crm_strdup_printf(XPATH_FMT_START XPATH_FMT_END,
                                             (const char *) first_half->str,
                                             node, date_substr);
        }
    } else {
        xpath_string = crm_strdup_printf("%s%s", (const char *) first_half->str,
                                         date_substr);
    }

    g_string_free(first_half, TRUE);
    free(date_substr);
    free(rsc_role_substr);

    return xpath_string;
}

// \return Standard Pacemaker return code
int
cli_resource_clear_all_expired(xmlNode *root, cib_t *cib_conn, int cib_options,
                               const char *rsc, const char *node, gboolean promoted_role_only)
{
    xmlXPathObject *xpathObj = NULL;
    xmlNode *cib_constraints = NULL;
    crm_time_t *now = crm_time_new(NULL);
    int i;
    int rc = pcmk_rc_ok;

    cib_constraints = pcmk_find_cib_element(root, XML_CIB_TAG_CONSTRAINTS);
    xpathObj = xpath_search(cib_constraints, "//" XML_CONS_TAG_RSC_LOCATION);

    for (i = 0; i < numXpathResults(xpathObj); i++) {
        xmlNode *constraint_node = getXpathResult(xpathObj, i);
        xmlNode *date_expr_node = NULL;
        crm_time_t *end = NULL;
        char *xpath_string = NULL;

        xpath_string = build_clear_xpath_string(constraint_node, rsc, node, promoted_role_only);
        if (xpath_string == NULL) {
            continue;
        }

        date_expr_node = get_xpath_object(xpath_string, constraint_node, LOG_DEBUG);
        if (date_expr_node == NULL) {
            free(xpath_string);
            continue;
        }

        /* And then finally, see if the date expression is expired.  If so,
         * clear the constraint.
         */
        end = crm_time_new(crm_element_value(date_expr_node, "end"));

        if (crm_time_compare(now, end) == 1) {
            xmlNode *fragment = NULL;
            xmlNode *location = NULL;

            fragment = create_xml_node(NULL, XML_CIB_TAG_CONSTRAINTS);
            location = create_xml_node(fragment, XML_CONS_TAG_RSC_LOCATION);
            crm_xml_set_id(location, "%s", ID(constraint_node));
            crm_log_xml_info(fragment, "Delete");

            rc = cib_conn->cmds->remove(cib_conn, XML_CIB_TAG_CONSTRAINTS,
                                        fragment, cib_options);
            rc = pcmk_legacy2rc(rc);

            if (rc != pcmk_rc_ok) {
                free(xpath_string);
                goto done;
            }

            free_xml(fragment);
        }

        crm_time_free(end);
        free(xpath_string);
    }

done:
    freeXpathObject(xpathObj);
    crm_time_free(now);
    return rc;
}
