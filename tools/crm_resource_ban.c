/*
 * Copyright 2004-2024 the Pacemaker project contributors
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

// \return Standard Pacemaker return code
int
cli_resource_ban(pcmk__output_t *out, const char *rsc_id, const char *host,
                 const char *move_lifetime, cib_t * cib_conn, int cib_options,
                 gboolean promoted_role_only, const char *promoted_role)
{
    char *later_s = NULL;
    int rc = pcmk_rc_ok;
    xmlNode *fragment = NULL;
    xmlNode *location = NULL;

    later_s = parse_cli_lifetime(out, move_lifetime);
    if(move_lifetime && later_s == NULL) {
        return EINVAL;
    }

    fragment = pcmk__xe_create(NULL, PCMK_XE_CONSTRAINTS);

    location = pcmk__xe_create(fragment, PCMK_XE_RSC_LOCATION);
    crm_xml_set_id(location, "cli-ban-%s-on-%s", rsc_id, host);

    out->info(out,
              "WARNING: Creating " PCMK_XE_RSC_LOCATION " constraint '%s' with "
              "a score of " PCMK_VALUE_MINUS_INFINITY " for resource %s on %s."
              "\n\tThis will prevent %s from %s on %s until the constraint is "
              "removed using the clear option or by editing the CIB with an "
              "appropriate tool.\n"
              "\tThis will be the case even if %s is the last node in the "
              "cluster",
              pcmk__xe_id(location), rsc_id, host, rsc_id,
              (promoted_role_only? "being promoted" : "running"), host, host);

    crm_xml_add(location, PCMK_XA_RSC, rsc_id);
    if(promoted_role_only) {
        crm_xml_add(location, PCMK_XA_ROLE, promoted_role);
    } else {
        crm_xml_add(location, PCMK_XA_ROLE, PCMK__ROLE_STARTED);
    }

    if (later_s == NULL) {
        /* Short form */
        crm_xml_add(location, PCMK_XE_NODE, host);
        crm_xml_add(location, PCMK_XA_SCORE, PCMK_VALUE_MINUS_INFINITY);

    } else {
        xmlNode *rule = pcmk__xe_create(location, PCMK_XE_RULE);
        xmlNode *expr = pcmk__xe_create(rule, PCMK_XE_EXPRESSION);

        crm_xml_set_id(rule, "cli-ban-%s-on-%s-rule", rsc_id, host);
        crm_xml_add(rule, PCMK_XA_SCORE, PCMK_VALUE_MINUS_INFINITY);
        crm_xml_add(rule, PCMK_XA_BOOLEAN_OP, PCMK_VALUE_AND);

        crm_xml_set_id(expr, "cli-ban-%s-on-%s-expr", rsc_id, host);
        crm_xml_add(expr, PCMK_XA_ATTRIBUTE, CRM_ATTR_UNAME);
        crm_xml_add(expr, PCMK_XA_OPERATION, PCMK_VALUE_EQ);
        crm_xml_add(expr, PCMK_XA_VALUE, host);
        crm_xml_add(expr, PCMK_XA_TYPE, PCMK_VALUE_STRING);

        expr = pcmk__xe_create(rule, PCMK_XE_DATE_EXPRESSION);
        crm_xml_set_id(expr, "cli-ban-%s-on-%s-lifetime", rsc_id, host);
        crm_xml_add(expr, PCMK_XA_OPERATION, PCMK_VALUE_LT);
        crm_xml_add(expr, PCMK_XA_END, later_s);
    }

    crm_log_xml_notice(fragment, "Modify");
    rc = cib_conn->cmds->modify(cib_conn, PCMK_XE_CONSTRAINTS, fragment,
                                cib_options);
    rc = pcmk_legacy2rc(rc);

    free_xml(fragment);
    free(later_s);

    if (rc != pcmk_rc_ok && promoted_role_only && strcmp(promoted_role, PCMK__ROLE_PROMOTED) == 0) {
        int banrc = cli_resource_ban(out, rsc_id, host, move_lifetime,
                              cib_conn, cib_options, promoted_role_only,
                              PCMK__ROLE_PROMOTED_LEGACY);
        if (banrc == pcmk_rc_ok) {
            rc = banrc;
        }
    }

    return rc;
}

// \return Standard Pacemaker return code
int
cli_resource_prefer(pcmk__output_t *out,const char *rsc_id, const char *host,
                    const char *move_lifetime, cib_t *cib_conn, int cib_options,
                    gboolean promoted_role_only, const char *promoted_role)
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

    fragment = pcmk__xe_create(NULL, PCMK_XE_CONSTRAINTS);

    location = pcmk__xe_create(fragment, PCMK_XE_RSC_LOCATION);
    crm_xml_set_id(location, "cli-prefer-%s", rsc_id);

    crm_xml_add(location, PCMK_XA_RSC, rsc_id);
    if(promoted_role_only) {
        crm_xml_add(location, PCMK_XA_ROLE, promoted_role);
    } else {
        crm_xml_add(location, PCMK_XA_ROLE, PCMK__ROLE_STARTED);
    }

    if (later_s == NULL) {
        /* Short form */
        crm_xml_add(location, PCMK_XE_NODE, host);
        crm_xml_add(location, PCMK_XA_SCORE, PCMK_VALUE_INFINITY);

    } else {
        xmlNode *rule = pcmk__xe_create(location, PCMK_XE_RULE);
        xmlNode *expr = pcmk__xe_create(rule, PCMK_XE_EXPRESSION);

        crm_xml_set_id(rule, "cli-prefer-rule-%s", rsc_id);
        crm_xml_add(rule, PCMK_XA_SCORE, PCMK_VALUE_INFINITY);
        crm_xml_add(rule, PCMK_XA_BOOLEAN_OP, PCMK_VALUE_AND);

        crm_xml_set_id(expr, "cli-prefer-expr-%s", rsc_id);
        crm_xml_add(expr, PCMK_XA_ATTRIBUTE, CRM_ATTR_UNAME);
        crm_xml_add(expr, PCMK_XA_OPERATION, PCMK_VALUE_EQ);
        crm_xml_add(expr, PCMK_XA_VALUE, host);
        crm_xml_add(expr, PCMK_XA_TYPE, PCMK_VALUE_STRING);

        expr = pcmk__xe_create(rule, PCMK_XE_DATE_EXPRESSION);
        crm_xml_set_id(expr, "cli-prefer-lifetime-end-%s", rsc_id);
        crm_xml_add(expr, PCMK_XA_OPERATION, PCMK_VALUE_LT);
        crm_xml_add(expr, PCMK_XA_END, later_s);
    }

    crm_log_xml_info(fragment, "Modify");
    rc = cib_conn->cmds->modify(cib_conn, PCMK_XE_CONSTRAINTS, fragment,
                                cib_options);
    rc = pcmk_legacy2rc(rc);

    free_xml(fragment);
    free(later_s);

    if (rc != pcmk_rc_ok && promoted_role_only && strcmp(promoted_role, PCMK__ROLE_PROMOTED) == 0) {
        int preferrc = cli_resource_prefer(out, rsc_id, host, move_lifetime,
                                 cib_conn, cib_options, promoted_role_only,
                                 PCMK__ROLE_PROMOTED_LEGACY);
        if (preferrc == pcmk_rc_ok) {
            rc = preferrc;
        }
    }

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
 * (2) The node could be given by node= in a PCMK_XE_RSC_LOCATION XML node.
 * That's what resource_clear_node_in_location handles. That XML looks like
 * this:
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

#define XPATH_FMT                                                   \
    "//" PCMK_XE_RSC_LOCATION "[@" PCMK_XA_ID "='cli-prefer-%s']"   \
    "[" PCMK_XE_RULE                                                \
        "[@" PCMK_XA_ID "='cli-prefer-rule-%s']"                    \
        "/" PCMK_XE_EXPRESSION                                      \
        "[@" PCMK_XA_ATTRIBUTE "='" CRM_ATTR_UNAME "' "             \
        "and @" PCMK_XA_VALUE "='%s']"                              \
    "]"

    xpath_string = crm_strdup_printf(XPATH_FMT, rsc_id, rsc_id, host);

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

    fragment = pcmk__xe_create(NULL, PCMK_XE_CONSTRAINTS);

    if (clear_ban_constraints == TRUE) {
        location = pcmk__xe_create(fragment, PCMK_XE_RSC_LOCATION);
        crm_xml_set_id(location, "cli-ban-%s-on-%s", rsc_id, host);
    }

    location = pcmk__xe_create(fragment, PCMK_XE_RSC_LOCATION);
    crm_xml_set_id(location, "cli-prefer-%s", rsc_id);
    if (force == FALSE) {
        crm_xml_add(location, PCMK_XE_NODE, host);
    }

    crm_log_xml_info(fragment, "Delete");
    rc = cib_conn->cmds->remove(cib_conn, PCMK_XE_CONSTRAINTS, fragment,
                                cib_options);
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
            pcmk_node_t *target = n->data;

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

static void
build_clear_xpath_string(GString *buf, const xmlNode *constraint_node,
                         const char *rsc, const char *node,
                         bool promoted_role_only)
{
    const char *cons_id = pcmk__xe_id(constraint_node);
    const char *cons_rsc = crm_element_value(constraint_node, PCMK_XA_RSC);
    GString *rsc_role_substr = NULL;
    const char *promoted_role_rule = "@" PCMK_XA_ROLE "='" PCMK__ROLE_PROMOTED
                                     "' or @" PCMK_XA_ROLE "='"
                                     PCMK__ROLE_PROMOTED_LEGACY "'";

    CRM_ASSERT(buf != NULL);
    g_string_truncate(buf, 0);

    if (!pcmk__starts_with(cons_id, "cli-ban-")
        && !pcmk__starts_with(cons_id, "cli-prefer-")) {
        return;
    }

    g_string_append(buf, "//" PCMK_XE_RSC_LOCATION);

    if ((node != NULL) || (rsc != NULL) || promoted_role_only) {
        g_string_append_c(buf, '[');

        if (node != NULL) {
            pcmk__g_strcat(buf, "@" PCMK_XE_NODE "='", node, "'", NULL);

            if (promoted_role_only || (rsc != NULL)) {
                g_string_append(buf, " and ");
            }
        }

        if ((rsc != NULL) && promoted_role_only) {
            rsc_role_substr = g_string_sized_new(64);
            pcmk__g_strcat(rsc_role_substr,
                           "@" PCMK_XA_RSC "='", rsc, "' "
                           "and (" , promoted_role_rule, ")", NULL);

        } else if (rsc != NULL) {
            rsc_role_substr = g_string_sized_new(64);
            pcmk__g_strcat(rsc_role_substr,
                           "@" PCMK_XA_RSC "='", rsc, "'", NULL);

        } else if (promoted_role_only) {
            rsc_role_substr = g_string_sized_new(64);
            g_string_append(rsc_role_substr, promoted_role_rule);
        }

        if (rsc_role_substr != NULL) {
            g_string_append(buf, rsc_role_substr->str);
        }
        g_string_append_c(buf, ']');
    }

    if (node != NULL) {
        g_string_append(buf, "|//" PCMK_XE_RSC_LOCATION);

        if (rsc_role_substr != NULL) {
            pcmk__g_strcat(buf, "[", rsc_role_substr, "]", NULL);
        }
        pcmk__g_strcat(buf,
                       "/" PCMK_XE_RULE "[" PCMK_XE_EXPRESSION
                       "[@" PCMK_XA_ATTRIBUTE "='" CRM_ATTR_UNAME "' "
                       "and @" PCMK_XA_VALUE "='", node, "']]", NULL);
    }

    g_string_append(buf, "//" PCMK_XE_DATE_EXPRESSION "[@" PCMK_XA_ID "='");
    if (pcmk__starts_with(cons_id, "cli-ban-")) {
        pcmk__g_strcat(buf, cons_id, "-lifetime']", NULL);

    } else {    // starts with "cli-prefer-"
        pcmk__g_strcat(buf,
                       "cli-prefer-lifetime-end-", cons_rsc, "']", NULL);
    }

    if (rsc_role_substr != NULL) {
        g_string_free(rsc_role_substr, TRUE);
    }
}

// \return Standard Pacemaker return code
int
cli_resource_clear_all_expired(xmlNode *root, cib_t *cib_conn, int cib_options,
                               const char *rsc, const char *node, gboolean promoted_role_only)
{
    GString *buf = NULL;
    xmlXPathObject *xpathObj = NULL;
    xmlNode *cib_constraints = NULL;
    crm_time_t *now = crm_time_new(NULL);
    int i;
    int rc = pcmk_rc_ok;

    cib_constraints = pcmk_find_cib_element(root, PCMK_XE_CONSTRAINTS);
    xpathObj = xpath_search(cib_constraints, "//" PCMK_XE_RSC_LOCATION);

    for (i = 0; i < numXpathResults(xpathObj); i++) {
        xmlNode *constraint_node = getXpathResult(xpathObj, i);
        xmlNode *date_expr_node = NULL;
        crm_time_t *end = NULL;
        int rc = pcmk_rc_ok;

        if (buf == NULL) {
            buf = g_string_sized_new(1024);
        }

        build_clear_xpath_string(buf, constraint_node, rsc, node,
                                 promoted_role_only);
        if (buf->len == 0) {
            continue;
        }

        date_expr_node = get_xpath_object((const char *) buf->str,
                                          constraint_node, LOG_DEBUG);
        if (date_expr_node == NULL) {
            continue;
        }

        /* And then finally, see if the date expression is expired.  If so,
         * clear the constraint.
         *
         * @COMPAT Check for error once we are rejecting rules with invalid end
         */
        rc = pcmk__xe_get_datetime(date_expr_node, PCMK_XA_END, &end);
        if (rc != pcmk_rc_ok) {
            crm_trace("Invalid " PCMK_XA_END ": %s", pcmk_rc_str(rc));
        }

        if (crm_time_compare(now, end) == 1) {
            xmlNode *fragment = NULL;
            xmlNode *location = NULL;

            fragment = pcmk__xe_create(NULL, PCMK_XE_CONSTRAINTS);
            location = pcmk__xe_create(fragment, PCMK_XE_RSC_LOCATION);
            crm_xml_set_id(location, "%s", pcmk__xe_id(constraint_node));
            crm_log_xml_info(fragment, "Delete");

            rc = cib_conn->cmds->remove(cib_conn, PCMK_XE_CONSTRAINTS, fragment,
                                        cib_options);
            rc = pcmk_legacy2rc(rc);

            if (rc != pcmk_rc_ok) {
                goto done;
            }

            free_xml(fragment);
        }

        crm_time_free(end);
    }

done:
    if (buf != NULL) {
        g_string_free(buf, TRUE);
    }
    freeXpathObject(xpathObj);
    crm_time_free(now);
    return rc;
}
