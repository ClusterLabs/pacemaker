/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>

#include <crm_resource.h>
#include <crm/common/lists_internal.h>
#include <crm/common/output.h>
#include <crm/common/results.h>

#define cons_string(x) x?x:"NA"
static int
print_constraint(xmlNode *xml_obj, void *userdata)
{
    pcmk_scheduler_t *scheduler = (pcmk_scheduler_t *) userdata;
    pcmk__output_t *out = scheduler->priv;
    xmlNode *lifetime = NULL;
    const char *id = crm_element_value(xml_obj, PCMK_XA_ID);

    if (id == NULL) {
        return pcmk_rc_ok;
    }

    // @COMPAT lifetime is deprecated
    lifetime = first_named_child(xml_obj, "lifetime");
    if (pe_evaluate_rules(lifetime, NULL, scheduler->now, NULL) == FALSE) {
        return pcmk_rc_ok;
    }

    if (!pcmk__xe_is(xml_obj, PCMK_XE_RSC_COLOCATION)) {
        return pcmk_rc_ok;
    }

    out->info(out, "Constraint %s %s %s %s %s %s %s",
              xml_obj->name,
              cons_string(crm_element_value(xml_obj, PCMK_XA_ID)),
              cons_string(crm_element_value(xml_obj, PCMK_XA_RSC)),
              cons_string(crm_element_value(xml_obj, PCMK_XA_WITH_RSC)),
              cons_string(crm_element_value(xml_obj, PCMK_XA_SCORE)),
              cons_string(crm_element_value(xml_obj, PCMK_XA_RSC_ROLE)),
              cons_string(crm_element_value(xml_obj, PCMK_XA_WITH_RSC_ROLE)));

    return pcmk_rc_ok;
}

void
cli_resource_print_cts_constraints(pcmk_scheduler_t *scheduler)
{
    pcmk__xe_foreach_child(pcmk_find_cib_element(scheduler->input,
                                                 PCMK_XE_CONSTRAINTS),
                           NULL, print_constraint, scheduler);
}

void
cli_resource_print_cts(pcmk_resource_t *rsc, pcmk__output_t *out)
{
    const char *host = NULL;
    bool needs_quorum = TRUE;
    const char *rtype = crm_element_value(rsc->xml, PCMK_XA_TYPE);
    const char *rprov = crm_element_value(rsc->xml, PCMK_XA_PROVIDER);
    const char *rclass = crm_element_value(rsc->xml, PCMK_XA_CLASS);
    pcmk_node_t *node = pcmk__current_node(rsc);

    if (pcmk__str_eq(rclass, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_casei)) {
        needs_quorum = FALSE;
    } else {
        // @TODO check requires in resource meta-data and rsc_defaults
    }

    if (node != NULL) {
        host = node->details->uname;
    }

    out->info(out, "Resource: %s %s %s %s %s %s %s %s %d %lld %#.16llx",
              rsc->xml->name, rsc->id,
              rsc->clone_name ? rsc->clone_name : rsc->id, rsc->parent ? rsc->parent->id : "NA",
              rprov ? rprov : "NA", rclass, rtype, host ? host : "NA", needs_quorum, rsc->flags,
              rsc->flags);

    g_list_foreach(rsc->children, (GFunc) cli_resource_print_cts, out);
}

// \return Standard Pacemaker return code
int
cli_resource_print_operations(const char *rsc_id, const char *host_uname,
                              bool active, pcmk_scheduler_t *scheduler)
{
    pcmk__output_t *out = scheduler->priv;
    int rc = pcmk_rc_no_output;
    GList *ops = find_operations(rsc_id, host_uname, active, scheduler);

    if (!ops) {
        return rc;
    }

    out->begin_list(out, NULL, NULL, "Resource Operations");
    rc = pcmk_rc_ok;

    for (GList *lpc = ops; lpc != NULL; lpc = lpc->next) {
        xmlNode *xml_op = (xmlNode *) lpc->data;
        out->message(out, "node-and-op", scheduler, xml_op);
    }

    out->end_list(out);
    return rc;
}

// \return Standard Pacemaker return code
int
cli_resource_print(pcmk_resource_t *rsc, pcmk_scheduler_t *scheduler,
                   bool expanded)
{
    pcmk__output_t *out = scheduler->priv;
    uint32_t show_opts = pcmk_show_pending;
    GList *all = NULL;

    all = g_list_prepend(all, (gpointer) "*");

    out->begin_list(out, NULL, NULL, "Resource Config");
    out->message(out, crm_map_element_name(rsc->xml), show_opts, rsc, all, all);
    out->message(out, "resource-config", rsc, !expanded);
    out->end_list(out);

    g_list_free(all);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("attribute-list", "pcmk_resource_t *", "const char *",
                  "const char *")
static int
attribute_list_default(pcmk__output_t *out, va_list args) {
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    const char *attr = va_arg(args, char *);
    const char *value = va_arg(args, const char *);

    if (value != NULL) {
        out->begin_list(out, NULL, NULL, "Attributes");
        out->list_item(out, attr, "%s", value);
        out->end_list(out);
        return pcmk_rc_ok;
    } else {
        out->err(out, "Attribute '%s' not found for '%s'", attr, rsc->id);
    }
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("agent-status", "int", "const char *", "const char *", "const char *",
                  "const char *", "const char *", "crm_exit_t", "const char *")
static int
agent_status_default(pcmk__output_t *out, va_list args) {
    int status = va_arg(args, int);
    const char *action = va_arg(args, const char *);
    const char *name = va_arg(args, const char *);
    const char *class = va_arg(args, const char *);
    const char *provider = va_arg(args, const char *);
    const char *type = va_arg(args, const char *);
    crm_exit_t rc = va_arg(args, crm_exit_t);
    const char *exit_reason = va_arg(args, const char *);

    if (status == PCMK_EXEC_DONE) {
        /* Operation <action> [for <resource>] (<class>[:<provider>]:<agent>)
         * returned <exit-code> (<exit-description>[: <exit-reason>])
         */
        out->info(out, "Operation %s%s%s (%s%s%s:%s) returned %d (%s%s%s)",
                  action,
                  ((name == NULL)? "" : " for "), ((name == NULL)? "" : name),
                  class,
                  ((provider == NULL)? "" : ":"),
                  ((provider == NULL)? "" : provider),
                  type, (int) rc, services_ocf_exitcode_str((int) rc),
                  ((exit_reason == NULL)? "" : ": "),
                  ((exit_reason == NULL)? "" : exit_reason));
    } else {
        /* Operation <action> [for <resource>] (<class>[:<provider>]:<agent>)
         * could not be executed (<execution-status>[: <exit-reason>])
         */
        out->err(out,
                 "Operation %s%s%s (%s%s%s:%s) could not be executed (%s%s%s)",
                 action,
                 ((name == NULL)? "" : " for "), ((name == NULL)? "" : name),
                 class,
                 ((provider == NULL)? "" : ":"),
                 ((provider == NULL)? "" : provider),
                 type, pcmk_exec_status_str(status),
                 ((exit_reason == NULL)? "" : ": "),
                 ((exit_reason == NULL)? "" : exit_reason));
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("agent-status", "int", "const char *", "const char *", "const char *",
                  "const char *", "const char *", "crm_exit_t", "const char *")
static int
agent_status_xml(pcmk__output_t *out, va_list args) {
    int status = va_arg(args, int);
    const char *action G_GNUC_UNUSED = va_arg(args, const char *);
    const char *name G_GNUC_UNUSED = va_arg(args, const char *);
    const char *class G_GNUC_UNUSED = va_arg(args, const char *);
    const char *provider G_GNUC_UNUSED = va_arg(args, const char *);
    const char *type G_GNUC_UNUSED = va_arg(args, const char *);
    crm_exit_t rc = va_arg(args, crm_exit_t);
    const char *exit_reason = va_arg(args, const char *);

    char *exit_s = pcmk__itoa(rc);
    char *status_str = pcmk__itoa(status);

    pcmk__output_create_xml_node(out, "agent-status",
                                 PCMK_XA_CODE, exit_s,
                                 "message", services_ocf_exitcode_str((int) rc),
                                 "execution_code", status_str,
                                 "execution_message", pcmk_exec_status_str(status),
                                 PCMK_XA_REASON, exit_reason,
                                 NULL);

    free(exit_s);
    free(status_str);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("attribute-list", "pcmk_resource_t *", "const char *",
                  "const char *")
static int
attribute_list_text(pcmk__output_t *out, va_list args) {
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    const char *attr = va_arg(args, char *);
    const char *value = va_arg(args, const char *);

    if (value != NULL) {
        pcmk__formatted_printf(out, "%s\n", value);
        return pcmk_rc_ok;
    } else {
        out->err(out, "Attribute '%s' not found for '%s'", attr, rsc->id);
    }
    return pcmk_rc_ok;
}
PCMK__OUTPUT_ARGS("override", "const char *", "const char *", "const char *")
static int
override_default(pcmk__output_t *out, va_list args) {
    const char *rsc_name = va_arg(args, const char *);
    const char *name = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);

    if (rsc_name == NULL) {
        out->list_item(out, NULL, "Overriding the cluster configuration with '%s' = '%s'",
                       name, value);
    } else {
        out->list_item(out, NULL, "Overriding the cluster configuration for '%s' with '%s' = '%s'",
                       rsc_name, name, value);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("override", "const char *", "const char *", "const char *")
static int
override_xml(pcmk__output_t *out, va_list args) {
    const char *rsc_name = va_arg(args, const char *);
    const char *name = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);

    xmlNodePtr node = pcmk__output_create_xml_node(out, "override",
                                                   PCMK_XA_NAME, name,
                                                   PCMK_XA_VALUE, value,
                                                   NULL);

    if (rsc_name != NULL) {
        crm_xml_add(node, PCMK_XA_RSC, rsc_name);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("property-list", "pcmk_resource_t *", "const char *")
static int
property_list_default(pcmk__output_t *out, va_list args) {
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    const char *attr = va_arg(args, char *);

    const char *value = crm_element_value(rsc->xml, attr);

    if (value != NULL) {
        out->begin_list(out, NULL, NULL, "Properties");
        out->list_item(out, attr, "%s", value);
        out->end_list(out);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("property-list", "pcmk_resource_t *", "const char *")
static int
property_list_text(pcmk__output_t *out, va_list args) {
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    const char *attr = va_arg(args, const char *);

    const char *value = crm_element_value(rsc->xml, attr);

    if (value != NULL) {
        pcmk__formatted_printf(out, "%s\n", value);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-agent-action", "int", "const char *", "const char *",
                  "const char *", "const char *", "const char *", "GHashTable *",
                  "crm_exit_t", "int", "const char *", "const char *", "const char *")
static int
resource_agent_action_default(pcmk__output_t *out, va_list args) {
    int verbose = va_arg(args, int);

    const char *class = va_arg(args, const char *);
    const char *provider = va_arg(args, const char *);
    const char *type = va_arg(args, const char *);
    const char *rsc_name = va_arg(args, const char *);
    const char *action = va_arg(args, const char *);
    GHashTable *overrides = va_arg(args, GHashTable *);
    crm_exit_t rc = va_arg(args, crm_exit_t);
    int status = va_arg(args, int);
    const char *exit_reason = va_arg(args, const char *);
    const char *stdout_data = va_arg(args, const char *);
    const char *stderr_data = va_arg(args, const char *);

    if (overrides) {
        GHashTableIter iter;
        const char *name = NULL;
        const char *value = NULL;

        out->begin_list(out, NULL, NULL, "overrides");

        g_hash_table_iter_init(&iter, overrides);
        while (g_hash_table_iter_next(&iter, (gpointer *) &name, (gpointer *) &value)) {
            out->message(out, "override", rsc_name, name, value);
        }

        out->end_list(out);
    }

    out->message(out, "agent-status", status, action, rsc_name, class, provider,
                 type, rc, exit_reason);

    /* hide output for validate-all if not in verbose */
    if ((verbose == 0)
        && pcmk__str_eq(action, PCMK_ACTION_VALIDATE_ALL, pcmk__str_casei)) {
        return pcmk_rc_ok;
    }

    if (stdout_data || stderr_data) {
        xmlNodePtr doc = NULL;

        if (stdout_data != NULL) {
            doc = string2xml(stdout_data);
        }
        if (doc != NULL) {
            out->output_xml(out, PCMK_XE_COMMAND, stdout_data);
            xmlFreeNode(doc);
        } else {
            out->subprocess_output(out, rc, stdout_data, stderr_data);
        }
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-agent-action", "int", "const char *", "const char *",
                  "const char *", "const char *", "const char *", "GHashTable *",
                  "crm_exit_t", "int", "const char *", "const char *", "const char *")
static int
resource_agent_action_xml(pcmk__output_t *out, va_list args) {
    int verbose G_GNUC_UNUSED = va_arg(args, int);

    const char *class = va_arg(args, const char *);
    const char *provider = va_arg(args, const char *);
    const char *type = va_arg(args, const char *);
    const char *rsc_name = va_arg(args, const char *);
    const char *action = va_arg(args, const char *);
    GHashTable *overrides = va_arg(args, GHashTable *);
    crm_exit_t rc = va_arg(args, crm_exit_t);
    int status = va_arg(args, int);
    const char *exit_reason = va_arg(args, const char *);
    const char *stdout_data = va_arg(args, const char *);
    const char *stderr_data = va_arg(args, const char *);

    xmlNodePtr node = pcmk__output_xml_create_parent(out, "resource-agent-action",
                                                     PCMK_XA_ACTION, action,
                                                     PCMK_XA_CLASS, class,
                                                     PCMK_XA_TYPE, type,
                                                     NULL);

    if (rsc_name) {
        crm_xml_add(node, PCMK_XA_RSC, rsc_name);
    }

    crm_xml_add(node, PCMK_XA_PROVIDER, provider);

    if (overrides) {
        GHashTableIter iter;
        const char *name = NULL;
        const char *value = NULL;

        out->begin_list(out, NULL, NULL, "overrides");

        g_hash_table_iter_init(&iter, overrides);
        while (g_hash_table_iter_next(&iter, (gpointer *) &name, (gpointer *) &value)) {
            out->message(out, "override", rsc_name, name, value);
        }

        out->end_list(out);
    }

    out->message(out, "agent-status", status, action, rsc_name, class, provider,
                 type, rc, exit_reason);

    if (stdout_data || stderr_data) {
        xmlNodePtr doc = NULL;

        if (stdout_data != NULL) {
            doc = string2xml(stdout_data);
        }
        if (doc != NULL) {
            out->output_xml(out, PCMK_XE_COMMAND, stdout_data);
            xmlFreeNode(doc);
        } else {
            out->subprocess_output(out, rc, stdout_data, stderr_data);
        }
    }

    pcmk__output_xml_pop_parent(out);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-check-list", "resource_checks_t *")
static int
resource_check_list_default(pcmk__output_t *out, va_list args) {
    resource_checks_t *checks = va_arg(args, resource_checks_t *);

    const pcmk_resource_t *parent = pe__const_top_resource(checks->rsc, false);

    if (checks->flags == 0) {
        return pcmk_rc_no_output;
    }

    out->begin_list(out, NULL, NULL, "Resource Checks");

    if (pcmk_is_set(checks->flags, rsc_remain_stopped)) {
        out->list_item(out, "check", "Configuration specifies '%s' should remain stopped",
                       parent->id);
    }

    if (pcmk_is_set(checks->flags, rsc_unpromotable)) {
        out->list_item(out, "check", "Configuration specifies '%s' should not be promoted",
                       parent->id);
    }

    if (pcmk_is_set(checks->flags, rsc_unmanaged)) {
        out->list_item(out, "check", "Configuration prevents cluster from stopping or starting unmanaged '%s'",
                       parent->id);
    }

    if (pcmk_is_set(checks->flags, rsc_locked)) {
        out->list_item(out, "check", "'%s' is locked to node %s due to shutdown",
                       parent->id, checks->lock_node);
    }

    if (pcmk_is_set(checks->flags, rsc_node_health)) {
        out->list_item(out, "check",
                       "'%s' cannot run on unhealthy nodes due to "
                       PCMK_OPT_NODE_HEALTH_STRATEGY "='%s'",
                       parent->id,
                       pcmk__cluster_option(checks->rsc->cluster->config_hash,
                                            PCMK_OPT_NODE_HEALTH_STRATEGY));
    }

    out->end_list(out);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-check-list", "resource_checks_t *")
static int
resource_check_list_xml(pcmk__output_t *out, va_list args) {
    resource_checks_t *checks = va_arg(args, resource_checks_t *);

    const pcmk_resource_t *parent = pe__const_top_resource(checks->rsc, false);

    xmlNodePtr node = pcmk__output_create_xml_node(out, "check",
                                                   PCMK_XA_ID, parent->id,
                                                   NULL);

    if (pcmk_is_set(checks->flags, rsc_remain_stopped)) {
        pcmk__xe_set_bool_attr(node, "remain_stopped", true);
    }

    if (pcmk_is_set(checks->flags, rsc_unpromotable)) {
        pcmk__xe_set_bool_attr(node, "promotable", false);
    }

    if (pcmk_is_set(checks->flags, rsc_unmanaged)) {
        pcmk__xe_set_bool_attr(node, "unmanaged", true);
    }

    if (pcmk_is_set(checks->flags, rsc_locked)) {
        crm_xml_add(node, "locked-to", checks->lock_node);
    }

    if (pcmk_is_set(checks->flags, rsc_node_health)) {
        pcmk__xe_set_bool_attr(node, "unhealthy", true);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-search-list", "GList *", "const char *")
static int
resource_search_list_default(pcmk__output_t *out, va_list args)
{
    GList *nodes = va_arg(args, GList *);
    const char *requested_name = va_arg(args, const char *);

    bool printed = false;
    int rc = pcmk_rc_no_output;

    if (!out->is_quiet(out) && nodes == NULL) {
        out->err(out, "resource %s is NOT running", requested_name);
        return rc;
    }

    for (GList *lpc = nodes; lpc != NULL; lpc = lpc->next) {
        node_info_t *ni = (node_info_t *) lpc->data;

        if (!printed) {
            out->begin_list(out, NULL, NULL, "Nodes");
            printed = true;
            rc = pcmk_rc_ok;
        }

        if (out->is_quiet(out)) {
            out->list_item(out, "node", "%s", ni->node_name);
        } else {
            const char *role_text = "";

            if (ni->promoted) {
#ifdef PCMK__COMPAT_2_0
                role_text = " " PCMK__ROLE_PROMOTED_LEGACY;
#else
                role_text = " " PCMK__ROLE_PROMOTED;
#endif
            }
            out->list_item(out, "node", "resource %s is running on: %s%s",
                           requested_name, ni->node_name, role_text);
        }
    }

    if (printed) {
        out->end_list(out);
    }

    return rc;
}

PCMK__OUTPUT_ARGS("resource-search-list", "GList *", "const char *")
static int
resource_search_list_xml(pcmk__output_t *out, va_list args)
{
    GList *nodes = va_arg(args, GList *);
    const char *requested_name = va_arg(args, const char *);

    pcmk__output_xml_create_parent(out, PCMK_XE_NODES,
                                   PCMK_XA_RESOURCE, requested_name,
                                   NULL);

    for (GList *lpc = nodes; lpc != NULL; lpc = lpc->next) {
        node_info_t *ni = (node_info_t *) lpc->data;
        xmlNodePtr sub_node = pcmk__output_create_xml_text_node(out,
                                                                PCMK_XE_NODE,
                                                                ni->node_name);

        if (ni->promoted) {
            crm_xml_add(sub_node, "state", "promoted");
        }
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-reasons-list", "GList *", "pcmk_resource_t *",
                  "pcmk_node_t *")
static int
resource_reasons_list_default(pcmk__output_t *out, va_list args)
{
    GList *resources = va_arg(args, GList *);
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    pcmk_node_t *node = va_arg(args, pcmk_node_t *);

    const char *host_uname = (node == NULL)? NULL : node->details->uname;

    out->begin_list(out, NULL, NULL, "Resource Reasons");

    if ((rsc == NULL) && (host_uname == NULL)) {
        GList *lpc = NULL;
        GList *hosts = NULL;

        for (lpc = resources; lpc != NULL; lpc = lpc->next) {
            pcmk_resource_t *rsc = (pcmk_resource_t *) lpc->data;
            rsc->fns->location(rsc, &hosts, TRUE);

            if (hosts == NULL) {
                out->list_item(out, "reason", "Resource %s is not running", rsc->id);
            } else {
                out->list_item(out, "reason", "Resource %s is running", rsc->id);
            }

            cli_resource_check(out, rsc, NULL);
            g_list_free(hosts);
            hosts = NULL;
        }

    } else if ((rsc != NULL) && (host_uname != NULL)) {
        if (resource_is_running_on(rsc, host_uname)) {
            out->list_item(out, "reason", "Resource %s is running on host %s",
                           rsc->id, host_uname);
        } else {
            out->list_item(out, "reason", "Resource %s is not running on host %s",
                           rsc->id, host_uname);
        }

        cli_resource_check(out, rsc, node);

    } else if ((rsc == NULL) && (host_uname != NULL)) {
        const char* host_uname =  node->details->uname;
        GList *allResources = node->details->allocated_rsc;
        GList *activeResources = node->details->running_rsc;
        GList *unactiveResources = pcmk__subtract_lists(allResources, activeResources, (GCompareFunc) strcmp);
        GList *lpc = NULL;

        for (lpc = activeResources; lpc != NULL; lpc = lpc->next) {
            pcmk_resource_t *rsc = (pcmk_resource_t *) lpc->data;
            out->list_item(out, "reason", "Resource %s is running on host %s",
                           rsc->id, host_uname);
            cli_resource_check(out, rsc, node);
        }

        for(lpc = unactiveResources; lpc != NULL; lpc = lpc->next) {
            pcmk_resource_t *rsc = (pcmk_resource_t *) lpc->data;
            out->list_item(out, "reason", "Resource %s is assigned to host %s but not running",
                           rsc->id, host_uname);
            cli_resource_check(out, rsc, node);
        }

        g_list_free(allResources);
        g_list_free(activeResources);
        g_list_free(unactiveResources);

    } else if ((rsc != NULL) && (host_uname == NULL)) {
        GList *hosts = NULL;

        rsc->fns->location(rsc, &hosts, TRUE);
        out->list_item(out, "reason", "Resource %s is %srunning",
                       rsc->id, (hosts? "" : "not "));
        cli_resource_check(out, rsc, NULL);
        g_list_free(hosts);
    }

    out->end_list(out);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-reasons-list", "GList *", "pcmk_resource_t *",
                  "pcmk_node_t *")
static int
resource_reasons_list_xml(pcmk__output_t *out, va_list args)
{
    GList *resources = va_arg(args, GList *);
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    pcmk_node_t *node = va_arg(args, pcmk_node_t *);

    const char *host_uname = (node == NULL)? NULL : node->details->uname;

    xmlNodePtr xml_node = pcmk__output_xml_create_parent(out, "reason", NULL);

    if ((rsc == NULL) && (host_uname == NULL)) {
        GList *lpc = NULL;
        GList *hosts = NULL;

        pcmk__output_xml_create_parent(out, PCMK_XE_RESOURCES, NULL);

        for (lpc = resources; lpc != NULL; lpc = lpc->next) {
            pcmk_resource_t *rsc = (pcmk_resource_t *) lpc->data;
            const char *running = NULL;

            rsc->fns->location(rsc, &hosts, TRUE);
            running = pcmk__btoa(hosts != NULL);

            pcmk__output_xml_create_parent(out, PCMK_XE_RESOURCE,
                                           PCMK_XA_ID, rsc->id,
                                           PCMK_XA_RUNNING, running,
                                           NULL);

            cli_resource_check(out, rsc, NULL);
            pcmk__output_xml_pop_parent(out);
            g_list_free(hosts);
            hosts = NULL;
        }

        pcmk__output_xml_pop_parent(out);

    } else if ((rsc != NULL) && (host_uname != NULL)) {
        if (resource_is_running_on(rsc, host_uname)) {
            crm_xml_add(xml_node, "running_on", host_uname);
        }

        cli_resource_check(out, rsc, node);

    } else if ((rsc == NULL) && (host_uname != NULL)) {
        const char* host_uname =  node->details->uname;
        GList *allResources = node->details->allocated_rsc;
        GList *activeResources = node->details->running_rsc;
        GList *unactiveResources = pcmk__subtract_lists(allResources, activeResources, (GCompareFunc) strcmp);
        GList *lpc = NULL;

        pcmk__output_xml_create_parent(out, PCMK_XE_RESOURCES, NULL);

        for (lpc = activeResources; lpc != NULL; lpc = lpc->next) {
            pcmk_resource_t *rsc = (pcmk_resource_t *) lpc->data;

            pcmk__output_xml_create_parent(out, PCMK_XE_RESOURCE,
                                           PCMK_XA_ID, rsc->id,
                                           PCMK_XA_RUNNING, PCMK_VALUE_TRUE,
                                           PCMK_XA_HOST, host_uname,
                                           NULL);

            cli_resource_check(out, rsc, node);
            pcmk__output_xml_pop_parent(out);
        }

        for(lpc = unactiveResources; lpc != NULL; lpc = lpc->next) {
            pcmk_resource_t *rsc = (pcmk_resource_t *) lpc->data;

            pcmk__output_xml_create_parent(out, PCMK_XE_RESOURCE,
                                           PCMK_XA_ID, rsc->id,
                                           PCMK_XA_RUNNING, PCMK_VALUE_FALSE,
                                           PCMK_XA_HOST, host_uname,
                                           NULL);

            cli_resource_check(out, rsc, node);
            pcmk__output_xml_pop_parent(out);
        }

        pcmk__output_xml_pop_parent(out);
        g_list_free(allResources);
        g_list_free(activeResources);
        g_list_free(unactiveResources);

    } else if ((rsc != NULL) && (host_uname == NULL)) {
        GList *hosts = NULL;

        rsc->fns->location(rsc, &hosts, TRUE);
        crm_xml_add(xml_node, PCMK_XA_RUNNING, pcmk__btoa(hosts != NULL));
        cli_resource_check(out, rsc, NULL);
        g_list_free(hosts);
    }

    return pcmk_rc_ok;
}

static void
add_resource_name(pcmk_resource_t *rsc, pcmk__output_t *out)
{
    if (rsc->children == NULL) {
        /* Sometimes PCMK_XE_RESOURCE might act as a PCMK_XA_NAME instead of an
         * XML element name, depending on whether the command line causes
         * --xml-simple-list to be forced.
         */
        out->list_item(out, PCMK_XE_RESOURCE, "%s", rsc->id);
    } else {
        g_list_foreach(rsc->children, (GFunc) add_resource_name, out);
    }
}

PCMK__OUTPUT_ARGS("resource-names-list", "GList *")
static int
resource_names(pcmk__output_t *out, va_list args) {
    GList *resources = va_arg(args, GList *);

    if (resources == NULL) {
        out->err(out, "NO resources configured\n");
        return pcmk_rc_no_output;
    }

    out->begin_list(out, NULL, NULL, "Resource Names");
    g_list_foreach(resources, (GFunc) add_resource_name, out);
    out->end_list(out);
    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "agent-status", "default", agent_status_default },
    { "agent-status", "xml", agent_status_xml },
    { "attribute-list", "default", attribute_list_default },
    { "attribute-list", "text", attribute_list_text },
    { "override", "default", override_default },
    { "override", "xml", override_xml },
    { "property-list", "default", property_list_default },
    { "property-list", "text", property_list_text },
    { "resource-agent-action", "default", resource_agent_action_default },
    { "resource-agent-action", "xml", resource_agent_action_xml },
    { "resource-check-list", "default", resource_check_list_default },
    { "resource-check-list", "xml", resource_check_list_xml },
    { "resource-search-list", "default", resource_search_list_default },
    { "resource-search-list", "xml", resource_search_list_xml },
    { "resource-reasons-list", "default", resource_reasons_list_default },
    { "resource-reasons-list", "xml", resource_reasons_list_xml },
    { "resource-names-list", "default", resource_names },

    { NULL, NULL, NULL }
};

void
crm_resource_register_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
