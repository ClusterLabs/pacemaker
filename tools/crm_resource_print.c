/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_resource.h>
#include <crm/common/lists_internal.h>
#include <crm/common/xml_internal.h>
#include <crm/common/output_internal.h>

#define cons_string(x) x?x:"NA"
void
cli_resource_print_cts_constraints(pcmk__output_t *out, pe_working_set_t * data_set)
{
    xmlNode *xml_obj = NULL;
    xmlNode *lifetime = NULL;
    xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, data_set->input);

    for (xml_obj = pcmk__xe_first_child(cib_constraints); xml_obj != NULL;
         xml_obj = pcmk__xe_next(xml_obj)) {
        const char *id = crm_element_value(xml_obj, XML_ATTR_ID);

        if (id == NULL) {
            continue;
        }

        // @COMPAT lifetime is deprecated
        lifetime = first_named_child(xml_obj, "lifetime");
        if (pe_evaluate_rules(lifetime, NULL, data_set->now, NULL) == FALSE) {
            continue;
        }

        if (!pcmk__str_eq(XML_CONS_TAG_RSC_DEPEND, crm_element_name(xml_obj), pcmk__str_casei)) {
            continue;
        }

        out->info(out, "Constraint %s %s %s %s %s %s %s",
                  crm_element_name(xml_obj),
                  cons_string(crm_element_value(xml_obj, XML_ATTR_ID)),
                  cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE)),
                  cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET)),
                  cons_string(crm_element_value(xml_obj, XML_RULE_ATTR_SCORE)),
                  cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_ROLE)),
                  cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET_ROLE)));
    }
}

void
cli_resource_print_cts(pcmk__output_t *out, pe_resource_t * rsc)
{
    GListPtr lpc = NULL;
    const char *host = NULL;
    bool needs_quorum = TRUE;
    const char *rtype = crm_element_value(rsc->xml, XML_ATTR_TYPE);
    const char *rprov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    const char *rclass = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    pe_node_t *node = pe__current_node(rsc);

    if (pcmk__str_eq(rclass, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_casei)) {
        needs_quorum = FALSE;
    } else {
        // @TODO check requires in resource meta-data and rsc_defaults
    }

    if (node != NULL) {
        host = node->details->uname;
    }

    out->info(out, "Resource: %s %s %s %s %s %s %s %s %d %lld 0x%.16llx",
              crm_element_name(rsc->xml), rsc->id,
              rsc->clone_name ? rsc->clone_name : rsc->id, rsc->parent ? rsc->parent->id : "NA",
              rprov ? rprov : "NA", rclass, rtype, host ? host : "NA", needs_quorum, rsc->flags,
              rsc->flags);

    for (lpc = rsc->children; lpc != NULL; lpc = lpc->next) {
        pe_resource_t *child = (pe_resource_t *) lpc->data;

        cli_resource_print_cts(out, child);
    }
}

// \return Standard Pacemaker return code
int
cli_resource_print_operations(pcmk__output_t *out, const char *rsc_id,
                              const char *host_uname, bool active,
                              pe_working_set_t * data_set)
{
    int rc = pcmk_rc_no_output;
    GListPtr ops = find_operations(rsc_id, host_uname, active, data_set);

    if (!ops) {
        return rc;
    }

    out->begin_list(out, NULL, NULL, "Resource Operations");
    rc = pcmk_rc_ok;

    for (GListPtr lpc = ops; lpc != NULL; lpc = lpc->next) {
        xmlNode *xml_op = (xmlNode *) lpc->data;
        out->message(out, "node-and-op", data_set, xml_op);
    }

    out->end_list(out);
    return rc;
}

// \return Standard Pacemaker return code
int
cli_resource_print(pcmk__output_t *out, pe_resource_t *rsc,
                   pe_working_set_t *data_set, bool expanded)
{
    unsigned int opts = pe_print_pending;
    GListPtr all = NULL;

    all = g_list_prepend(all, strdup("*"));

    out->begin_list(out, NULL, NULL, "Resource Config");
    out->message(out, crm_map_element_name(rsc->xml), opts, rsc, all, all);
    out->message(out, "resource-config", rsc, !expanded);
    out->end_list(out);

    g_list_free_full(all, free);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("attribute", "pe_resource_t *", "char *", "GHashTable *")
static int
attribute_default(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    char *attr = va_arg(args, char *);
    GHashTable *params = va_arg(args, GHashTable *);

    const char *value = g_hash_table_lookup(params, attr);

    if (value != NULL) {
        out->begin_list(out, NULL, NULL, "Attributes");
        out->list_item(out, attr, "%s", value);
        out->end_list(out);
    } else {
        out->err(out, "Attribute '%s' not found for '%s'", attr, rsc->id);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("attribute", "pe_resource_t *", "char *", "GHashTable *")
static int
attribute_text(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    char *attr = va_arg(args, char *);
    GHashTable *params = va_arg(args, GHashTable *);

    const char *value = g_hash_table_lookup(params, attr);

    if (value != NULL) {
        out->info(out, "%s", value);
    } else {
        out->err(out, "Attribute '%s' not found for '%s'", attr, rsc->id);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("property", "pe_resource_t *", "char *")
static int
property_default(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    char *attr = va_arg(args, char *);

    const char *value = crm_element_value(rsc->xml, attr);

    if (value != NULL) {
        out->begin_list(out, NULL, NULL, "Properties");
        out->list_item(out, attr, "%s", value);
        out->end_list(out);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("property", "pe_resource_t *", "char *")
static int
property_text(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    char *attr = va_arg(args, char *);

    const char *value = crm_element_value(rsc->xml, attr);

    if (value != NULL) {
        out->info(out, "%s", value);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-check", "resource_checks_t *")
static int
resource_check_default(pcmk__output_t *out, va_list args) {
    resource_checks_t *checks = va_arg(args, resource_checks_t *);

    pe_resource_t *parent = uber_parent(checks->rsc);
    int rc = pcmk_rc_no_output;
    bool printed = false;

    if (checks->flags != 0 || checks->lock_node != NULL) {
        printed = true;
        out->begin_list(out, NULL, NULL, "Resource Checks");
    }

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

    if (checks->lock_node) {
        out->list_item(out, "check", "'%s' is locked to node %s due to shutdown",
                       parent->id, checks->lock_node);
    }

    if (printed) {
        out->end_list(out);
        rc = pcmk_rc_ok;
    }

    return rc;
}

PCMK__OUTPUT_ARGS("resource-check", "resource_checks_t *")
static int
resource_check_xml(pcmk__output_t *out, va_list args) {
    resource_checks_t *checks = va_arg(args, resource_checks_t *);

    pe_resource_t *parent = uber_parent(checks->rsc);
    int rc = pcmk_rc_no_output;

    xmlNode *node = pcmk__output_create_xml_node(out, "check",
                                                 "id", parent->id,
                                                 NULL);

    if (pcmk_is_set(checks->flags, rsc_remain_stopped)) {
        xmlSetProp(node, (pcmkXmlStr) "remain_stopped", (pcmkXmlStr) "true");
    }

    if (pcmk_is_set(checks->flags, rsc_unpromotable)) {
        xmlSetProp(node, (pcmkXmlStr) "promotable", (pcmkXmlStr) "false");
    }

    if (pcmk_is_set(checks->flags, rsc_unmanaged)) {
        xmlSetProp(node, (pcmkXmlStr) "unmanaged", (pcmkXmlStr) "true");
    }

    if (checks->lock_node) {
        xmlSetProp(node, (pcmkXmlStr) "locked-to", (pcmkXmlStr) checks->lock_node);
    }

    return rc;
}

PCMK__OUTPUT_ARGS("resource-search", "GListPtr", "pe_resource_t *", "gchar *")
static int
resource_search_default(pcmk__output_t *out, va_list args)
{
    GListPtr nodes = va_arg(args, GListPtr);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    gchar *requested_name = va_arg(args, gchar *);

    bool printed = false;
    int rc = pcmk_rc_no_output;

    if (!out->is_quiet(out) && nodes == NULL) {
        out->err(out, "resource %s is NOT running", requested_name);
        return rc;
    }

    for (GListPtr lpc = nodes; lpc != NULL; lpc = lpc->next) {
        pe_node_t *node = (pe_node_t *) lpc->data;

        if (!printed) {
            out->begin_list(out, NULL, NULL, "Nodes");
            printed = true;
            rc = pcmk_rc_ok;
        }

        if (out->is_quiet(out)) {
            out->list_item(out, "node", "%s", node->details->uname);
        } else {
            const char *state = "";

            if (!pe_rsc_is_clone(rsc) && rsc->fns->state(rsc, TRUE) == RSC_ROLE_MASTER) {
                state = " Master";
            }
            out->list_item(out, "node", "resource %s is running on: %s%s",
                           requested_name, node->details->uname, state);
        }
    }

    if (printed) {
        out->end_list(out);
    }

    return rc;
}


PCMK__OUTPUT_ARGS("resource-search", "GListPtr", "pe_resource_t *", "gchar *")
static int
resource_search_xml(pcmk__output_t *out, va_list args)
{
    GListPtr nodes = va_arg(args, GListPtr);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    gchar *requested_name = va_arg(args, gchar *);

    xmlNode *xml_node = pcmk__output_xml_create_parent(out, "nodes");

    xmlSetProp(xml_node, (pcmkXmlStr) "resource", (pcmkXmlStr) requested_name);

    for (GListPtr lpc = nodes; lpc != NULL; lpc = lpc->next) {
        pe_node_t *node = (pe_node_t *) lpc->data;
        xmlNode *sub_node = pcmk__output_create_xml_text_node(out, "node", node->details->uname);

        if (!pe_rsc_is_clone(rsc) && rsc->fns->state(rsc, TRUE) == RSC_ROLE_MASTER) {
            xmlSetProp(sub_node, (pcmkXmlStr) "state", (pcmkXmlStr) "promoted");
        }
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-why", "cib_t *", "GListPtr", "pe_resource_t *",
                  "pe_node_t *")
static int
resource_why_default(pcmk__output_t *out, va_list args)
{
    cib_t *cib_conn = va_arg(args, cib_t *);
    GListPtr resources = va_arg(args, GListPtr);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_node_t *node = va_arg(args, pe_node_t *);

    const char *host_uname = (node == NULL)? NULL : node->details->uname;

    out->begin_list(out, NULL, NULL, "Resource Reasons");

    if ((rsc == NULL) && (host_uname == NULL)) {
        GListPtr lpc = NULL;
        GListPtr hosts = NULL;

        for (lpc = resources; lpc != NULL; lpc = lpc->next) {
            pe_resource_t *rsc = (pe_resource_t *) lpc->data;
            rsc->fns->location(rsc, &hosts, TRUE);

            if (hosts == NULL) {
                out->list_item(out, "reason", "Resource %s is not running", rsc->id);
            } else {
                out->list_item(out, "reason", "Resource %s is running", rsc->id);
            }

            cli_resource_check(out, cib_conn, rsc);
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

        cli_resource_check(out, cib_conn, rsc);

    } else if ((rsc == NULL) && (host_uname != NULL)) {
        const char* host_uname =  node->details->uname;
        GListPtr allResources = node->details->allocated_rsc;
        GListPtr activeResources = node->details->running_rsc;
        GListPtr unactiveResources = pcmk__subtract_lists(allResources, activeResources, (GCompareFunc) strcmp);
        GListPtr lpc = NULL;

        for (lpc = activeResources; lpc != NULL; lpc = lpc->next) {
            pe_resource_t *rsc = (pe_resource_t *) lpc->data;
            out->list_item(out, "reason", "Resource %s is running on host %s",
                           rsc->id, host_uname);
            cli_resource_check(out, cib_conn, rsc);
        }

        for(lpc = unactiveResources; lpc != NULL; lpc = lpc->next) {
            pe_resource_t *rsc = (pe_resource_t *) lpc->data;
            out->list_item(out, "reason", "Resource %s is assigned to host %s but not running",
                           rsc->id, host_uname);
            cli_resource_check(out, cib_conn, rsc);
        }

        g_list_free(allResources);
        g_list_free(activeResources);
        g_list_free(unactiveResources);

    } else if ((rsc != NULL) && (host_uname == NULL)) {
        GListPtr hosts = NULL;

        rsc->fns->location(rsc, &hosts, TRUE);
        out->list_item(out, "reason", "Resource %s is %srunning",
                       rsc->id, (hosts? "" : "not "));
        cli_resource_check(out, cib_conn, rsc);
        g_list_free(hosts);
    }

    out->end_list(out);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("resource-why", "cib_t *", "GListPtr", "pe_resource_t *",
                  "pe_node_t *")
static int
resource_why_xml(pcmk__output_t *out, va_list args)
{
    cib_t *cib_conn = va_arg(args, cib_t *);
    GListPtr resources = va_arg(args, GListPtr);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    pe_node_t *node = va_arg(args, pe_node_t *);

    const char *host_uname = (node == NULL)? NULL : node->details->uname;

    xmlNode *xml_node = pcmk__output_xml_create_parent(out, "reason");

    if ((rsc == NULL) && (host_uname == NULL)) {
        GListPtr lpc = NULL;
        GListPtr hosts = NULL;

        pcmk__output_xml_create_parent(out, "resources");

        for (lpc = resources; lpc != NULL; lpc = lpc->next) {
            pe_resource_t *rsc = (pe_resource_t *) lpc->data;
            xmlNode *rsc_node = NULL;

            rsc->fns->location(rsc, &hosts, TRUE);

            rsc_node = pcmk__output_xml_create_parent(out, "resource");
            xmlSetProp(rsc_node, (pcmkXmlStr) "id", (pcmkXmlStr) rsc->id);
            xmlSetProp(rsc_node, (pcmkXmlStr) "running",
                       (pcmkXmlStr) pcmk__btoa(hosts != NULL));

            cli_resource_check(out, cib_conn, rsc);
            pcmk__output_xml_pop_parent(out);
            g_list_free(hosts);
            hosts = NULL;
        }

        pcmk__output_xml_pop_parent(out);

    } else if ((rsc != NULL) && (host_uname != NULL)) {
        if (resource_is_running_on(rsc, host_uname)) {
            xmlSetProp(xml_node, (pcmkXmlStr) "running_on", (pcmkXmlStr) host_uname);
        }

        cli_resource_check(out, cib_conn, rsc);

    } else if ((rsc == NULL) && (host_uname != NULL)) {
        const char* host_uname =  node->details->uname;
        GListPtr allResources = node->details->allocated_rsc;
        GListPtr activeResources = node->details->running_rsc;
        GListPtr unactiveResources = pcmk__subtract_lists(allResources, activeResources, (GCompareFunc) strcmp);
        GListPtr lpc = NULL;

        pcmk__output_xml_create_parent(out, "resources");

        for (lpc = activeResources; lpc != NULL; lpc = lpc->next) {
            pe_resource_t *rsc = (pe_resource_t *) lpc->data;
            xmlNode *rsc_node = NULL;

            rsc_node = pcmk__output_xml_create_parent(out, "resource");
            xmlSetProp(rsc_node, (pcmkXmlStr) "id", (pcmkXmlStr) rsc->id);
            xmlSetProp(rsc_node, (pcmkXmlStr) "running", (pcmkXmlStr) "true");
            xmlSetProp(rsc_node, (pcmkXmlStr) "host", (pcmkXmlStr) host_uname);

            cli_resource_check(out, cib_conn, rsc);
            pcmk__output_xml_pop_parent(out);
        }

        for(lpc = unactiveResources; lpc != NULL; lpc = lpc->next) {
            pe_resource_t *rsc = (pe_resource_t *) lpc->data;
            xmlNode *rsc_node = NULL;

            rsc_node = pcmk__output_xml_create_parent(out, "resource");
            xmlSetProp(rsc_node, (pcmkXmlStr) "id", (pcmkXmlStr) rsc->id);
            xmlSetProp(rsc_node, (pcmkXmlStr) "running", (pcmkXmlStr) "false");
            xmlSetProp(rsc_node, (pcmkXmlStr) "host", (pcmkXmlStr) host_uname);

            cli_resource_check(out, cib_conn, rsc);
            pcmk__output_xml_pop_parent(out);
        }

        pcmk__output_xml_pop_parent(out);
        g_list_free(allResources);
        g_list_free(activeResources);
        g_list_free(unactiveResources);

    } else if ((rsc != NULL) && (host_uname == NULL)) {
        GListPtr hosts = NULL;

        rsc->fns->location(rsc, &hosts, TRUE);
        xmlSetProp(xml_node, (pcmkXmlStr) "running",
                   (pcmkXmlStr) pcmk__btoa(hosts != NULL));
        cli_resource_check(out, cib_conn, rsc);
        g_list_free(hosts);
    }

    return pcmk_rc_ok;
}

static void
add_resource_name(pcmk__output_t *out, pe_resource_t *rsc) {
    if (rsc->children == NULL) {
        out->list_item(out, "resource", "%s", rsc->id);
    } else {
        for (GListPtr lpc = rsc->children; lpc != NULL; lpc = lpc->next) {
            pe_resource_t *child = (pe_resource_t *) lpc->data;
            add_resource_name(out, child);
        }
    }
}

PCMK__OUTPUT_ARGS("resource-names-list", "GListPtr")
static int
resource_names(pcmk__output_t *out, va_list args) {
    GListPtr resources = va_arg(args, GListPtr);

    if (resources == NULL) {
        out->err(out, "NO resources configured\n");
        return pcmk_rc_no_output;
    }

    out->begin_list(out, NULL, NULL, "Resource Names");

    for (GListPtr lpc = resources; lpc != NULL; lpc = lpc->next) {
        pe_resource_t *rsc = (pe_resource_t *) lpc->data;
        add_resource_name(out, rsc);
    }

    out->end_list(out);
    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "attribute", "default", attribute_default },
    { "attribute", "text", attribute_text },
    { "property", "default", property_default },
    { "property", "text", property_text },
    { "resource-check", "default", resource_check_default },
    { "resource-check", "xml", resource_check_xml },
    { "resource-search", "default", resource_search_default },
    { "resource-search", "xml", resource_search_xml },
    { "resource-why", "default", resource_why_default },
    { "resource-why", "xml", resource_why_xml },
    { "resource-names-list", "default", resource_names },

    { NULL, NULL, NULL }
};

void
crm_resource_register_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
