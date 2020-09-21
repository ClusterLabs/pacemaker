/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_resource.h>
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

        if (pcmk__str_eq(XML_CONS_TAG_RSC_DEPEND, crm_element_name(xml_obj), pcmk__str_casei)) {
            printf("Constraint %s %s %s %s %s %s %s\n",
                   crm_element_name(xml_obj),
                   cons_string(crm_element_value(xml_obj, XML_ATTR_ID)),
                   cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE)),
                   cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET)),
                   cons_string(crm_element_value(xml_obj, XML_RULE_ATTR_SCORE)),
                   cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_ROLE)),
                   cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET_ROLE)));

        } else if (pcmk__str_eq(XML_CONS_TAG_RSC_LOCATION, crm_element_name(xml_obj), pcmk__str_casei)) {
            /* unpack_location(xml_obj, data_set); */
        }
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

    printf("Resource: %s %s %s %s %s %s %s %s %d %lld 0x%.16llx\n",
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
    pe_resource_t *rsc = NULL;
    int opts = pe_print_printf | pe_print_rsconly | pe_print_suppres_nl | pe_print_pending;
    GListPtr ops = find_operations(rsc_id, host_uname, active, data_set);
    GListPtr lpc = NULL;

    for (lpc = ops; lpc != NULL; lpc = lpc->next) {
        xmlNode *xml_op = (xmlNode *) lpc->data;

        const char *op_rsc = crm_element_value(xml_op, "resource");
        const char *status_s = crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS);
        const char *op_key = crm_element_value(xml_op, XML_LRM_ATTR_TASK_KEY);
        int status = crm_parse_int(status_s, "0");
        time_t last_change = 0;

        rsc = pe_find_resource(data_set->resources, op_rsc);
        if(rsc) {
            rsc->fns->print(rsc, "", opts, stdout);
        } else {
            fprintf(stdout, "Unknown resource %s", op_rsc);
        }

        fprintf(stdout, ": %s (node=%s, call=%s, rc=%s",
                op_key ? op_key : ID(xml_op),
                crm_element_value(xml_op, XML_ATTR_UNAME),
                crm_element_value(xml_op, XML_LRM_ATTR_CALLID),
                crm_element_value(xml_op, XML_LRM_ATTR_RC));

        if (crm_element_value_epoch(xml_op, XML_RSC_OP_LAST_CHANGE,
                                    &last_change) == pcmk_ok) {
            fprintf(stdout, ", " XML_RSC_OP_LAST_CHANGE "=%s, exec=%sms",
                    crm_strip_trailing_newline(ctime(&last_change)),
                    crm_element_value(xml_op, XML_RSC_OP_T_EXEC));
        }
        fprintf(stdout, "): %s\n", services_lrm_status_str(status));
    }
    return pcmk_rc_ok;
}

void
cli_resource_print_location(pcmk__output_t *out, pe_resource_t * rsc, const char *prefix)
{
    GListPtr lpc = NULL;
    GListPtr list = rsc->rsc_location;
    int offset = 0;

    if (prefix) {
        offset = strlen(prefix) - 2;
    }

    for (lpc = list; lpc != NULL; lpc = lpc->next) {
        pe__location_t *cons = lpc->data;

        GListPtr lpc2 = NULL;

        for (lpc2 = cons->node_list_rh; lpc2 != NULL; lpc2 = lpc2->next) {
            pe_node_t *node = (pe_node_t *) lpc2->data;
            char *score = score2char(node->weight);

            fprintf(stdout, "%s: Node %-*s (score=%s, id=%s)\n",
                    prefix ? prefix : "  ", 71 - offset, node->details->uname, score, cons->id);
            free(score);
        }
    }
}

void
cli_resource_print_colocation(pcmk__output_t *out, pe_resource_t * rsc,
                              bool dependents, bool recursive, int offset)
{
    char *prefix = NULL;
    GListPtr lpc = NULL;
    GListPtr list = rsc->rsc_cons;

    prefix = calloc(1, (offset * 4) + 1);
    memset(prefix, ' ', offset * 4);

    if (dependents) {
        list = rsc->rsc_cons_lhs;
    }

    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        /* Break colocation loops */
        printf("loop %s\n", rsc->id);
        free(prefix);
        return;
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);
    for (lpc = list; lpc != NULL; lpc = lpc->next) {
        rsc_colocation_t *cons = (rsc_colocation_t *) lpc->data;

        char *score = NULL;
        pe_resource_t *peer = cons->rsc_rh;

        if (dependents) {
            peer = cons->rsc_lh;
        }

        if (pcmk_is_set(peer->flags, pe_rsc_allocating)) {
            if (dependents == FALSE) {
                fprintf(stdout, "%s%-*s (id=%s - loop)\n", prefix, 80 - (4 * offset), peer->id,
                        cons->id);
            }
            continue;
        }

        if (dependents && recursive) {
            cli_resource_print_colocation(out, peer, dependents, recursive, offset + 1);
        }

        score = score2char(cons->score);
        if (cons->role_rh > RSC_ROLE_STARTED) {
            fprintf(stdout, "%s%-*s (score=%s, %s role=%s, id=%s)\n", prefix, 80 - (4 * offset),
                    peer->id, score, dependents ? "needs" : "with", role2text(cons->role_rh),
                    cons->id);
        } else {
            fprintf(stdout, "%s%-*s (score=%s, id=%s)\n", prefix, 80 - (4 * offset),
                    peer->id, score, cons->id);
        }
        cli_resource_print_location(out, peer, prefix);
        free(score);

        if (!dependents && recursive) {
            cli_resource_print_colocation(out, peer, dependents, recursive, offset + 1);
        }
    }
    free(prefix);
}

// \return Standard Pacemaker return code
int
cli_resource_print(pcmk__output_t *out, pe_resource_t *rsc,
                   pe_working_set_t *data_set, bool expanded)
{
    char *rsc_xml = NULL;
    int opts = pe_print_printf | pe_print_pending;

    rsc->fns->print(rsc, NULL, opts, stdout);

    rsc_xml = dump_xml_formatted((!expanded && rsc->orig_xml)?
                                 rsc->orig_xml : rsc->xml);
    fprintf(stdout, "%sxml:\n%s\n", expanded ? "" : "raw ", rsc_xml);
    free(rsc_xml);
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
    { "resource-names-list", "default", resource_names },

    { NULL, NULL, NULL }
};

void
crm_resource_register_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
