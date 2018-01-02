
/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_resource.h>

#define cons_string(x) x?x:"NA"
void
cli_resource_print_cts_constraints(pe_working_set_t * data_set)
{
    xmlNode *xml_obj = NULL;
    xmlNode *lifetime = NULL;
    xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, data_set->input);

    for (xml_obj = __xml_first_child(cib_constraints); xml_obj != NULL;
         xml_obj = __xml_next(xml_obj)) {
        const char *id = crm_element_value(xml_obj, XML_ATTR_ID);

        if (id == NULL) {
            continue;
        }

        lifetime = first_named_child(xml_obj, "lifetime");

        if (test_ruleset(lifetime, NULL, data_set->now) == FALSE) {
            continue;
        }

        if (safe_str_eq(XML_CONS_TAG_RSC_DEPEND, crm_element_name(xml_obj))) {
            printf("Constraint %s %s %s %s %s %s %s\n",
                   crm_element_name(xml_obj),
                   cons_string(crm_element_value(xml_obj, XML_ATTR_ID)),
                   cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE)),
                   cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET)),
                   cons_string(crm_element_value(xml_obj, XML_RULE_ATTR_SCORE)),
                   cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_ROLE)),
                   cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET_ROLE)));

        } else if (safe_str_eq(XML_CONS_TAG_RSC_LOCATION, crm_element_name(xml_obj))) {
            /* unpack_location(xml_obj, data_set); */
        }
    }
}

void
cli_resource_print_cts(resource_t * rsc)
{
    GListPtr lpc = NULL;
    const char *host = NULL;
    bool needs_quorum = TRUE;
    const char *rtype = crm_element_value(rsc->xml, XML_ATTR_TYPE);
    const char *rprov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    const char *rclass = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);

    if (safe_str_eq(rclass, PCMK_RESOURCE_CLASS_STONITH)) {
        xmlNode *op = NULL;

        needs_quorum = FALSE;

        for (op = __xml_first_child(rsc->ops_xml); op != NULL; op = __xml_next(op)) {
            if (crm_str_eq((const char *)op->name, "op", TRUE)) {
                const char *name = crm_element_value(op, "name");

                if (safe_str_neq(name, CRMD_ACTION_START)) {
                    const char *value = crm_element_value(op, "requires");

                    if (safe_str_eq(value, "nothing")) {
                        needs_quorum = FALSE;
                    }
                    break;
                }
            }
        }
    }

    if (rsc->running_on != NULL && g_list_length(rsc->running_on) == 1) {
        node_t *tmp = rsc->running_on->data;

        host = tmp->details->uname;
    }

    printf("Resource: %s %s %s %s %s %s %s %s %d %lld 0x%.16llx\n",
           crm_element_name(rsc->xml), rsc->id,
           rsc->clone_name ? rsc->clone_name : rsc->id, rsc->parent ? rsc->parent->id : "NA",
           rprov ? rprov : "NA", rclass, rtype, host ? host : "NA", needs_quorum, rsc->flags,
           rsc->flags);

    for (lpc = rsc->children; lpc != NULL; lpc = lpc->next) {
        resource_t *child = (resource_t *) lpc->data;

        cli_resource_print_cts(child);
    }
}


void
cli_resource_print_raw(resource_t * rsc)
{
    GListPtr lpc = NULL;
    GListPtr children = rsc->children;

    if (children == NULL) {
        printf("%s\n", rsc->id);
    }

    for (lpc = children; lpc != NULL; lpc = lpc->next) {
        resource_t *child = (resource_t *) lpc->data;

        cli_resource_print_raw(child);
    }
}

int
cli_resource_print_list(pe_working_set_t * data_set, bool raw)
{
    int found = 0;

    GListPtr lpc = NULL;
    int opts = pe_print_printf | pe_print_rsconly | pe_print_pending;

    for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
        resource_t *rsc = (resource_t *) lpc->data;

        if (is_set(rsc->flags, pe_rsc_orphan)
            && rsc->fns->active(rsc, TRUE) == FALSE) {
            continue;
        }
        rsc->fns->print(rsc, NULL, opts, stdout);
        found++;
    }

    if (found == 0) {
        printf("NO resources configured\n");
        return -ENXIO;
    }

    return 0;
}

int
cli_resource_print_operations(const char *rsc_id, const char *host_uname, bool active,
                         pe_working_set_t * data_set)
{
    resource_t *rsc = NULL;
    int opts = pe_print_printf | pe_print_rsconly | pe_print_suppres_nl | pe_print_pending;
    GListPtr ops = find_operations(rsc_id, host_uname, active, data_set);
    GListPtr lpc = NULL;

    for (lpc = ops; lpc != NULL; lpc = lpc->next) {
        xmlNode *xml_op = (xmlNode *) lpc->data;

        const char *op_rsc = crm_element_value(xml_op, "resource");
        const char *last = crm_element_value(xml_op, XML_RSC_OP_LAST_CHANGE);
        const char *status_s = crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS);
        const char *op_key = crm_element_value(xml_op, XML_LRM_ATTR_TASK_KEY);
        int status = crm_parse_int(status_s, "0");

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
        if (last) {
            time_t run_at = crm_parse_int(last, "0");

            fprintf(stdout, ", last-rc-change=%s, exec=%sms",
                    crm_strip_trailing_newline(ctime(&run_at)), crm_element_value(xml_op, XML_RSC_OP_T_EXEC));
        }
        fprintf(stdout, "): %s\n", services_lrm_status_str(status));
    }
    return pcmk_ok;
}

void
cli_resource_print_location(resource_t * rsc, const char *prefix)
{
    GListPtr lpc = NULL;
    GListPtr list = rsc->rsc_location;
    int offset = 0;

    if (prefix) {
        offset = strlen(prefix) - 2;
    }

    for (lpc = list; lpc != NULL; lpc = lpc->next) {
        rsc_to_node_t *cons = (rsc_to_node_t *) lpc->data;

        GListPtr lpc2 = NULL;

        for (lpc2 = cons->node_list_rh; lpc2 != NULL; lpc2 = lpc2->next) {
            node_t *node = (node_t *) lpc2->data;
            char *score = score2char(node->weight);

            fprintf(stdout, "%s: Node %-*s (score=%s, id=%s)\n",
                    prefix ? prefix : "  ", 71 - offset, node->details->uname, score, cons->id);
            free(score);
        }
    }
}

void
cli_resource_print_colocation(resource_t * rsc, bool dependents, bool recursive, int offset)
{
    char *prefix = NULL;
    GListPtr lpc = NULL;
    GListPtr list = rsc->rsc_cons;

    prefix = calloc(1, (offset * 4) + 1);
    memset(prefix, ' ', offset * 4);

    if (dependents) {
        list = rsc->rsc_cons_lhs;
    }

    if (is_set(rsc->flags, pe_rsc_allocating)) {
        /* Break colocation loops */
        printf("loop %s\n", rsc->id);
        free(prefix);
        return;
    }

    set_bit(rsc->flags, pe_rsc_allocating);
    for (lpc = list; lpc != NULL; lpc = lpc->next) {
        rsc_colocation_t *cons = (rsc_colocation_t *) lpc->data;

        char *score = NULL;
        resource_t *peer = cons->rsc_rh;

        if (dependents) {
            peer = cons->rsc_lh;
        }

        if (is_set(peer->flags, pe_rsc_allocating)) {
            if (dependents == FALSE) {
                fprintf(stdout, "%s%-*s (id=%s - loop)\n", prefix, 80 - (4 * offset), peer->id,
                        cons->id);
            }
            continue;
        }

        if (dependents && recursive) {
            cli_resource_print_colocation(peer, dependents, recursive, offset + 1);
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
        cli_resource_print_location(peer, prefix);
        free(score);

        if (!dependents && recursive) {
            cli_resource_print_colocation(peer, dependents, recursive, offset + 1);
        }
    }
    free(prefix);
}

int
cli_resource_print(resource_t *rsc, pe_working_set_t *data_set, bool expanded)
{
    char *rsc_xml = NULL;
    int opts = pe_print_printf | pe_print_pending;

    rsc->fns->print(rsc, NULL, opts, stdout);

    rsc_xml = dump_xml_formatted((!expanded && rsc->orig_xml)?
                                 rsc->orig_xml : rsc->xml);
    fprintf(stdout, "%sxml:\n%s\n", expanded ? "" : "raw ", rsc_xml);
    free(rsc_xml);
    return 0;
}

int
cli_resource_print_attribute(resource_t *rsc, const char *attr, pe_working_set_t * data_set)
{
    int rc = -ENXIO;
    node_t *current = NULL;
    GHashTable *params = NULL;
    const char *value = NULL;

    if (g_list_length(rsc->running_on) == 1) {
        current = rsc->running_on->data;

    } else if (g_list_length(rsc->running_on) > 1) {
        CMD_ERR("%s is active on more than one node,"
                " returning the default value for %s", rsc->id, crm_str(attr));
    }

    params = crm_str_table_new();

    if (safe_str_eq(attr_set_type, XML_TAG_ATTR_SETS)) {
        get_rsc_attributes(params, rsc, current, data_set);

    } else if (safe_str_eq(attr_set_type, XML_TAG_META_SETS)) {
        /* No need to redirect to the parent */
        get_meta_attributes(params, rsc, current, data_set);

    } else {
        unpack_instance_attributes(data_set->input, rsc->xml,
                                   XML_TAG_UTILIZATION, NULL,
                                   params, NULL, FALSE, data_set->now);
    }

    crm_debug("Looking up %s in %s", attr, rsc->id);
    value = g_hash_table_lookup(params, attr);
    if (value != NULL) {
        fprintf(stdout, "%s\n", value);
        rc = 0;

    } else {
        CMD_ERR("Attribute '%s' not found for '%s'", attr, rsc->id);
    }

    g_hash_table_destroy(params);
    return rc;
}


int
cli_resource_print_property(resource_t *rsc, const char *attr, pe_working_set_t * data_set)
{
    const char *value = crm_element_value(rsc->xml, attr);

    if (value != NULL) {
        fprintf(stdout, "%s\n", value);
        return 0;
    }
    return -ENXIO;
}
