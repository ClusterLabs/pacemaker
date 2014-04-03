/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include <unpack.h>
#include <crm/msg_xml.h>

#define VARIANT_CLONE 1
#include "./variant.h"

void clone_create_notifications(resource_t * rsc, action_t * action, action_t * action_complete,
                                pe_working_set_t * data_set);
void force_non_unique_clone(resource_t * rsc, const char *rid, pe_working_set_t * data_set);
resource_t *create_child_clone(resource_t * rsc, int sub_id, pe_working_set_t * data_set);

static void
mark_as_orphan(resource_t * rsc)
{
    GListPtr gIter = rsc->children;

    set_bit(rsc->flags, pe_rsc_orphan);

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child = (resource_t *) gIter->data;

        mark_as_orphan(child);
    }
}

void
clear_bit_recursive(resource_t * rsc, unsigned long long flag)
{
    GListPtr gIter = rsc->children;

    clear_bit(rsc->flags, flag);
    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        clear_bit_recursive(child_rsc, flag);
    }
}

void
force_non_unique_clone(resource_t * rsc, const char *rid, pe_working_set_t * data_set)
{
    if (rsc->variant == pe_clone || rsc->variant == pe_master) {
        clone_variant_data_t *clone_data = NULL;

        get_clone_variant_data(clone_data, rsc);

        crm_config_warn("Clones %s contains non-OCF resource %s and so "
                        "can only be used as an anonymous clone. "
                        "Set the " XML_RSC_ATTR_UNIQUE " meta attribute to false", rsc->id, rid);

        clone_data->clone_node_max = 1;
        clone_data->clone_max = g_list_length(data_set->nodes);
        clear_bit_recursive(rsc, pe_rsc_unique);
    }
}

resource_t *
find_clone_instance(resource_t * rsc, const char *sub_id, pe_working_set_t * data_set)
{
    char *child_id = NULL;
    resource_t *child = NULL;
    const char *child_base = NULL;
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    child_base = ID(clone_data->xml_obj_child);
    child_id = crm_concat(child_base, sub_id, ':');
    child = pe_find_resource(rsc->children, child_id);

    free(child_id);
    return child;
}

resource_t *
create_child_clone(resource_t * rsc, int sub_id, pe_working_set_t * data_set)
{
    gboolean as_orphan = FALSE;
    char *inc_num = NULL;
    char *inc_max = NULL;
    resource_t *child_rsc = NULL;
    xmlNode *child_copy = NULL;
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    CRM_CHECK(clone_data->xml_obj_child != NULL, return FALSE);

    if (sub_id < 0) {
        as_orphan = TRUE;
        sub_id = clone_data->total_clones;
    }
    inc_num = crm_itoa(sub_id);
    inc_max = crm_itoa(clone_data->clone_max);

    child_copy = copy_xml(clone_data->xml_obj_child);

    crm_xml_add(child_copy, XML_RSC_ATTR_INCARNATION, inc_num);

    if (common_unpack(child_copy, &child_rsc, rsc, data_set) == FALSE) {
        pe_err("Failed unpacking resource %s", crm_element_value(child_copy, XML_ATTR_ID));
        child_rsc = NULL;
        goto bail;
    }
/*  child_rsc->globally_unique = rsc->globally_unique; */

    clone_data->total_clones += 1;
    pe_rsc_trace(child_rsc, "Setting clone attributes for: %s", child_rsc->id);
    rsc->children = g_list_append(rsc->children, child_rsc);
    if (as_orphan) {
        mark_as_orphan(child_rsc);
    }

    add_hash_param(child_rsc->meta, XML_RSC_ATTR_INCARNATION_MAX, inc_max);

    print_resource(LOG_DEBUG_3, "Added ", child_rsc, FALSE);

  bail:
    free(inc_num);
    free(inc_max);

    return child_rsc;
}

gboolean
master_unpack(resource_t * rsc, pe_working_set_t * data_set)
{
    const char *master_max = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_MASTER_MAX);
    const char *master_node_max = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_MASTER_NODEMAX);

    g_hash_table_replace(rsc->meta, strdup("stateful"), strdup(XML_BOOLEAN_TRUE));
    if (clone_unpack(rsc, data_set)) {
        clone_variant_data_t *clone_data = NULL;

        get_clone_variant_data(clone_data, rsc);
        clone_data->master_max = crm_parse_int(master_max, "1");
        clone_data->master_node_max = crm_parse_int(master_node_max, "1");
        return TRUE;
    }
    return FALSE;
}

gboolean
clone_unpack(resource_t * rsc, pe_working_set_t * data_set)
{
    int lpc = 0;
    const char *type = NULL;
    int num_xml_children = 0;
    xmlNode *a_child = NULL;
    xmlNode *xml_obj = rsc->xml;
    clone_variant_data_t *clone_data = NULL;

    const char *ordered = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_ORDERED);
    const char *interleave = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_INTERLEAVE);
    const char *max_clones = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_INCARNATION_MAX);
    const char *max_clones_node = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_INCARNATION_NODEMAX);

    pe_rsc_trace(rsc, "Processing resource %s...", rsc->id);

    clone_data = calloc(1, sizeof(clone_variant_data_t));
    rsc->variant_opaque = clone_data;
    clone_data->interleave = FALSE;
    clone_data->ordered = FALSE;

    clone_data->active_clones = 0;
    clone_data->xml_obj_child = NULL;
    clone_data->clone_node_max = crm_parse_int(max_clones_node, "1");

    if (max_clones) {
        clone_data->clone_max = crm_parse_int(max_clones, "1");

    } else if (g_list_length(data_set->nodes) > 0) {
        clone_data->clone_max = g_list_length(data_set->nodes);

    } else {
        clone_data->clone_max = 1;      /* Handy during crm_verify */
    }

    if (crm_is_true(interleave)) {
        clone_data->interleave = TRUE;
    }
    if (crm_is_true(ordered)) {
        clone_data->ordered = TRUE;
    }
    if ((rsc->flags & pe_rsc_unique) == 0 && clone_data->clone_node_max > 1) {
        crm_config_err("Anonymous clones (%s) may only support one copy per node", rsc->id);
        clone_data->clone_node_max = 1;
    }

    pe_rsc_trace(rsc, "Options for %s", rsc->id);
    pe_rsc_trace(rsc, "\tClone max: %d", clone_data->clone_max);
    pe_rsc_trace(rsc, "\tClone node max: %d", clone_data->clone_node_max);
    pe_rsc_trace(rsc, "\tClone is unique: %s",
                 is_set(rsc->flags, pe_rsc_unique) ? "true" : "false");

    clone_data->xml_obj_child = find_xml_node(xml_obj, XML_CIB_TAG_GROUP, FALSE);

    if (clone_data->xml_obj_child == NULL) {
        clone_data->xml_obj_child = find_xml_node(xml_obj, XML_CIB_TAG_RESOURCE, TRUE);
        for (a_child = __xml_first_child(xml_obj); a_child != NULL; a_child = __xml_next(a_child)) {
            if (crm_str_eq((const char *)a_child->name, XML_CIB_TAG_RESOURCE, TRUE)) {
                num_xml_children++;
            }
        }
    }

    if (clone_data->xml_obj_child == NULL) {
        crm_config_err("%s has nothing to clone", rsc->id);
        return FALSE;
    }

    for (a_child = __xml_first_child(xml_obj); a_child != NULL; a_child = __xml_next(a_child)) {
        if (crm_str_eq((const char *)a_child->name, type, TRUE)) {
            num_xml_children++;
        }
    }

    if (num_xml_children > 1) {
        crm_config_err("%s has too many children.  Only the first (%s) will be cloned.",
                       rsc->id, ID(clone_data->xml_obj_child));
    }

    /*
     * Make clones ever so slightly sticky by default
     *
     * This helps ensure clone instances are not shuffled around the cluster
     * for no benefit in situations when pre-allocation is not appropriate
     */
    if (g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_STICKINESS) == NULL) {
        add_hash_param(rsc->meta, XML_RSC_ATTR_STICKINESS, "1");
    }

    pe_rsc_trace(rsc, "\tClone is unique (fixed): %s",
                 is_set(rsc->flags, pe_rsc_unique) ? "true" : "false");
    clone_data->notify_confirm = is_set(rsc->flags, pe_rsc_notify);
    add_hash_param(rsc->meta, XML_RSC_ATTR_UNIQUE,
                   is_set(rsc->flags, pe_rsc_unique) ? XML_BOOLEAN_TRUE : XML_BOOLEAN_FALSE);

    for (lpc = 0; lpc < clone_data->clone_max; lpc++) {
        if (create_child_clone(rsc, lpc, data_set) == NULL) {
            return FALSE;
        }
    }

    if (clone_data->clone_max == 0) {
        /* create one so that unpack_find_resource() will hook up
         * any orphans up to the parent correctly
         */
        if (create_child_clone(rsc, -1, data_set) == NULL) {
            return FALSE;
        }
    }

    pe_rsc_trace(rsc, "Added %d children to resource %s...", clone_data->clone_max, rsc->id);
    return TRUE;
}

gboolean
clone_active(resource_t * rsc, gboolean all)
{
    GListPtr gIter = rsc->children;

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;
        gboolean child_active = child_rsc->fns->active(child_rsc, all);

        if (all == FALSE && child_active) {
            return TRUE;
        } else if (all && child_active == FALSE) {
            return FALSE;
        }
    }

    if (all) {
        return TRUE;
    } else {
        return FALSE;
    }
}

static void
short_print(char *list, const char *prefix, const char *type, long options, void *print_data)
{
    if (list) {
        if (options & pe_print_html) {
            status_print("<li>");
        }
        status_print("%s%s: [%s ]", prefix, type, list);

        if (options & pe_print_html) {
            status_print("</li>\n");

        } else if (options & pe_print_suppres_nl) {
            /* nothing */
        } else if ((options & pe_print_printf) || (options & pe_print_ncurses)) {
            status_print("\n");
        }

    }
}

static void
clone_print_xml(resource_t * rsc, const char *pre_text, long options, void *print_data)
{
    int is_master_slave = rsc->variant == pe_master ? 1 : 0;
    char *child_text = crm_concat(pre_text, "   ", ' ');
    GListPtr gIter = rsc->children;

    status_print("%s<clone ", pre_text);
    status_print("id=\"%s\" ", rsc->id);
    status_print("multi_state=\"%s\" ", is_master_slave ? "true" : "false");
    status_print("unique=\"%s\" ", is_set(rsc->flags, pe_rsc_unique) ? "true" : "false");
    status_print("managed=\"%s\" ", is_set(rsc->flags, pe_rsc_managed) ? "true" : "false");
    status_print("failed=\"%s\" ", is_set(rsc->flags, pe_rsc_failed) ? "true" : "false");
    status_print("failure_ignored=\"%s\" ",
                 is_set(rsc->flags, pe_rsc_failure_ignored) ? "true" : "false");
    status_print(">\n");

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        child_rsc->fns->print(child_rsc, child_text, options, print_data);
    }

    status_print("%s</clone>\n", pre_text);
    free(child_text);
}

bool is_set_recursive(resource_t * rsc, long long flag, bool any)
{
    GListPtr gIter;
    bool all = !any;

    if(is_set(rsc->flags, flag)) {
        if(any) {
            return TRUE;
        }
    } else if(all) {
        return FALSE;
    }

    for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        if(is_set_recursive(gIter->data, flag, any)) {
            if(any) {
                return TRUE;
            }

        } else if(all) {
            return FALSE;
        }
    }

    if(all) {
        return TRUE;
    }
    return FALSE;
}

void
clone_print(resource_t * rsc, const char *pre_text, long options, void *print_data)
{
    char *list_text = NULL;
    char *child_text = NULL;
    char *stopped_list = NULL;
    const char *type = "Clone";

    GListPtr master_list = NULL;
    GListPtr started_list = NULL;
    GListPtr gIter = rsc->children;

    clone_variant_data_t *clone_data = NULL;
    int active_instances = 0;

    if (pre_text == NULL) {
        pre_text = " ";
    }

    if (options & pe_print_xml) {
        clone_print_xml(rsc, pre_text, options, print_data);
        return;
    }

    get_clone_variant_data(clone_data, rsc);

    child_text = crm_concat(pre_text, "   ", ' ');

    if (rsc->variant == pe_master) {
        type = "Master/Slave";
    }

    status_print("%s%s Set: %s [%s]%s%s",
                 pre_text ? pre_text : "", type, rsc->id, ID(clone_data->xml_obj_child),
                 is_set(rsc->flags, pe_rsc_unique) ? " (unique)" : "",
                 is_set(rsc->flags, pe_rsc_managed) ? "" : " (unmanaged)");

    if (options & pe_print_html) {
        status_print("\n<ul>\n");

    } else if ((options & pe_print_log) == 0) {
        status_print("\n");
    }

    for (; gIter != NULL; gIter = gIter->next) {
        gboolean print_full = FALSE;
        resource_t *child_rsc = (resource_t *) gIter->data;

        if (options & pe_print_clone_details) {
            print_full = TRUE;
        }

        if (child_rsc->fns->active(child_rsc, FALSE) == FALSE) {
            /* Inactive clone */
            if (is_set(child_rsc->flags, pe_rsc_orphan)) {
                continue;

            } else if (is_set(rsc->flags, pe_rsc_unique)) {
                print_full = TRUE;
            } else {
                stopped_list = add_list_element(stopped_list, child_rsc->id);
            }

        } else if (is_set_recursive(child_rsc, pe_rsc_unique, TRUE)
                   || is_set_recursive(child_rsc, pe_rsc_orphan, TRUE)
                   || is_set_recursive(child_rsc, pe_rsc_managed, FALSE) == FALSE
                   || is_set_recursive(child_rsc, pe_rsc_failed, TRUE)) {

            /* Unique, unmanaged or failed clone */
            print_full = TRUE;

        } else if (child_rsc->fns->active(child_rsc, TRUE)) {
            /* Fully active anonymous clone */
            node_t *location = child_rsc->fns->location(child_rsc, NULL, TRUE);

            if (location) {
                enum rsc_role_e a_role = child_rsc->fns->state(child_rsc, TRUE);

                if (a_role > RSC_ROLE_SLAVE) {
                    /* And active on a single node as master */
                    master_list = g_list_append(master_list, location);

                } else {
                    /* And active on a single node as started/slave */
                    started_list = g_list_append(started_list, location);
                }

            } else {
                /* uncolocated group - bleh */
                print_full = TRUE;
            }

        } else {
            /* Partially active anonymous clone */
            print_full = TRUE;
        }

        if (print_full) {
            if (options & pe_print_html) {
                status_print("<li>\n");
            }
            child_rsc->fns->print(child_rsc, child_text, options, print_data);
            if (options & pe_print_html) {
                status_print("</li>\n");
            }
        }
    }

    /* Masters */
    master_list = g_list_sort(master_list, sort_node_uname);
    for (gIter = master_list; gIter; gIter = gIter->next) {
        node_t *host = gIter->data;

        list_text = add_list_element(list_text, host->details->uname);
	active_instances++;
    }

    short_print(list_text, child_text, "Masters", options, print_data);
    g_list_free(master_list);
    free(list_text);
    list_text = NULL;

    /* Started/Slaves */
    started_list = g_list_sort(started_list, sort_node_uname);
    for (gIter = started_list; gIter; gIter = gIter->next) {
        node_t *host = gIter->data;

        list_text = add_list_element(list_text, host->details->uname);
	active_instances++;
    }

    short_print(list_text, child_text, rsc->variant == pe_master ? "Slaves" : "Started", options,
                print_data);
    g_list_free(started_list);
    free(list_text);
    list_text = NULL;

    /* Stopped */
    if(is_not_set(rsc->flags, pe_rsc_unique) 
	&& (clone_data->clone_max > active_instances)) {

        GListPtr nIter;
        GListPtr list = g_hash_table_get_values(rsc->allowed_nodes);

        /* Custom stopped list for non-unique clones */
        free(stopped_list); stopped_list = NULL;

        if(g_list_length(list) == 0) {
            /* Clusters with symmetrical=false haven't calculated allowed_nodes yet
             * If we've not probed for them yet, the Stopped list will be empty
             */
            list = g_hash_table_get_values(rsc->known_on);
        }

        list = g_list_sort(list, sort_node_uname);
        for (nIter = list; nIter != NULL; nIter = nIter->next) {
            node_t *node = (node_t *)nIter->data;

            if(pe_find_node(rsc->running_on, node->details->uname) == NULL) {
                stopped_list = add_list_element(stopped_list, node->details->uname);
            }
        }
        g_list_free(list);
    }

    short_print(stopped_list, child_text, "Stopped", options, print_data);
    free(stopped_list);

    if (options & pe_print_html) {
        status_print("</ul>\n");
    }

    free(child_text);
}

void
clone_free(resource_t * rsc)
{
    GListPtr gIter = rsc->children;
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    pe_rsc_trace(rsc, "Freeing %s", rsc->id);

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        pe_rsc_trace(child_rsc, "Freeing child %s", child_rsc->id);
        free_xml(child_rsc->xml);
        child_rsc->xml = NULL;
        /* There could be a saved unexpanded xml */
        free_xml(child_rsc->orig_xml);
        child_rsc->orig_xml = NULL;
        child_rsc->fns->free(child_rsc);
    }

    g_list_free(rsc->children);

    if (clone_data) {
        CRM_ASSERT(clone_data->demote_notify == NULL);
        CRM_ASSERT(clone_data->stop_notify == NULL);
        CRM_ASSERT(clone_data->start_notify == NULL);
        CRM_ASSERT(clone_data->promote_notify == NULL);
    }

    common_free(rsc);
}

enum rsc_role_e
clone_resource_state(const resource_t * rsc, gboolean current)
{
    enum rsc_role_e clone_role = RSC_ROLE_UNKNOWN;
    GListPtr gIter = rsc->children;

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;
        enum rsc_role_e a_role = child_rsc->fns->state(child_rsc, current);

        if (a_role > clone_role) {
            clone_role = a_role;
        }
    }

    pe_rsc_trace(rsc, "%s role: %s", rsc->id, role2text(clone_role));
    return clone_role;
}
