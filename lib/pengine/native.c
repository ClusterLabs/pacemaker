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
#include <crm/pengine/complex.h>
#include <crm/pengine/internal.h>
#include <unpack.h>
#include <crm/msg_xml.h>

#define VARIANT_NATIVE 1
#include "./variant.h"

void
native_add_running(resource_t * rsc, node_t * node, pe_working_set_t * data_set)
{
    GListPtr gIter = rsc->running_on;

    CRM_CHECK(node != NULL, return);
    for (; gIter != NULL; gIter = gIter->next) {
        node_t *a_node = (node_t *) gIter->data;

        CRM_CHECK(a_node != NULL, return);
        if (safe_str_eq(a_node->details->id, node->details->id)) {
            return;
        }
    }

    pe_rsc_trace(rsc, "Adding %s to %s %s", rsc->id, node->details->uname,
                 is_set(rsc->flags, pe_rsc_managed)?"":"(unmanaged)");

    rsc->running_on = g_list_append(rsc->running_on, node);
    if (rsc->variant == pe_native) {
        node->details->running_rsc = g_list_append(node->details->running_rsc, rsc);
    }

    if (rsc->variant == pe_native && node->details->maintenance) {
        clear_bit(rsc->flags, pe_rsc_managed);
    }

    if (is_not_set(rsc->flags, pe_rsc_managed)) {
        resource_t *p = rsc->parent;

        pe_rsc_info(rsc, "resource %s isnt managed", rsc->id);
        resource_location(rsc, node, INFINITY, "not_managed_default", data_set);

        while(p && node->details->online) {
            /* add without the additional location constraint */
            p->running_on = g_list_append(p->running_on, node);
            p = p->parent;
        }
        return;
    }

    if (rsc->variant == pe_native && g_list_length(rsc->running_on) > 1) {
        switch (rsc->recovery_type) {
            case recovery_stop_only:
                {
                    GHashTableIter gIter;
                    node_t *local_node = NULL;

                    /* make sure it doesnt come up again */
                    g_hash_table_destroy(rsc->allowed_nodes);
                    rsc->allowed_nodes = node_hash_from_list(data_set->nodes);
                    g_hash_table_iter_init(&gIter, rsc->allowed_nodes);
                    while (g_hash_table_iter_next(&gIter, NULL, (void **)&local_node)) {
                        local_node->weight = -INFINITY;
                    }
                }
                break;
            case recovery_stop_start:
                break;
            case recovery_block:
                clear_bit(rsc->flags, pe_rsc_managed);
                set_bit(rsc->flags, pe_rsc_block);
                break;
        }
        crm_debug("%s is active on %d nodes including %s: %s",
                  rsc->id, g_list_length(rsc->running_on), node->details->uname,
                  recovery2text(rsc->recovery_type));

    } else {
        pe_rsc_trace(rsc, "Resource %s is active on: %s", rsc->id, node->details->uname);
    }

    if (rsc->parent != NULL) {
        native_add_running(rsc->parent, node, data_set);
    }
}

extern void force_non_unique_clone(resource_t * rsc, const char *rid, pe_working_set_t * data_set);

gboolean
native_unpack(resource_t * rsc, pe_working_set_t * data_set)
{
    resource_t *parent = uber_parent(rsc);
    native_variant_data_t *native_data = NULL;
    const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);

    pe_rsc_trace(rsc, "Processing resource %s...", rsc->id);

    native_data = calloc(1, sizeof(native_variant_data_t));
    rsc->variant_opaque = native_data;

    if (is_set(rsc->flags, pe_rsc_unique) && rsc->parent) {

        if (safe_str_eq(class, "lsb")) {
            resource_t *top = uber_parent(rsc);

            force_non_unique_clone(top, rsc->id, data_set);
        }
    }

    if (safe_str_eq(class, "ocf") == FALSE) {
        const char *stateful = g_hash_table_lookup(parent->meta, "stateful");

        if (safe_str_eq(stateful, XML_BOOLEAN_TRUE)) {
            pe_err
                ("Resource %s is of type %s and therefore cannot be used as a master/slave resource",
                 rsc->id, class);
            return FALSE;
        }
    }

    return TRUE;
}

resource_t *
native_find_rsc(resource_t * rsc, const char *id, node_t * on_node, int flags)
{
    gboolean match = FALSE;
    resource_t *result = NULL;
    GListPtr gIter = rsc->children;

    CRM_ASSERT(id != NULL);

    if (flags & pe_find_clone) {
        const char *rid = ID(rsc->xml);

        if (rsc->parent == NULL) {
            match = FALSE;

        } else if (safe_str_eq(rsc->id, id)) {
            match = TRUE;

        } else if (safe_str_eq(rid, id)) {
            match = TRUE;
        }

    } else {
        if (strcmp(rsc->id, id) == 0) {
            match = TRUE;

        } else if (is_set(flags, pe_find_renamed)
                   && rsc->clone_name && strcmp(rsc->clone_name, id) == 0) {
            match = TRUE;
        }
    }

    if (match && on_node) {
        pe_rsc_trace(rsc, "Now checking %s is on %s", rsc->id, on_node->details->uname);
        if (is_set(flags, pe_find_current) && rsc->running_on) {

            GListPtr gIter = rsc->running_on;

            for (; gIter != NULL; gIter = gIter->next) {
                node_t *loc = (node_t *) gIter->data;

                if (loc->details == on_node->details) {
                    return rsc;
                }
            }

        } else if (is_set(flags, pe_find_inactive) && rsc->running_on == NULL) {
            return rsc;

        } else if (is_not_set(flags, pe_find_current) && rsc->allocated_to
                   && rsc->allocated_to->details == on_node->details) {
            return rsc;
        }

    } else if (match) {
        return rsc;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child = (resource_t *) gIter->data;

        result = rsc->fns->find_rsc(child, id, on_node, flags);
        if (result) {
            return result;
        }
    }
    return NULL;
}

char *
native_parameter(resource_t * rsc, node_t * node, gboolean create, const char *name,
                 pe_working_set_t * data_set)
{
    char *value_copy = NULL;
    const char *value = NULL;
    GHashTable *hash = rsc->parameters;
    GHashTable *local_hash = NULL;

    CRM_CHECK(rsc != NULL, return NULL);
    CRM_CHECK(name != NULL && strlen(name) != 0, return NULL);

    pe_rsc_trace(rsc, "Looking up %s in %s", name, rsc->id);

    if (create || g_hash_table_size(rsc->parameters) == 0) {
        if (node != NULL) {
            pe_rsc_trace(rsc, "Creating hash with node %s", node->details->uname);
        } else {
            pe_rsc_trace(rsc, "Creating default hash");
        }

        local_hash = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                           g_hash_destroy_str, g_hash_destroy_str);

        get_rsc_attributes(local_hash, rsc, node, data_set);

        hash = local_hash;
    }

    value = g_hash_table_lookup(hash, name);
    if (value == NULL) {
        /* try meta attributes instead */
        value = g_hash_table_lookup(rsc->meta, name);
    }

    if (value != NULL) {
        value_copy = strdup(value);
    }
    if (local_hash != NULL) {
        g_hash_table_destroy(local_hash);
    }
    return value_copy;
}

gboolean
native_active(resource_t * rsc, gboolean all)
{
    GListPtr gIter = rsc->running_on;

    for (; gIter != NULL; gIter = gIter->next) {
        node_t *a_node = (node_t *) gIter->data;

        if (a_node->details->unclean) {
            crm_debug("Resource %s: node %s is unclean", rsc->id, a_node->details->uname);
            return TRUE;
        } else if (a_node->details->online == FALSE) {
            crm_debug("Resource %s: node %s is offline", rsc->id, a_node->details->uname);
        } else {
            crm_debug("Resource %s active on %s", rsc->id, a_node->details->uname);
            return TRUE;
        }
    }

    return FALSE;
}

struct print_data_s {
    long options;
    void *print_data;
};

static void
native_print_attr(gpointer key, gpointer value, gpointer user_data)
{
    long options = ((struct print_data_s *)user_data)->options;
    void *print_data = ((struct print_data_s *)user_data)->print_data;

    status_print("Option: %s = %s\n", (char *)key, (char *)value);
}

static const char *
native_pending_state(resource_t * rsc)
{
    const char *pending_state = NULL;

    if (safe_str_eq(rsc->pending_task, CRMD_ACTION_START)) {
        pending_state = "Starting";

    } else if (safe_str_eq(rsc->pending_task, CRMD_ACTION_STOP)) {
        pending_state = "Stopping";

    } else if (safe_str_eq(rsc->pending_task, CRMD_ACTION_MIGRATE)) {
        pending_state = "Migrating";

    } else if (safe_str_eq(rsc->pending_task, CRMD_ACTION_MIGRATED)) {
       /* Work might be done in here. */
        pending_state = "Migrating";

    } else if (safe_str_eq(rsc->pending_task, CRMD_ACTION_PROMOTE)) {
        pending_state = "Promoting";

    } else if (safe_str_eq(rsc->pending_task, CRMD_ACTION_DEMOTE)) {
        pending_state = "Demoting";
    }

    return pending_state;
}

static const char *
native_pending_task(resource_t * rsc)
{
    const char *pending_task = NULL;

    if (safe_str_eq(rsc->pending_task, CRMD_ACTION_NOTIFY)) {
        /* "Notifying" is not very useful to be shown. */
        pending_task = NULL;

    } else if (safe_str_eq(rsc->pending_task, CRMD_ACTION_STATUS)) {
        pending_task = "Monitoring";

    /* Comment this out until someone requests it */
    /*
    } else if (safe_str_eq(rsc->pending_task, "probe")) {
        pending_task = "Checking";
    */
    }

    return pending_task;
}

static void
native_print_xml(resource_t * rsc, const char *pre_text, long options, void *print_data)
{
    enum rsc_role_e role = rsc->role;
    const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    const char *prov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    const char *rsc_state = NULL;

    if(role == RSC_ROLE_STARTED && uber_parent(rsc)->variant == pe_master) {
        role = RSC_ROLE_SLAVE;
    }

    /* resource information. */
    status_print("%s<resource ", pre_text);
    status_print("id=\"%s\" ", rsc_printable_id(rsc));
    status_print("resource_agent=\"%s%s%s:%s\" ",
                 class,
                 prov ? "::" : "", prov ? prov : "", crm_element_value(rsc->xml, XML_ATTR_TYPE));

    if (options & pe_print_pending) {
        rsc_state = native_pending_state(rsc);
    }
    if (rsc_state == NULL) {
        rsc_state = role2text(role);
    }
    status_print("role=\"%s\" ", rsc_state);
    status_print("active=\"%s\" ", rsc->fns->active(rsc, TRUE) ? "true" : "false");
    status_print("orphaned=\"%s\" ", is_set(rsc->flags, pe_rsc_orphan) ? "true" : "false");
    status_print("managed=\"%s\" ", is_set(rsc->flags, pe_rsc_managed) ? "true" : "false");
    status_print("failed=\"%s\" ", is_set(rsc->flags, pe_rsc_failed) ? "true" : "false");
    status_print("failure_ignored=\"%s\" ",
                 is_set(rsc->flags, pe_rsc_failure_ignored) ? "true" : "false");
    status_print("nodes_running_on=\"%d\" ", g_list_length(rsc->running_on));

    if (options & pe_print_pending) {
        const char *pending_task = native_pending_task(rsc);

        if (pending_task) {
            status_print("pending=\"%s\" ", pending_task);
        }
    }

    if (options & pe_print_dev) {
        status_print("provisional=\"%s\" ",
                     is_set(rsc->flags, pe_rsc_provisional) ? "true" : "false");
        status_print("runnable=\"%s\" ", is_set(rsc->flags, pe_rsc_runnable) ? "true" : "false");
        status_print("priority=\"%f\" ", (double)rsc->priority);
        status_print("variant=\"%s\" ", crm_element_name(rsc->xml));
    }

    /* print out the nodes this resource is running on */
    if (options & pe_print_rsconly) {
        status_print("/>\n");
        /* do nothing */
    } else if (g_list_length(rsc->running_on) > 0) {
        GListPtr gIter = rsc->running_on;

        status_print(">\n");
        for (; gIter != NULL; gIter = gIter->next) {
            node_t *node = (node_t *) gIter->data;

            status_print("%s    <node name=\"%s\" id=\"%s\" cached=\"%s\"/>\n", pre_text,
                         node->details->uname, node->details->id,
                         node->details->online ? "false" : "true");
        }
        status_print("%s</resource>\n", pre_text);
    } else {
        status_print("/>\n");
    }
}


void
native_print(resource_t * rsc, const char *pre_text, long options, void *print_data)
{
    node_t *node = NULL;
    const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    const char *kind = crm_element_value(rsc->xml, XML_ATTR_TYPE);
    const char *target_role = NULL;

    int offset = 0;
    char buffer[LINE_MAX];

    CRM_ASSERT(rsc->variant == pe_native);
    CRM_ASSERT(kind != NULL);

    if (rsc->meta) {
        const char *is_internal = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_INTERNAL_RSC);
        if (crm_is_true(is_internal)) {
            crm_trace("skipping print of internal resource %s", rsc->id);
            return;
        }
        target_role = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);
    }

    if (pre_text == NULL && (options & pe_print_printf)) {
        pre_text = " ";
    }

    if (options & pe_print_xml) {
        native_print_xml(rsc, pre_text, options, print_data);
        return;
    }

    if (rsc->running_on != NULL) {
        node = rsc->running_on->data;
    }
    if ((options & pe_print_rsconly) || g_list_length(rsc->running_on) > 1) {
        node = NULL;
    }

    if (options & pe_print_html) {
        if (is_not_set(rsc->flags, pe_rsc_managed)) {
            status_print("<font color=\"yellow\">");

        } else if (is_set(rsc->flags, pe_rsc_failed)) {
            status_print("<font color=\"red\">");

        } else if (rsc->variant == pe_native && g_list_length(rsc->running_on) == 0) {
            status_print("<font color=\"red\">");

        } else if (g_list_length(rsc->running_on) > 1) {
            status_print("<font color=\"orange\">");

        } else if (is_set(rsc->flags, pe_rsc_failure_ignored)) {
            status_print("<font color=\"yellow\">");

        } else {
            status_print("<font color=\"green\">");
        }
    }

    if(pre_text) {
        offset += snprintf(buffer + offset, LINE_MAX - offset, "%s", pre_text);
    }
    offset += snprintf(buffer + offset, LINE_MAX - offset, "%s", rsc_printable_id(rsc));
    offset += snprintf(buffer + offset, LINE_MAX - offset, "\t(%s", class);
    if (safe_str_eq(class, "ocf")) {
        const char *prov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
        offset += snprintf(buffer + offset, LINE_MAX - offset, "::%s", prov);
    }
    offset += snprintf(buffer + offset, LINE_MAX - offset, ":%s):\t", kind);
    if(is_set(rsc->flags, pe_rsc_orphan)) {
        offset += snprintf(buffer + offset, LINE_MAX - offset, " ORPHANED ");
    }
    if(rsc->role > RSC_ROLE_SLAVE && is_set(rsc->flags, pe_rsc_failed)) {
        offset += snprintf(buffer + offset, LINE_MAX - offset, "FAILED %s ", role2text(rsc->role));
    } else if(is_set(rsc->flags, pe_rsc_failed)) {
        offset += snprintf(buffer + offset, LINE_MAX - offset, "FAILED ");
    } else {
        const char *rsc_state = NULL;

        if (options & pe_print_pending) {
            rsc_state = native_pending_state(rsc);
        }
        if (rsc_state == NULL) {
            rsc_state = role2text(rsc->role);
        }
        if (target_role) {
            enum rsc_role_e target_role_e = text2role(target_role);

	    /* Ignore target role Started, as it is the default anyways
             * (and would also allow a Master to be Master).
             * Show if current role differs from target role,
             * or if target role limits our abilities. */
            if (target_role_e != RSC_ROLE_STARTED && (
                target_role_e == RSC_ROLE_SLAVE ||
		target_role_e == RSC_ROLE_STOPPED ||
                safe_str_neq(target_role, rsc_state)))
            {
                offset += snprintf(buffer + offset, LINE_MAX - offset, "(target-role:%s) ", target_role);
            }
        }
        offset += snprintf(buffer + offset, LINE_MAX - offset, "%s ", rsc_state);
    }

    if(node) {
        offset += snprintf(buffer + offset, LINE_MAX - offset, "%s ", node->details->uname);
    }

    if (options & pe_print_pending) {
        const char *pending_task = native_pending_task(rsc);

        if (pending_task) {
            offset += snprintf(buffer + offset, LINE_MAX - offset, "(%s) ", pending_task);
        }
    }

    if(is_not_set(rsc->flags, pe_rsc_managed)) {
        offset += snprintf(buffer + offset, LINE_MAX - offset, "(unmanaged) ");
    }
    if(is_set(rsc->flags, pe_rsc_failure_ignored)) {
        offset += snprintf(buffer + offset, LINE_MAX - offset, "(failure ignored)");
    }

    if ((options & pe_print_rsconly) || g_list_length(rsc->running_on) > 1) {
        const char *desc = crm_element_value(rsc->xml, XML_ATTR_DESC);
        if(desc) {
            offset += snprintf(buffer + offset, LINE_MAX - offset, "%s", desc);
        }
    }

    CRM_LOG_ASSERT(offset > 0);
    status_print("%s", buffer);

#if CURSES_ENABLED
    if ((options & pe_print_rsconly) || g_list_length(rsc->running_on) > 1) {
        /* Done */

    } else if (options & pe_print_ncurses) {
        /* coverity[negative_returns] False positive */
        move(-1, 0);
    }
#endif

    if (options & pe_print_html) {
        status_print(" </font> ");
    }

    if ((options & pe_print_rsconly)) {

    } else if (g_list_length(rsc->running_on) > 1) {
        GListPtr gIter = rsc->running_on;
        int counter = 0;

        if (options & pe_print_html) {
            status_print("<ul>\n");
        } else if ((options & pe_print_printf)
                   || (options & pe_print_ncurses)) {
            status_print("[");
        }

        for (; gIter != NULL; gIter = gIter->next) {
            node_t *node = (node_t *) gIter->data;

            counter++;

            if (options & pe_print_html) {
                status_print("<li>\n%s", node->details->uname);

            } else if ((options & pe_print_printf)
                       || (options & pe_print_ncurses)) {
                status_print(" %s", node->details->uname);

            } else if ((options & pe_print_log)) {
                status_print("\t%d : %s", counter, node->details->uname);

            } else {
                status_print("%s", node->details->uname);
            }
            if (options & pe_print_html) {
                status_print("</li>\n");

            }
        }

        if (options & pe_print_html) {
            status_print("</ul>\n");
        } else if ((options & pe_print_printf)
                   || (options & pe_print_ncurses)) {
            status_print(" ]");
        }
    }

    if (options & pe_print_html) {
        status_print("<br/>\n");
    } else if (options & pe_print_suppres_nl) {
        /* nothing */
    } else if ((options & pe_print_printf) || (options & pe_print_ncurses)) {
        status_print("\n");
    }

    if (options & pe_print_details) {
        struct print_data_s pdata;

        pdata.options = options;
        pdata.print_data = print_data;
        g_hash_table_foreach(rsc->parameters, native_print_attr, &pdata);
    }

    if (options & pe_print_dev) {
        GHashTableIter iter;
        node_t *node = NULL;

        status_print("%s\t(%s%svariant=%s, priority=%f)", pre_text,
                     is_set(rsc->flags, pe_rsc_provisional) ? "provisional, " : "",
                     is_set(rsc->flags, pe_rsc_runnable) ? "" : "non-startable, ",
                     crm_element_name(rsc->xml), (double)rsc->priority);
        status_print("%s\tAllowed Nodes", pre_text);
        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            status_print("%s\t * %s %d", pre_text, node->details->uname, node->weight);
        }
    }

    if (options & pe_print_max_details) {
        GHashTableIter iter;
        node_t *node = NULL;

        status_print("%s\t=== Allowed Nodes\n", pre_text);
        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            print_node("\t", node, FALSE);
        }
    }
}

void
native_free(resource_t * rsc)
{
    pe_rsc_trace(rsc, "Freeing resource action list (not the data)");
    common_free(rsc);
}

enum rsc_role_e
native_resource_state(const resource_t * rsc, gboolean current)
{
    enum rsc_role_e role = rsc->next_role;

    if (current) {
        role = rsc->role;
    }
    pe_rsc_trace(rsc, "%s state: %s", rsc->id, role2text(role));
    return role;
}

node_t *
native_location(resource_t * rsc, GListPtr * list, gboolean current)
{
    node_t *one = NULL;
    GListPtr result = NULL;

    if (rsc->children) {
        GListPtr gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child = (resource_t *) gIter->data;

            child->fns->location(child, &result, current);
        }

    } else if (current && rsc->running_on) {
        result = g_list_copy(rsc->running_on);

    } else if (current == FALSE && rsc->allocated_to) {
        result = g_list_append(NULL, rsc->allocated_to);
    }

    if (result && g_list_length(result) == 1) {
        one = g_list_nth_data(result, 0);
    }

    if (list) {
        GListPtr gIter = result;

        for (; gIter != NULL; gIter = gIter->next) {
            node_t *node = (node_t *) gIter->data;

            if (*list == NULL || pe_find_node_id(*list, node->details->id) == NULL) {
                *list = g_list_append(*list, node);
            }
        }
    }

    g_list_free(result);
    return one;
}

static void
get_rscs_brief(GListPtr rsc_list, GHashTable * rsc_table, GHashTable * active_table)
{
    GListPtr gIter = rsc_list;

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;

        const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
        const char *kind = crm_element_value(rsc->xml, XML_ATTR_TYPE);

        int offset = 0;
        char buffer[LINE_MAX];

        int *rsc_counter = NULL;
        int *active_counter = NULL;

        if (rsc->variant != pe_native) {
            continue;
        }

        offset += snprintf(buffer + offset, LINE_MAX - offset, "%s", class);
        if (safe_str_eq(class, "ocf")) {
            const char *prov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
            offset += snprintf(buffer + offset, LINE_MAX - offset, "::%s", prov);
        }
        offset += snprintf(buffer + offset, LINE_MAX - offset, ":%s", kind);
        CRM_LOG_ASSERT(offset > 0);

        if (rsc_table) {
            rsc_counter = g_hash_table_lookup(rsc_table, buffer);
            if (rsc_counter == NULL) {
                rsc_counter = calloc(1, sizeof(int));
                *rsc_counter = 0;
                g_hash_table_insert(rsc_table, strdup(buffer), rsc_counter);
            }
            (*rsc_counter)++;
        }

        if (active_table) {
            GListPtr gIter2 = rsc->running_on;

            for (; gIter2 != NULL; gIter2 = gIter2->next) {
                node_t *node = (node_t *) gIter2->data;
                GHashTable *node_table = NULL;

                if (node->details->unclean == FALSE && node->details->online == FALSE) {
                    continue;
                }

                node_table = g_hash_table_lookup(active_table, node->details->uname);
                if (node_table == NULL) {
                    node_table = g_hash_table_new_full(crm_str_hash, g_str_equal, free, free);
                    g_hash_table_insert(active_table, strdup(node->details->uname), node_table);
                }

                active_counter = g_hash_table_lookup(node_table, buffer);
                if (active_counter == NULL) {
                    active_counter = calloc(1, sizeof(int));
                    *active_counter = 0;
                    g_hash_table_insert(node_table, strdup(buffer), active_counter);
                }
                (*active_counter)++;
            }
        }
    }
}

static void
destroy_node_table(gpointer data)
{
    GHashTable *node_table = data;

    if (node_table) {
        g_hash_table_destroy(node_table);
    }
}

void
print_rscs_brief(GListPtr rsc_list, const char *pre_text, long options,
                 void *print_data, gboolean print_all)
{
    GHashTable *rsc_table = g_hash_table_new_full(crm_str_hash, g_str_equal, free, free);
    GHashTable *active_table = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                                     free, destroy_node_table);
    GHashTableIter hash_iter;
    char *type = NULL;
    int *rsc_counter = NULL;

    get_rscs_brief(rsc_list, rsc_table, active_table);

    g_hash_table_iter_init(&hash_iter, rsc_table);
    while (g_hash_table_iter_next(&hash_iter, (gpointer *)&type, (gpointer *)&rsc_counter)) {
        GHashTableIter hash_iter2;
        char *node_name = NULL;
        GHashTable *node_table = NULL;
        int active_counter_all = 0;

        g_hash_table_iter_init(&hash_iter2, active_table);
        while (g_hash_table_iter_next(&hash_iter2, (gpointer *)&node_name, (gpointer *)&node_table)) {
            int *active_counter = g_hash_table_lookup(node_table, type);

            if (active_counter == NULL || *active_counter == 0) {
                continue;

            } else {
                active_counter_all += *active_counter;
            }

            if (options & pe_print_rsconly) {
                node_name = NULL;
            }

            if (options & pe_print_html) {
                status_print("<li>\n");
            }

            if (print_all) {
                status_print("%s%d/%d\t(%s):\tActive %s\n", pre_text ? pre_text : "",
                             active_counter ? *active_counter : 0,
                             rsc_counter ? *rsc_counter : 0, type,
                             active_counter && (*active_counter > 0) && node_name ? node_name : "");
            } else {
                status_print("%s%d\t(%s):\tActive %s\n", pre_text ? pre_text : "",
                             active_counter ? *active_counter : 0, type,
                             active_counter && (*active_counter > 0) && node_name ? node_name : "");
            }

            if (options & pe_print_html) {
                status_print("</li>\n");
            }
        }

        if (print_all && active_counter_all == 0) {
            if (options & pe_print_html) {
                status_print("<li>\n");
            }

            status_print("%s%d/%d\t(%s):\tActive\n", pre_text ? pre_text : "",
                         active_counter_all,
                         rsc_counter ? *rsc_counter : 0, type);

            if (options & pe_print_html) {
                status_print("</li>\n");
            }
        }
    }

    if (rsc_table) {
        g_hash_table_destroy(rsc_table);
        rsc_table = NULL;
    }
    if (active_table) {
        g_hash_table_destroy(active_table);
        active_table = NULL;
    }
}
