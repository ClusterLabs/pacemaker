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

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <glib.h>

#include <crm/pengine/internal.h>
#include <unpack.h>

#define MEMCHECK_STAGE_0 0

#define check_and_exit(stage) 	cleanup_calculations(data_set);		\
	crm_mem_stats(NULL);						\
	crm_err("Exiting: stage %d", stage);				\
	crm_exit(1);

/*
 * Unpack everything
 * At the end you'll have:
 *  - A list of nodes
 *  - A list of resources (each with any dependencies on other resources)
 *  - A list of constraints between resources and nodes
 *  - A list of constraints between start/stop actions
 *  - A list of nodes that need to be stonith'd
 *  - A list of nodes that need to be shutdown
 *  - A list of the possible stop/start actions (without dependencies)
 */
gboolean
cluster_status(pe_working_set_t * data_set)
{
    xmlNode *config = get_xpath_object("//"XML_CIB_TAG_CRMCONFIG, data_set->input, LOG_TRACE);
    xmlNode *cib_nodes = get_xpath_object("//"XML_CIB_TAG_NODES, data_set->input, LOG_TRACE);
    xmlNode *cib_resources = get_xpath_object("//"XML_CIB_TAG_RESOURCES, data_set->input, LOG_TRACE);
    xmlNode *cib_status = get_xpath_object("//"XML_CIB_TAG_STATUS, data_set->input, LOG_TRACE);
    xmlNode *cib_domains = get_xpath_object("//"XML_CIB_TAG_DOMAINS, data_set->input, LOG_TRACE);
    const char *value = crm_element_value(data_set->input, XML_ATTR_HAVE_QUORUM);

    crm_trace("Beginning unpack");
    pe_dataset = data_set;

    /* reset remaining global variables */
    data_set->failed = create_xml_node(NULL, "failed-ops");

    if (data_set->input == NULL) {
        return FALSE;
    }

    if (data_set->now == NULL) {
        data_set->now = crm_time_new(NULL);
    }

    if (data_set->dc_uuid == NULL
        && data_set->input != NULL
        && crm_element_value(data_set->input, XML_ATTR_DC_UUID) != NULL) {
        /* this should always be present */
        data_set->dc_uuid = crm_element_value_copy(data_set->input, XML_ATTR_DC_UUID);
    }

    clear_bit(data_set->flags, pe_flag_have_quorum);
    if (crm_is_true(value)) {
        set_bit(data_set->flags, pe_flag_have_quorum);
    }

    data_set->op_defaults = get_xpath_object("//"XML_CIB_TAG_OPCONFIG, data_set->input, LOG_TRACE);
    data_set->rsc_defaults = get_xpath_object("//"XML_CIB_TAG_RSCCONFIG, data_set->input, LOG_TRACE);

    unpack_config(config, data_set);

   if (is_not_set(data_set->flags, pe_flag_quick_location)
       && is_not_set(data_set->flags, pe_flag_have_quorum)
       && data_set->no_quorum_policy != no_quorum_ignore) {
        crm_warn("We do not have quorum - fencing and resource management disabled");
    }

    unpack_nodes(cib_nodes, data_set);
    unpack_domains(cib_domains, data_set);

    if(is_not_set(data_set->flags, pe_flag_quick_location)) {
        unpack_remote_nodes(cib_resources, data_set);
    }

    unpack_resources(cib_resources, data_set);

    if(is_not_set(data_set->flags, pe_flag_quick_location)) {
        unpack_status(cib_status, data_set);
    }

    set_bit(data_set->flags, pe_flag_have_status);
    return TRUE;
}

static void
pe_free_resources(GListPtr resources)
{
    resource_t *rsc = NULL;
    GListPtr iterator = resources;

    while (iterator != NULL) {
        iterator = iterator;
        rsc = (resource_t *) iterator->data;
        iterator = iterator->next;
        rsc->fns->free(rsc);
    }
    if (resources != NULL) {
        g_list_free(resources);
    }
}

static void
pe_free_actions(GListPtr actions)
{
    GListPtr iterator = actions;

    while (iterator != NULL) {
        pe_free_action(iterator->data);
        iterator = iterator->next;
    }
    if (actions != NULL) {
        g_list_free(actions);
    }
}

static void
pe_free_nodes(GListPtr nodes)
{
    GListPtr iterator = nodes;

    while (iterator != NULL) {
        node_t *node = (node_t *) iterator->data;
        struct node_shared_s *details = node->details;

        iterator = iterator->next;

        crm_trace("deleting node");
        print_node("delete", node, FALSE);

        if (details != NULL) {
            crm_trace("%s is being deleted", details->uname);
            if (details->attrs != NULL) {
                g_hash_table_destroy(details->attrs);
            }
            if (details->utilization != NULL) {
                g_hash_table_destroy(details->utilization);
            }
            if (details->digest_cache != NULL) {
                g_hash_table_destroy(details->digest_cache);
            }
            g_list_free(details->running_rsc);
            g_list_free(details->allocated_rsc);
            free(details);
        }
        free(node);
    }
    if (nodes != NULL) {
        g_list_free(nodes);
    }
}

void
cleanup_calculations(pe_working_set_t * data_set)
{
    pe_dataset = NULL;
    if (data_set == NULL) {
        return;
    }

    clear_bit(data_set->flags, pe_flag_have_status);
    if (data_set->config_hash != NULL) {
        g_hash_table_destroy(data_set->config_hash);
    }

    if (data_set->tickets) {
        g_hash_table_destroy(data_set->tickets);
    }

    if (data_set->template_rsc_sets) {
        g_hash_table_destroy(data_set->template_rsc_sets);
    }

    free(data_set->dc_uuid);

    crm_trace("deleting resources");
    pe_free_resources(data_set->resources);

    crm_trace("deleting actions");
    pe_free_actions(data_set->actions);

    if (data_set->domains) {
        g_hash_table_destroy(data_set->domains);
    }

    crm_trace("deleting nodes");
    pe_free_nodes(data_set->nodes);

    free_xml(data_set->graph);
    crm_time_free(data_set->now);
    free_xml(data_set->input);
    free_xml(data_set->failed);

    set_working_set_defaults(data_set);

    CRM_CHECK(data_set->ordering_constraints == NULL,;
        );
    CRM_CHECK(data_set->placement_constraints == NULL,;
        );
}

void
set_working_set_defaults(pe_working_set_t * data_set)
{
    pe_dataset = data_set;
    memset(data_set, 0, sizeof(pe_working_set_t));

    data_set->dc_uuid = NULL;
    data_set->order_id = 1;
    data_set->action_id = 1;
    data_set->no_quorum_policy = no_quorum_freeze;

    data_set->flags = 0x0ULL;
    set_bit(data_set->flags, pe_flag_stop_rsc_orphans);
    set_bit(data_set->flags, pe_flag_symmetric_cluster);
    set_bit(data_set->flags, pe_flag_is_managed_default);
    set_bit(data_set->flags, pe_flag_stop_action_orphans);
}

resource_t *
pe_find_resource(GListPtr rsc_list, const char *id)
{
    GListPtr rIter = NULL;

    for (rIter = rsc_list; id && rIter; rIter = rIter->next) {
        resource_t *parent = rIter->data;

        resource_t *match =
            parent->fns->find_rsc(parent, id, NULL, pe_find_renamed | pe_find_current);
        if (match != NULL) {
            return match;
        }
    }
    crm_trace("No match for %s", id);
    return NULL;
}

node_t *
pe_find_node_any(GListPtr nodes, const char *id, const char *uname)
{
    node_t *match = pe_find_node_id(nodes, id);

    if (match) {
        return match;
    }
    crm_trace("Looking up %s via it's uname instead", uname);
    return pe_find_node(nodes, uname);
}

node_t *
pe_find_node_id(GListPtr nodes, const char *id)
{
    GListPtr gIter = nodes;

    for (; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;

        if (node && safe_str_eq(node->details->id, id)) {
            return node;
        }
    }
    /* error */
    return NULL;
}

node_t *
pe_find_node(GListPtr nodes, const char *uname)
{
    GListPtr gIter = nodes;

    for (; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;

        if (node && safe_str_eq(node->details->uname, uname)) {
            return node;
        }
    }
    /* error */
    return NULL;
}
