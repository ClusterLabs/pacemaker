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
#include <crm/transition.h>
#include <sys/stat.h>

CRM_TRACE_INIT_DATA(transitioner);

static crm_action_t *
unpack_action(synapse_t * parent, xmlNode * xml_action)
{
    crm_action_t *action = NULL;
    xmlNode *action_copy = NULL;
    const char *value = crm_element_value(xml_action, XML_ATTR_ID);

    if (value == NULL) {
        crm_err("Actions must have an id!");
        crm_log_xml_trace(xml_action, "Action with missing id");
        return NULL;
    }

    action_copy = copy_xml(xml_action);
    action = calloc(1, sizeof(crm_action_t));
    if (action == NULL) {
        return NULL;
    }

    action->id = crm_parse_int(value, NULL);
    action->type = action_type_rsc;
    action->xml = action_copy;
    action->synapse = parent;

    if (safe_str_eq(crm_element_name(action_copy), XML_GRAPH_TAG_RSC_OP)) {
        action->type = action_type_rsc;

    } else if (safe_str_eq(crm_element_name(action_copy), XML_GRAPH_TAG_PSEUDO_EVENT)) {
        action->type = action_type_pseudo;

    } else if (safe_str_eq(crm_element_name(action_copy), XML_GRAPH_TAG_CRM_EVENT)) {
        action->type = action_type_crm;
    }

    action->params = xml2list(action_copy);

    value = g_hash_table_lookup(action->params, "CRM_meta_timeout");
    if (value != NULL) {
        action->timeout = crm_parse_int(value, NULL);
    }

    value = g_hash_table_lookup(action->params, "CRM_meta_interval");
    if (value != NULL) {
        action->interval = crm_parse_int(value, NULL);
    }

    value = g_hash_table_lookup(action->params, "CRM_meta_can_fail");
    if (value != NULL) {
        crm_str_to_boolean(value, &(action->can_fail));
    }

    crm_trace("Action %d has timer set to %dms", action->id, action->timeout);

    return action;
}

static synapse_t *
unpack_synapse(crm_graph_t * new_graph, xmlNode * xml_synapse)
{
    const char *value = NULL;
    xmlNode *inputs = NULL;
    xmlNode *action_set = NULL;
    synapse_t *new_synapse = NULL;

    CRM_CHECK(xml_synapse != NULL, return NULL);
    crm_trace("looking in synapse %s", ID(xml_synapse));

    new_synapse = calloc(1, sizeof(synapse_t));
    new_synapse->id = crm_parse_int(ID(xml_synapse), NULL);

    value = crm_element_value(xml_synapse, XML_CIB_ATTR_PRIORITY);
    if (value != NULL) {
        new_synapse->priority = crm_parse_int(value, NULL);
    }

    new_graph->num_synapses++;
    CRM_CHECK(new_synapse->id >= 0, free(new_synapse);
              return NULL);

    crm_trace("look for actions in synapse %s", crm_element_value(xml_synapse, XML_ATTR_ID));

    for (action_set = __xml_first_child(xml_synapse); action_set != NULL;
         action_set = __xml_next(action_set)) {
        if (crm_str_eq((const char *)action_set->name, "action_set", TRUE)) {
            xmlNode *action = NULL;

            for (action = __xml_first_child(action_set); action != NULL;
                 action = __xml_next(action)) {
                crm_action_t *new_action = unpack_action(new_synapse, action);

                new_graph->num_actions++;

                if (new_action == NULL) {
                    continue;
                }
                crm_trace("Adding action %d to synapse %d", new_action->id, new_synapse->id);

                new_synapse->actions = g_list_append(new_synapse->actions, new_action);
            }
        }
    }

    crm_trace("look for inputs in synapse %s", ID(xml_synapse));

    for (inputs = __xml_first_child(xml_synapse); inputs != NULL; inputs = __xml_next(inputs)) {
        if (crm_str_eq((const char *)inputs->name, "inputs", TRUE)) {
            xmlNode *trigger = NULL;

            for (trigger = __xml_first_child(inputs); trigger != NULL;
                 trigger = __xml_next(trigger)) {
                xmlNode *input = NULL;

                for (input = __xml_first_child(trigger); input != NULL; input = __xml_next(input)) {
                    crm_action_t *new_input = unpack_action(new_synapse, input);

                    if (new_input == NULL) {
                        continue;
                    }

                    crm_trace("Adding input %d to synapse %d", new_input->id, new_synapse->id);

                    new_synapse->inputs = g_list_append(new_synapse->inputs, new_input);
                }
            }
        }
    }

    return new_synapse;
}

crm_graph_t *
unpack_graph(xmlNode * xml_graph, const char *reference)
{
/*
  <transition_graph>
  <synapse>
  <action_set>
  <rsc_op id="2"
  ...
  <inputs>
  <rsc_op id="2"
  ...
*/
    crm_graph_t *new_graph = NULL;
    const char *t_id = NULL;
    const char *time = NULL;
    xmlNode *synapse = NULL;

    new_graph = calloc(1, sizeof(crm_graph_t));

    new_graph->id = -1;
    new_graph->abort_priority = 0;
    new_graph->network_delay = -1;
    new_graph->transition_timeout = -1;
    new_graph->stonith_timeout = -1;
    new_graph->completion_action = tg_done;

    new_graph->migrating = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                                 g_hash_destroy_str, g_hash_destroy_str);

    if (reference) {
        new_graph->source = strdup(reference);
    } else {
        new_graph->source = strdup("unknown");
    }

    if (xml_graph != NULL) {
        t_id = crm_element_value(xml_graph, "transition_id");
        CRM_CHECK(t_id != NULL, free(new_graph);
                  return NULL);
        new_graph->id = crm_parse_int(t_id, "-1");

        time = crm_element_value(xml_graph, "cluster-delay");
        CRM_CHECK(time != NULL, free(new_graph);
                  return NULL);
        new_graph->network_delay = crm_get_msec(time);

        time = crm_element_value(xml_graph, "stonith-timeout");
        if (time == NULL) {
            new_graph->stonith_timeout = new_graph->network_delay;
        } else {
            new_graph->stonith_timeout = crm_get_msec(time);
        }

        t_id = crm_element_value(xml_graph, "batch-limit");
        new_graph->batch_limit = crm_parse_int(t_id, "0");

        t_id = crm_element_value(xml_graph, "migration-limit");
        new_graph->migration_limit = crm_parse_int(t_id, "-1");
    }

    for (synapse = __xml_first_child(xml_graph); synapse != NULL; synapse = __xml_next(synapse)) {
        if (crm_str_eq((const char *)synapse->name, "synapse", TRUE)) {
            synapse_t *new_synapse = unpack_synapse(new_graph, synapse);

            if (new_synapse != NULL) {
                new_graph->synapses = g_list_append(new_graph->synapses, new_synapse);
            }
        }
    }

    crm_debug("Unpacked transition %d: %d actions in %d synapses",
              new_graph->id, new_graph->num_actions, new_graph->num_synapses);

    return new_graph;
}

static void
destroy_action(crm_action_t * action)
{
    if (action->timer && action->timer->source_id != 0) {
        crm_warn("Cancelling timer for action %d (src=%d)", action->id, action->timer->source_id);
        g_source_remove(action->timer->source_id);
    }
    if (action->params) {
        g_hash_table_destroy(action->params);
    }
    free_xml(action->xml);
    free(action->timer);
    free(action);
}

static void
destroy_synapse(synapse_t * synapse)
{
    while (g_list_length(synapse->actions) > 0) {
        crm_action_t *action = g_list_nth_data(synapse->actions, 0);

        synapse->actions = g_list_remove(synapse->actions, action);
        destroy_action(action);
    }

    while (g_list_length(synapse->inputs) > 0) {
        crm_action_t *action = g_list_nth_data(synapse->inputs, 0);

        synapse->inputs = g_list_remove(synapse->inputs, action);
        destroy_action(action);
    }
    free(synapse);
}

void
destroy_graph(crm_graph_t * graph)
{
    if (graph == NULL) {
        return;
    }
    while (g_list_length(graph->synapses) > 0) {
        synapse_t *synapse = g_list_nth_data(graph->synapses, 0);

        graph->synapses = g_list_remove(graph->synapses, synapse);
        destroy_synapse(synapse);
    }

    g_hash_table_destroy(graph->migrating);
    free(graph->source);
    free(graph);
}

lrmd_event_data_t *
convert_graph_action(xmlNode * resource, crm_action_t * action, int status, int rc)
{
    xmlNode *xop = NULL;
    lrmd_event_data_t *op = NULL;
    GHashTableIter iter;
    const char *name = NULL;
    const char *value = NULL;
    xmlNode *action_resource = NULL;

    CRM_CHECK(action != NULL, return NULL);
    CRM_CHECK(action->type == action_type_rsc, return NULL);

    action_resource = first_named_child(action->xml, XML_CIB_TAG_RESOURCE);
    CRM_CHECK(action_resource != NULL, crm_log_xml_warn(action->xml, "Bad");
              return NULL);

    op = calloc(1, sizeof(lrmd_event_data_t));

    op->rsc_id = strdup(ID(action_resource));
    op->interval = action->interval;
    op->op_type = strdup(crm_element_value(action->xml, XML_LRM_ATTR_TASK));

    op->rc = rc;
    op->op_status = status;
    op->t_run = time(NULL);
    op->t_rcchange = op->t_run;

    op->params = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                       g_hash_destroy_str, g_hash_destroy_str);

    g_hash_table_iter_init(&iter, action->params);
    while (g_hash_table_iter_next(&iter, (void **)&name, (void **)&value)) {
        g_hash_table_insert(op->params, strdup(name), strdup(value));
    }

    for (xop = __xml_first_child(resource); xop != NULL; xop = __xml_next(xop)) {
        int tmp = 0;

        crm_element_value_int(xop, XML_LRM_ATTR_CALLID, &tmp);
        crm_debug("Got call_id=%d for %s", tmp, ID(resource));
        if (tmp > op->call_id) {
            op->call_id = tmp;
        }
    }

    op->call_id++;
    return op;
}
