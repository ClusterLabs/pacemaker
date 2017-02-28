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

gboolean (*cache_check_fn)(lrmd_rsc_info_t *rsc, const char *node_name) = NULL;

static crm_action_t *
unpack_action(synapse_t * parent, xmlNode * xml_action)
{
    crm_action_t *action = NULL;
    const char *value = crm_element_value(xml_action, XML_ATTR_ID);
    xmlNode *rsc_xml = NULL;

    if (value == NULL) {
        crm_err("Actions must have an id!");
        crm_log_xml_trace(xml_action, "Action with missing id");
        return NULL;
    }

    action = calloc(1, sizeof(crm_action_t));
    if (action == NULL) {
        crm_perror(LOG_CRIT, "Cannot unpack action");
        crm_log_xml_trace(xml_action, "Lost action");
        return NULL;
    }

    action->id = crm_parse_int(value, NULL);
    if (action->id > parent->graph->max_action_id) {
        parent->graph->max_action_id = action->id;
    }

    action->type = action_type_rsc;
    action->xml = copy_xml(xml_action);
    action->synapse = parent;

    if (safe_str_eq(crm_element_name(action->xml), XML_GRAPH_TAG_RSC_OP)) {
        action->type = action_type_rsc;

    } else if (safe_str_eq(crm_element_name(action->xml), XML_GRAPH_TAG_PSEUDO_EVENT)) {
        action->type = action_type_pseudo;

    } else if (safe_str_eq(crm_element_name(action->xml), XML_GRAPH_TAG_CRM_EVENT)) {
        action->type = action_type_crm;
    }

    action->params = xml2list(action->xml);

    value = g_hash_table_lookup(action->params, "CRM_meta_timeout");
    if (value != NULL) {
        action->timeout = crm_parse_int(value, NULL);
    }

    /* Take start-delay into account for the timeout of the action timer */
    value = g_hash_table_lookup(action->params, "CRM_meta_start_delay");
    if (value != NULL) {
        action->timeout += crm_parse_int(value, NULL);
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

    action->task = crm_element_value_copy(action->xml, XML_LRM_ATTR_TASK);

    rsc_xml = find_xml_node(action->xml, XML_CIB_TAG_RESOURCE, FALSE);
    if (!rsc_xml) {
        return action;
    }

    value = crm_element_value(rsc_xml, XML_ATTR_ID_LONG);
    if (value != NULL) {
        g_hash_table_insert(action->params, strdup(XML_ATTR_ID_LONG), strdup(value));
    }

    action->rsc_info = calloc(1, sizeof(lrmd_rsc_info_t));
    action->rsc_info->id = crm_element_value_copy(rsc_xml, XML_ATTR_ID);
    action->rsc_info->class = crm_element_value_copy(rsc_xml, XML_AGENT_ATTR_CLASS);
    action->rsc_info->provider = crm_element_value_copy(rsc_xml, XML_AGENT_ATTR_PROVIDER);
    action->rsc_info->type = crm_element_value_copy(rsc_xml, XML_ATTR_TYPE);

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

    new_synapse->graph = new_graph;

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

static char *
generate_metadata_key(lrmd_rsc_info_t *rsc, const char *node)
{
    char *ra_key = NULL;
    char *result = NULL;

    if (!rsc) {
        return NULL;
    }

    ra_key = crm_generate_ra_key(rsc->class, rsc->provider, rsc->type);
    result = crm_concat(ra_key, node, '_');
    free(ra_key);

    return result;
}

static gboolean
has_injected_metadata_for(crm_action_t *action, GHashTable *injected_metadata)
{
    const char *node = NULL;
    char *key = NULL;
    gboolean result = FALSE;

    CRM_CHECK(action, return FALSE);

    node = crm_meta_value(action->params, XML_LRM_ATTR_TARGET);
    key = generate_metadata_key(action->rsc_info, node);

    if (!key) {
        return FALSE;
    }

    result = g_hash_table_lookup(injected_metadata, key) != NULL;
    free(key);

    return result;
}

static gboolean
has_cached_metadata_for(crm_action_t *action)
{
    const char *node = NULL;

    CRM_CHECK(action, return FALSE);

    if (!action->rsc_info || !cache_check_fn) {
        return FALSE;
    }

    node = crm_meta_value(action->params, XML_LRM_ATTR_TARGET);

    return cache_check_fn(action->rsc_info, node);
}

static void destroy_action(crm_action_t * action);

static GListPtr
prepend_probe_action(GListPtr actions, synapse_t *synapse)
{
    GListPtr lpc;

    for (lpc = synapse->actions; lpc != NULL; lpc = lpc->next) {
        crm_action_t *action = (crm_action_t *) lpc->data;

        if (action->type == action_type_rsc && action->interval == 0 &&
            safe_str_eq(action->task, RSC_STATUS)) {
                actions = g_list_prepend(actions, action);
        }
    }

    return actions;
}

static GListPtr
prepend_start_action(GListPtr actions, synapse_t *synapse)
{
    GListPtr lpc;

    for (lpc = synapse->actions; lpc != NULL; lpc = lpc->next) {
        crm_action_t *action = (crm_action_t *) lpc->data;

        if (action->type == action_type_rsc && safe_str_eq(action->task, RSC_START)) {
            actions = g_list_prepend(actions, action);
        }
    }

    return actions;
}

static GListPtr
prepend_other_action(GListPtr actions, synapse_t *synapse, GHashTable *injected)
{
    GListPtr lpc;

    for (lpc = synapse->actions; lpc != NULL; lpc = lpc->next) {
        crm_action_t *action = (crm_action_t *) lpc->data;

        if (action->type == action_type_rsc && !has_cached_metadata_for(action) &&
                !has_injected_metadata_for(action, injected)) {
            actions = g_list_prepend(actions, action);
        }
    }

    return actions;
}

static void
inject_metadata(crm_action_t *action, GHashTable *injected)
{
    crm_action_t *new_input = NULL;
    synapse_t *new_synapse = NULL;
    xmlNode *synapse = NULL;
    xmlNode *action_set = NULL;
    xmlNode *op = NULL;
    xmlNode *rsc = NULL;
    xmlNode *attrs = NULL;
    char *key = NULL;
    const char *long_id = NULL;
    const char *node = NULL;
    const char *node_uuid = NULL;
    crm_graph_t *graph = NULL;

    CRM_CHECK(action, return);

    if (!action->rsc_info) {
        return;
    }

    graph = action->synapse->graph;

    key = generate_op_key(action->rsc_info->id, RSC_METADATA, 0);

    node = crm_meta_value(action->params, XML_LRM_ATTR_TARGET);
    node_uuid = crm_meta_value(action->params, XML_LRM_ATTR_TARGET_UUID);

    synapse = create_xml_node(NULL, "synapse");
    // graph->num_synapses will be incremented later when whe synapse is unpacked
    crm_xml_add_int(synapse, XML_ATTR_ID, graph->num_synapses);

    action_set = create_xml_node(synapse, "action_set");

    op = create_xml_node(action_set, XML_GRAPH_TAG_RSC_OP);
    crm_xml_add_int(op, XML_ATTR_ID, graph->max_action_id + 1);
    crm_xml_add(op, XML_LRM_ATTR_TASK, RSC_METADATA);
    crm_xml_add(op, XML_LRM_ATTR_TARGET, node);
    crm_xml_add(op, XML_LRM_ATTR_TARGET_UUID, node_uuid);
    crm_xml_add(op, XML_LRM_ATTR_TASK_KEY, key);
    free(key);

    rsc = create_xml_node(op, XML_CIB_TAG_RESOURCE);
    crm_xml_add(rsc, XML_ATTR_ID, action->rsc_info->id);
    crm_xml_add(rsc, XML_AGENT_ATTR_CLASS, action->rsc_info->class);
    crm_xml_add(rsc, XML_AGENT_ATTR_PROVIDER, action->rsc_info->provider);
    crm_xml_add(rsc, XML_ATTR_TYPE, action->rsc_info->type);

    long_id = g_hash_table_lookup(action->params, XML_ATTR_ID_LONG);
    if (long_id) {
        crm_xml_add(rsc, XML_ATTR_ID_LONG, long_id);
    }

    attrs = create_xml_node(op, XML_TAG_ATTRS);
    crm_xml_add_int(attrs, CRM_META "_" XML_ATTR_TIMEOUT, CRMD_METADATA_CALL_TIMEOUT);
    crm_xml_add(attrs, CRM_META "_" XML_LRM_ATTR_TARGET, node);
    crm_xml_add(attrs, CRM_META "_" XML_LRM_ATTR_TARGET_UUID, node_uuid);
    crm_xml_add(attrs, XML_ATTR_CRM_VERSION, g_hash_table_lookup(action->params, XML_ATTR_CRM_VERSION));
    crm_xml_add(attrs, "CRM_meta_on_fail", "ignore");
    crm_xml_add(attrs, "CRM_meta_can_fail", "true");

    new_input = unpack_action(action->synapse, op);
    if (!new_input) {
        free_xml(synapse);
        return;
    }

    new_synapse = unpack_synapse(graph, synapse);
    free_xml(synapse);

    if (!new_synapse) {
        destroy_action(new_input);
        return;
    }

    action->synapse->inputs = g_list_append(action->synapse->inputs, new_input);

    graph->synapses = g_list_prepend(graph->synapses, new_synapse);

    key = generate_metadata_key(action->rsc_info, node);

    if (!key) {
        return;
    }

    g_hash_table_replace(injected, key, key);
}

static void
inject_metadata_for(GListPtr actions, GHashTable *injected)
{
    GListPtr iter;

    for (iter = actions; iter != NULL; iter = iter->next) {
        crm_action_t *action = (crm_action_t *) iter->data;

        if (!has_injected_metadata_for(action, injected)) {
            inject_metadata(action, injected);
        }
    }
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
    GListPtr sIter = NULL;
    GListPtr start_actions = NULL;
    GListPtr probe_actions = NULL;
    GListPtr other_actions = NULL;
    GHashTable *injected = NULL;

    new_graph = calloc(1, sizeof(crm_graph_t));

    new_graph->id = -1;
    new_graph->abort_priority = 0;
    new_graph->network_delay = -1;
    new_graph->transition_timeout = -1;
    new_graph->stonith_timeout = -1;
    new_graph->completion_action = tg_done;
    new_graph->max_action_id = 0;

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
                probe_actions = prepend_probe_action(probe_actions, new_synapse);
                start_actions = prepend_start_action(start_actions, new_synapse);
            }
        }
    }

    injected = g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, NULL);

    inject_metadata_for(probe_actions, injected);
    inject_metadata_for(start_actions, injected);

    for (sIter = new_graph->synapses; sIter != NULL; sIter = sIter->next) {
        synapse_t *synapse = (synapse_t*) sIter->data;

        other_actions = prepend_other_action(other_actions, synapse, injected);
    }

    inject_metadata_for(other_actions, injected);

    g_hash_table_destroy(injected);
    g_list_free(start_actions);
    g_list_free(probe_actions);
    g_list_free(other_actions);

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
    free(action->task);
    lrmd_free_rsc_info(action->rsc_info);
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
    op->op_type = strdup(action->task);

    op->rc = rc;
    op->op_status = status;
    op->t_run = time(NULL);
    op->t_rcchange = op->t_run;

    op->params = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                       g_hash_destroy_str, g_hash_destroy_str);

    g_hash_table_iter_init(&iter, action->params);
    while (g_hash_table_iter_next(&iter, (void **)&name, (void **)&value)) {
        if (safe_str_eq(name, XML_ATTR_ID_LONG)) {
            continue;
        }

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
