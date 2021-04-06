/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include <pacemaker-internal.h>

static crm_action_t *
unpack_action(synapse_t * parent, xmlNode * xml_action)
{
    crm_action_t *action = NULL;
    const char *value = crm_element_value(xml_action, XML_ATTR_ID);

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

    pcmk__scan_min_int(value, &(action->id), -1);
    action->type = action_type_rsc;
    action->xml = copy_xml(xml_action);
    action->synapse = parent;

    if (pcmk__str_eq(crm_element_name(action->xml), XML_GRAPH_TAG_RSC_OP, pcmk__str_casei)) {
        action->type = action_type_rsc;

    } else if (pcmk__str_eq(crm_element_name(action->xml), XML_GRAPH_TAG_PSEUDO_EVENT, pcmk__str_casei)) {
        action->type = action_type_pseudo;

    } else if (pcmk__str_eq(crm_element_name(action->xml), XML_GRAPH_TAG_CRM_EVENT, pcmk__str_casei)) {
        action->type = action_type_crm;
    }

    action->params = xml2list(action->xml);

    value = g_hash_table_lookup(action->params, "CRM_meta_timeout");
    pcmk__scan_min_int(value, &(action->timeout), 0);

    /* Take start-delay into account for the timeout of the action timer */
    value = g_hash_table_lookup(action->params, "CRM_meta_start_delay");
    {
        int start_delay;

        pcmk__scan_min_int(value, &start_delay, 0);
        action->timeout += start_delay;
    }

    if (pcmk__guint_from_hash(action->params,
                              CRM_META "_" XML_LRM_ATTR_INTERVAL, 0,
                              &(action->interval_ms)) != pcmk_rc_ok) {
        action->interval_ms = 0;
    }

    value = g_hash_table_lookup(action->params, "CRM_meta_can_fail");
    if (value != NULL) {
        crm_str_to_boolean(value, &(action->can_fail));
#ifndef PCMK__COMPAT_2_0
        if (action->can_fail) {
            crm_warn("Support for the can_fail meta-attribute is deprecated"
                     " and will be removed in a future release");
        }
#endif
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
    pcmk__scan_min_int(ID(xml_synapse), &(new_synapse->id), 0);

    value = crm_element_value(xml_synapse, XML_CIB_ATTR_PRIORITY);
    pcmk__scan_min_int(value, &(new_synapse->priority), 0);

    CRM_CHECK(new_synapse->id >= 0, free(new_synapse);
              return NULL);

    new_graph->num_synapses++;

    crm_trace("look for actions in synapse %s", crm_element_value(xml_synapse, XML_ATTR_ID));

    for (action_set = pcmk__xml_first_child(xml_synapse); action_set != NULL;
         action_set = pcmk__xml_next(action_set)) {

        if (pcmk__str_eq((const char *)action_set->name, "action_set",
                         pcmk__str_none)) {
            xmlNode *action = NULL;

            for (action = pcmk__xml_first_child(action_set); action != NULL;
                 action = pcmk__xml_next(action)) {
                crm_action_t *new_action = unpack_action(new_synapse, action);

                if (new_action == NULL) {
                    continue;
                }

                new_graph->num_actions++;

                crm_trace("Adding action %d to synapse %d", new_action->id, new_synapse->id);

                new_synapse->actions = g_list_append(new_synapse->actions, new_action);
            }
        }
    }

    crm_trace("look for inputs in synapse %s", ID(xml_synapse));

    for (inputs = pcmk__xml_first_child(xml_synapse); inputs != NULL;
         inputs = pcmk__xml_next(inputs)) {

        if (pcmk__str_eq((const char *)inputs->name, "inputs", pcmk__str_none)) {
            xmlNode *trigger = NULL;

            for (trigger = pcmk__xml_first_child(inputs); trigger != NULL;
                 trigger = pcmk__xml_next(trigger)) {
                xmlNode *input = NULL;

                for (input = pcmk__xml_first_child(trigger); input != NULL;
                     input = pcmk__xml_next(input)) {
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

static void destroy_action(crm_action_t * action);

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
    new_graph->network_delay = 0;
    new_graph->stonith_timeout = 0;
    new_graph->completion_action = tg_done;

    if (reference) {
        new_graph->source = strdup(reference);
    } else {
        new_graph->source = strdup("unknown");
    }

    if (xml_graph != NULL) {
        t_id = crm_element_value(xml_graph, "transition_id");
        CRM_CHECK(t_id != NULL, free(new_graph);
                  return NULL);
        pcmk__scan_min_int(t_id, &(new_graph->id), -1);

        time = crm_element_value(xml_graph, "cluster-delay");
        CRM_CHECK(time != NULL, free(new_graph);
                  return NULL);
        new_graph->network_delay = crm_parse_interval_spec(time);

        time = crm_element_value(xml_graph, "stonith-timeout");
        if (time == NULL) {
            new_graph->stonith_timeout = new_graph->network_delay;
        } else {
            new_graph->stonith_timeout = crm_parse_interval_spec(time);
        }

        // Use 0 (dynamic limit) as default/invalid, -1 (no limit) as minimum
        t_id = crm_element_value(xml_graph, "batch-limit");
        if ((t_id == NULL)
            || (pcmk__scan_min_int(t_id, &(new_graph->batch_limit),
                                   -1) != pcmk_rc_ok)) {
            new_graph->batch_limit = 0;
        }

        t_id = crm_element_value(xml_graph, "migration-limit");
        pcmk__scan_min_int(t_id, &(new_graph->migration_limit), -1);
    }

    for (synapse = pcmk__xml_first_child(xml_graph); synapse != NULL;
         synapse = pcmk__xml_next(synapse)) {

        if (pcmk__str_eq((const char *)synapse->name, "synapse", pcmk__str_none)) {
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
    while (synapse->actions != NULL) {
        crm_action_t *action = g_list_nth_data(synapse->actions, 0);

        synapse->actions = g_list_remove(synapse->actions, action);
        destroy_action(action);
    }

    while (synapse->inputs != NULL) {
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
    while (graph->synapses != NULL) {
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

    op = lrmd_new_event(ID(action_resource),
                        crm_element_value(action->xml, XML_LRM_ATTR_TASK),
                        action->interval_ms);
    op->rc = rc;
    op->op_status = status;
    op->t_run = time(NULL);
    op->t_rcchange = op->t_run;
    op->params = pcmk__strkey_table(free, free);

    g_hash_table_iter_init(&iter, action->params);
    while (g_hash_table_iter_next(&iter, (void **)&name, (void **)&value)) {
        g_hash_table_insert(op->params, strdup(name), strdup(value));
    }

    for (xop = pcmk__xml_first_child(resource); xop != NULL;
         xop = pcmk__xml_next(xop)) {
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
