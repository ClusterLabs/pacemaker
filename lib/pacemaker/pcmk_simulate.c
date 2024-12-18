/*
 * Copyright 2021-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/cib/internal.h>
#include <crm/common/output.h>
#include <crm/common/results.h>
#include <crm/common/scheduler.h>
#include <pacemaker-internal.h>
#include <pacemaker.h>

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libpacemaker_private.h"

static pcmk__output_t *out = NULL;
static cib_t *fake_cib = NULL;
static GList *fake_resource_list = NULL;
static const GList *fake_op_fail_list = NULL;

static void set_effective_date(pcmk_scheduler_t *scheduler, bool print_original,
                               const char *use_date);

/*!
 * \internal
 * \brief Create an action name for use in a dot graph
 *
 * \param[in] action   Action to create name for
 * \param[in] verbose  If true, add action ID to name
 *
 * \return Newly allocated string with action name
 * \note It is the caller's responsibility to free the result.
 */
static char *
create_action_name(const pcmk_action_t *action, bool verbose)
{
    char *action_name = NULL;
    const char *prefix = "";
    const char *action_host = NULL;
    const char *history_id = NULL;
    const char *task = action->task;

    if (action->node != NULL) {
        action_host = action->node->priv->name;
    } else if (!pcmk_is_set(action->flags, pcmk__action_pseudo)) {
        action_host = "<none>";
    }

    if (pcmk__str_eq(action->task, PCMK_ACTION_CANCEL, pcmk__str_none)) {
        prefix = "Cancel ";
        task = action->cancel_task;
    }

    if (action->rsc != NULL) {
        history_id = action->rsc->priv->history_id;
    }

    if (history_id != NULL) {
        char *key = NULL;
        guint interval_ms = 0;

        if (pcmk__guint_from_hash(action->meta, PCMK_META_INTERVAL, 0,
                                  &interval_ms) != pcmk_rc_ok) {
            interval_ms = 0;
        }

        if (pcmk__strcase_any_of(action->task, PCMK_ACTION_NOTIFY,
                                 PCMK_ACTION_NOTIFIED, NULL)) {
            const char *n_type = g_hash_table_lookup(action->meta,
                                                     "notify_key_type");
            const char *n_task = g_hash_table_lookup(action->meta,
                                                     "notify_key_operation");

            pcmk__assert((n_type != NULL) && (n_task != NULL));
            key = pcmk__notify_key(history_id, n_type, n_task);
        } else {
            key = pcmk__op_key(history_id, task, interval_ms);
        }

        if (action_host != NULL) {
            action_name = crm_strdup_printf("%s%s %s",
                                            prefix, key, action_host);
        } else {
            action_name = crm_strdup_printf("%s%s", prefix, key);
        }
        free(key);

    } else if (pcmk__str_eq(action->task, PCMK_ACTION_STONITH,
                            pcmk__str_none)) {
        const char *op = g_hash_table_lookup(action->meta,
                                             PCMK__META_STONITH_ACTION);

        action_name = crm_strdup_printf("%s%s '%s' %s",
                                        prefix, action->task, op, action_host);

    } else if (action->rsc && action_host) {
        action_name = crm_strdup_printf("%s%s %s",
                                        prefix, action->uuid, action_host);

    } else if (action_host) {
        action_name = crm_strdup_printf("%s%s %s",
                                        prefix, action->task, action_host);

    } else {
        action_name = crm_strdup_printf("%s", action->uuid);
    }

    if (verbose) {
        char *with_id = crm_strdup_printf("%s (%d)", action_name, action->id);

        free(action_name);
        action_name = with_id;
    }
    return action_name;
}

/*!
 * \internal
 * \brief Display the status of a cluster
 *
 * \param[in,out] scheduler     Scheduler data
 * \param[in]     show_opts     How to modify display (as pcmk_show_opt_e flags)
 * \param[in]     section_opts  Sections to display (as pcmk_section_e flags)
 * \param[in]     title         What to use as list title
 * \param[in]     print_spacer  Whether to display a spacer first
 */
static void
print_cluster_status(pcmk_scheduler_t *scheduler, uint32_t show_opts,
                     uint32_t section_opts, const char *title,
                     bool print_spacer)
{
    pcmk__output_t *out = scheduler->priv->out;
    GList *all = NULL;
    crm_exit_t stonith_rc = 0;
    enum pcmk_pacemakerd_state state = pcmk_pacemakerd_state_invalid;

    section_opts |= pcmk_section_nodes | pcmk_section_resources;
    show_opts |= pcmk_show_inactive_rscs | pcmk_show_failed_detail;

    all = g_list_prepend(all, (gpointer) "*");

    PCMK__OUTPUT_SPACER_IF(out, print_spacer);
    out->begin_list(out, NULL, NULL, "%s", title);
    out->message(out, "cluster-status",
                 scheduler, state, stonith_rc, NULL,
                 pcmk__fence_history_none, section_opts, show_opts, NULL,
                 all, all);
    out->end_list(out);

    g_list_free(all);
}

/*!
 * \internal
 * \brief Display a summary of all actions scheduled in a transition
 *
 * \param[in,out] scheduler     Scheduler data (fully scheduled)
 * \param[in]     print_spacer  Whether to display a spacer first
 */
static void
print_transition_summary(pcmk_scheduler_t *scheduler, bool print_spacer)
{
    pcmk__output_t *out = scheduler->priv->out;

    PCMK__OUTPUT_SPACER_IF(out, print_spacer);
    out->begin_list(out, NULL, NULL, "Transition Summary");
    pcmk__output_actions(scheduler);
    out->end_list(out);
}

/*!
 * \internal
 * \brief Reset scheduler input, output, date, and flags
 *
 * \param[in,out] scheduler  Scheduler data
 * \param[in]     input      What to set as cluster input
 * \param[in]     out        What to set as cluster output object
 * \param[in]     use_date   What to set as cluster's current timestamp
 * \param[in]     flags      Group of enum pcmk__scheduler_flags to set
 */
static void
reset(pcmk_scheduler_t *scheduler, xmlNodePtr input, pcmk__output_t *out,
      const char *use_date, unsigned int flags)
{
    scheduler->input = input;
    scheduler->priv->out = out;
    set_effective_date(scheduler, true, use_date);
    if (pcmk_is_set(flags, pcmk_sim_sanitized)) {
        pcmk__set_scheduler_flags(scheduler, pcmk__sched_sanitized);
    }
    if (pcmk_is_set(flags, pcmk_sim_show_scores)) {
        pcmk__set_scheduler_flags(scheduler, pcmk__sched_output_scores);
    }
    if (pcmk_is_set(flags, pcmk_sim_show_utilization)) {
        pcmk__set_scheduler_flags(scheduler, pcmk__sched_show_utilization);
    }
}

/*!
 * \brief Write out a file in dot(1) format describing the actions that will
 *        be taken by the scheduler in response to an input CIB file.
 *
 * \param[in,out] scheduler    Scheduler data
 * \param[in]     dot_file     The filename to write
 * \param[in]     all_actions  Write all actions, even those that are optional
 *                             or are on unmanaged resources
 * \param[in]     verbose      Add extra information, such as action IDs, to the
 *                             output
 *
 * \return Standard Pacemaker return code
 */
static int
write_sim_dotfile(pcmk_scheduler_t *scheduler, const char *dot_file,
                  bool all_actions, bool verbose)
{
    GList *iter = NULL;
    FILE *dot_strm = fopen(dot_file, "w");

    if (dot_strm == NULL) {
        return errno;
    }

    fprintf(dot_strm, " digraph \"g\" {\n");
    for (iter = scheduler->priv->actions; iter != NULL; iter = iter->next) {
        pcmk_action_t *action = (pcmk_action_t *) iter->data;
        const char *style = "dashed";
        const char *font = "black";
        const char *color = "black";
        char *action_name = create_action_name(action, verbose);

        if (pcmk_is_set(action->flags, pcmk__action_pseudo)) {
            font = "orange";
        }

        if (pcmk_is_set(action->flags, pcmk__action_added_to_graph)) {
            style = PCMK__VALUE_BOLD;
            color = "green";

        } else if ((action->rsc != NULL)
                   && !pcmk_is_set(action->rsc->flags, pcmk__rsc_managed)) {
            color = "red";
            font = "purple";
            if (!all_actions) {
                goto do_not_write;
            }

        } else if (pcmk_is_set(action->flags, pcmk__action_optional)) {
            color = "blue";
            if (!all_actions) {
                goto do_not_write;
            }

        } else {
            color = "red";
            CRM_LOG_ASSERT(!pcmk_is_set(action->flags, pcmk__action_runnable));
        }

        pcmk__set_action_flags(action, pcmk__action_added_to_graph);
        fprintf(dot_strm, "\"%s\" [ style=%s color=\"%s\" fontcolor=\"%s\"]\n",
                action_name, style, color, font);
  do_not_write:
        free(action_name);
    }

    for (iter = scheduler->priv->actions; iter != NULL; iter = iter->next) {
        pcmk_action_t *action = (pcmk_action_t *) iter->data;

        for (GList *before_iter = action->actions_before;
             before_iter != NULL; before_iter = before_iter->next) {

            pcmk__related_action_t *before = before_iter->data;

            char *before_name = NULL;
            char *after_name = NULL;
            const char *style = "dashed";
            bool optional = true;

            if (before->graphed) {
                optional = false;
                style = PCMK__VALUE_BOLD;
            } else if (before->flags == pcmk__ar_none) {
                continue;
            } else if (pcmk_is_set(before->action->flags,
                                   pcmk__action_added_to_graph)
                       && pcmk_is_set(action->flags, pcmk__action_added_to_graph)
                       && before->flags != pcmk__ar_if_on_same_node_or_target) {
                optional = false;
            }

            if (all_actions || !optional) {
                before_name = create_action_name(before->action, verbose);
                after_name = create_action_name(action, verbose);
                fprintf(dot_strm, "\"%s\" -> \"%s\" [ style = %s]\n",
                        before_name, after_name, style);
                free(before_name);
                free(after_name);
            }
        }
    }

    fprintf(dot_strm, "}\n");
    fflush(dot_strm);
    fclose(dot_strm);
    return pcmk_rc_ok;
}

/*!
 * \brief Profile the configuration updates and scheduler actions in a single
 *        CIB file, printing the profiling timings.
 *
 * \note \p scheduler->priv->out must have been set to a valid \p pcmk__output_t
 *       object before this function is called.
 *
 * \param[in]     xml_file   The CIB file to profile
 * \param[in]     repeat     Number of times to run
 * \param[in,out] scheduler  Scheduler data
 * \param[in]     use_date   The date to set the cluster's time to (may be NULL)
 */
static void
profile_file(const char *xml_file, long long repeat,
             pcmk_scheduler_t *scheduler, const char *use_date)
{
    pcmk__output_t *out = scheduler->priv->out;
    xmlNode *cib_object = NULL;
    clock_t start = 0;
    clock_t end;
    unsigned long long scheduler_flags = pcmk__sched_none;

    pcmk__assert(out != NULL);

    cib_object = pcmk__xml_read(xml_file);
    start = clock();

    if (pcmk_find_cib_element(cib_object, PCMK_XE_STATUS) == NULL) {
        pcmk__xe_create(cib_object, PCMK_XE_STATUS);
    }

    if (pcmk__update_configured_schema(&cib_object, false) != pcmk_rc_ok) {
        pcmk__xml_free(cib_object);
        return;
    }

    if (!pcmk__validate_xml(cib_object, NULL, NULL, NULL)) {
        pcmk__xml_free(cib_object);
        return;
    }

    if (pcmk_is_set(scheduler->flags, pcmk__sched_output_scores)) {
        scheduler_flags |= pcmk__sched_output_scores;
    }
    if (pcmk_is_set(scheduler->flags, pcmk__sched_show_utilization)) {
        scheduler_flags |= pcmk__sched_show_utilization;
    }

    for (int i = 0; i < repeat; ++i) {
        int rc;
        xmlNode *input = cib_object;

        if (repeat > 1) {
            input = pcmk__xml_copy(NULL, cib_object);
        }
        scheduler->input = input;
        set_effective_date(scheduler, false, use_date);
        rc = pcmk__schedule_actions(input, scheduler_flags, scheduler);
        pe_reset_working_set(scheduler);

        if (rc != pcmk_rc_ok) {
            break;
        }
    }

    end = clock();
    out->message(out, "profile", xml_file, start, end);
}

void
pcmk__profile_dir(const char *dir, long long repeat,
                  pcmk_scheduler_t *scheduler, const char *use_date)
{
    pcmk__output_t *out = scheduler->priv->out;
    struct dirent **namelist;

    int file_num = scandir(dir, &namelist, 0, alphasort);

    pcmk__assert(out != NULL);

    if (file_num > 0) {
        struct stat prop;
        char buffer[FILENAME_MAX];

        out->begin_list(out, NULL, NULL, "Timings");

        while (file_num--) {
            if ('.' == namelist[file_num]->d_name[0]) {
                free(namelist[file_num]);
                continue;

            } else if (!pcmk__ends_with_ext(namelist[file_num]->d_name,
                                            ".xml")) {
                free(namelist[file_num]);
                continue;
            }
            snprintf(buffer, sizeof(buffer), "%s/%s",
                     dir, namelist[file_num]->d_name);
            if (stat(buffer, &prop) == 0 && S_ISREG(prop.st_mode)) {
                profile_file(buffer, repeat, scheduler, use_date);
            }
            free(namelist[file_num]);
        }
        free(namelist);

        out->end_list(out);
    }
}

/*!
 * \brief Set the date of the cluster, either to the value given by
 *        \p use_date, or to the \c PCMK_XA_EXECUTION_DATE value in the CIB.
 *
 * \note \p scheduler->priv->out must have been set to a valid \p pcmk__output_t
 *       object before this function is called.
 *
 * \param[in,out] scheduler       Scheduler data
 * \param[in]     print_original  If \p true, the \c PCMK_XA_EXECUTION_DATE
 *                                should also be printed
 * \param[in]     use_date        The date to set the cluster's time to
 *                                (may be NULL)
 */
static void
set_effective_date(pcmk_scheduler_t *scheduler, bool print_original,
                   const char *use_date)
{
    pcmk__output_t *out = scheduler->priv->out;
    time_t original_date = 0;

    pcmk__assert(out != NULL);

    crm_element_value_epoch(scheduler->input, PCMK_XA_EXECUTION_DATE,
                            &original_date);

    if (use_date) {
        scheduler->priv->now = crm_time_new(use_date);
        out->info(out, "Setting effective cluster time: %s", use_date);
        crm_time_log(LOG_NOTICE, "Pretending 'now' is", scheduler->priv->now,
                     crm_time_log_date | crm_time_log_timeofday);

    } else if (original_date != 0) {
        scheduler->priv->now = pcmk__copy_timet(original_date);

        if (print_original) {
            char *when = crm_time_as_string(scheduler->priv->now,
                                            crm_time_log_date
                                            |crm_time_log_timeofday);

            out->info(out, "Using the original execution date of: %s", when);
            free(when);
        }
    }
}

/*!
 * \internal
 * \brief Simulate successfully executing a pseudo-action in a graph
 *
 * \param[in,out] graph   Graph to update with pseudo-action result
 * \param[in,out] action  Pseudo-action to simulate executing
 *
 * \return Standard Pacemaker return code
 */
static int
simulate_pseudo_action(pcmk__graph_t *graph, pcmk__graph_action_t *action)
{
    const char *node = crm_element_value(action->xml, PCMK__META_ON_NODE);
    const char *task = crm_element_value(action->xml, PCMK__XA_OPERATION_KEY);

    pcmk__set_graph_action_flags(action, pcmk__graph_action_confirmed);
    out->message(out, "inject-pseudo-action", node, task);

    pcmk__update_graph(graph, action);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Simulate executing a resource action in a graph
 *
 * \param[in,out] graph   Graph to update with resource action result
 * \param[in,out] action  Resource action to simulate executing
 *
 * \return Standard Pacemaker return code
 */
static int
simulate_resource_action(pcmk__graph_t *graph, pcmk__graph_action_t *action)
{
    int rc;
    lrmd_event_data_t *op = NULL;
    int target_outcome = PCMK_OCF_OK;

    const char *rtype = NULL;
    const char *rclass = NULL;
    const char *resource = NULL;
    const char *rprovider = NULL;
    const char *resource_config_name = NULL;
    const char *operation = crm_element_value(action->xml, PCMK_XA_OPERATION);
    const char *target_rc_s = crm_meta_value(action->params,
                                             PCMK__META_OP_TARGET_RC);

    xmlNode *cib_node = NULL;
    xmlNode *cib_resource = NULL;
    xmlNode *action_rsc = pcmk__xe_first_child(action->xml, PCMK_XE_PRIMITIVE,
                                               NULL, NULL);

    char *node = crm_element_value_copy(action->xml, PCMK__META_ON_NODE);
    char *uuid = NULL;
    const char *router_node = crm_element_value(action->xml,
                                                PCMK__XA_ROUTER_NODE);

    // Certain actions don't need to be displayed or history entries
    if (pcmk__str_eq(operation, CRM_OP_REPROBE, pcmk__str_none)) {
        crm_debug("No history injection for %s op on %s", operation, node);
        goto done; // Confirm action and update graph
    }

    if (action_rsc == NULL) { // Shouldn't be possible
        crm_log_xml_err(action->xml, "Bad");
        free(node);
        return EPROTO;
    }

    /* A resource might be known by different names in the configuration and in
     * the action (for example, a clone instance). Grab the configuration name
     * (which is preferred when writing history), and if necessary, the instance
     * name.
     */
    resource_config_name = crm_element_value(action_rsc, PCMK_XA_ID);
    if (resource_config_name == NULL) { // Shouldn't be possible
        crm_log_xml_err(action->xml, "No ID");
        free(node);
        return EPROTO;
    }
    resource = resource_config_name;
    if (pe_find_resource(fake_resource_list, resource) == NULL) {
        const char *longname = crm_element_value(action_rsc, PCMK__XA_LONG_ID);

        if ((longname != NULL)
            && (pe_find_resource(fake_resource_list, longname) != NULL)) {
            resource = longname;
        }
    }

    // Certain actions need to be displayed but don't need history entries
    if (pcmk__strcase_any_of(operation, PCMK_ACTION_DELETE,
                             PCMK_ACTION_META_DATA, NULL)) {
        out->message(out, "inject-rsc-action", resource, operation, node,
                     (guint) 0);
        goto done; // Confirm action and update graph
    }

    rclass = crm_element_value(action_rsc, PCMK_XA_CLASS);
    rtype = crm_element_value(action_rsc, PCMK_XA_TYPE);
    rprovider = crm_element_value(action_rsc, PCMK_XA_PROVIDER);

    pcmk__scan_min_int(target_rc_s, &target_outcome, 0);

    pcmk__assert(fake_cib->cmds->query(fake_cib, NULL, NULL,
                                       cib_sync_call) == pcmk_ok);

    // Ensure the action node is in the CIB
    uuid = crm_element_value_copy(action->xml, PCMK__META_ON_NODE_UUID);
    cib_node = pcmk__inject_node(fake_cib, node,
                                 ((router_node == NULL)? uuid: node));
    free(uuid);
    pcmk__assert(cib_node != NULL);

    // Add a history entry for the action
    cib_resource = pcmk__inject_resource_history(out, cib_node, resource,
                                                 resource_config_name,
                                                 rclass, rtype, rprovider);
    if (cib_resource == NULL) {
        crm_err("Could not simulate action %d history for resource %s",
                action->id, resource);
        free(node);
        pcmk__xml_free(cib_node);
        return EINVAL;
    }

    // Simulate and display an executor event for the action result
    op = pcmk__event_from_graph_action(cib_resource, action, PCMK_EXEC_DONE,
                                       target_outcome, "User-injected result");
    out->message(out, "inject-rsc-action", resource, op->op_type, node,
                 op->interval_ms);

    // Check whether action is in a list of desired simulated failures
    for (const GList *iter = fake_op_fail_list;
         iter != NULL; iter = iter->next) {
        const char *spec = (const char *) iter->data;
        char *key = NULL;
        const char *match_name = NULL;
        const char *offset = NULL;

        // Allow user to specify anonymous clone with or without instance number
        key = crm_strdup_printf(PCMK__OP_FMT "@%s=", resource, op->op_type,
                                op->interval_ms, node);
        if (strncasecmp(key, spec, strlen(key)) == 0) {
            match_name = resource;
        }
        free(key);

        // If not found, try the resource's name in the configuration
        if ((match_name == NULL)
            && (strcmp(resource, resource_config_name) != 0)) {

            key = crm_strdup_printf(PCMK__OP_FMT "@%s=", resource_config_name,
                                    op->op_type, op->interval_ms, node);
            if (strncasecmp(key, spec, strlen(key)) == 0) {
                match_name = resource_config_name;
            }
            free(key);
        }

        if (match_name == NULL) {
            continue; // This failed action entry doesn't match
        }

        // ${match_name}_${task}_${interval_in_ms}@${node}=${rc}
        rc = sscanf(spec, "%*[^=]=%d", (int *) &op->rc);
        if (rc != 1) {
            out->err(out, "Invalid failed operation '%s' "
                          "(result code must be integer)", spec);
            continue; // Keep checking other list entries
        }

        out->info(out, "Pretending action %d failed with rc=%d",
                  action->id, op->rc);
        pcmk__set_graph_action_flags(action, pcmk__graph_action_failed);
        graph->abort_priority = PCMK_SCORE_INFINITY;

        if (pcmk__str_eq(op->op_type, PCMK_ACTION_START, pcmk__str_none)) {
            offset = pcmk__s(graph->failed_start_offset, PCMK_VALUE_INFINITY);

        } else if (pcmk__str_eq(op->op_type, PCMK_ACTION_STOP,
                                pcmk__str_none)) {
            offset = pcmk__s(graph->failed_stop_offset, PCMK_VALUE_INFINITY);
        }

        pcmk__inject_failcount(out, fake_cib, cib_node, match_name, op->op_type,
                               op->interval_ms, op->rc,
                               pcmk_str_is_infinity(offset));
        break;
    }

    pcmk__inject_action_result(cib_resource, op, node, target_outcome);
    lrmd_free_event(op);
    rc = fake_cib->cmds->modify(fake_cib, PCMK_XE_STATUS, cib_node,
                                cib_sync_call);
    pcmk__assert(rc == pcmk_ok);

  done:
    free(node);
    pcmk__xml_free(cib_node);
    pcmk__set_graph_action_flags(action, pcmk__graph_action_confirmed);
    pcmk__update_graph(graph, action);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Simulate successfully executing a cluster action
 *
 * \param[in,out] graph   Graph to update with action result
 * \param[in,out] action  Cluster action to simulate
 *
 * \return Standard Pacemaker return code
 */
static int
simulate_cluster_action(pcmk__graph_t *graph, pcmk__graph_action_t *action)
{
    const char *node = crm_element_value(action->xml, PCMK__META_ON_NODE);
    const char *task = crm_element_value(action->xml, PCMK_XA_OPERATION);
    xmlNode *rsc = pcmk__xe_first_child(action->xml, PCMK_XE_PRIMITIVE, NULL,
                                        NULL);

    pcmk__set_graph_action_flags(action, pcmk__graph_action_confirmed);
    out->message(out, "inject-cluster-action", node, task, rsc);
    pcmk__update_graph(graph, action);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Simulate successfully executing a fencing action
 *
 * \param[in,out] graph   Graph to update with action result
 * \param[in,out] action  Fencing action to simulate
 *
 * \return Standard Pacemaker return code
 */
static int
simulate_fencing_action(pcmk__graph_t *graph, pcmk__graph_action_t *action)
{
    const char *op = crm_meta_value(action->params, PCMK__META_STONITH_ACTION);
    char *target = crm_element_value_copy(action->xml, PCMK__META_ON_NODE);

    out->message(out, "inject-fencing-action", target, op);

    if (!pcmk__str_eq(op, PCMK_ACTION_ON, pcmk__str_casei)) {
        int rc = pcmk_ok;
        GString *xpath = g_string_sized_new(512);

        // Set node state to offline
        xmlNode *cib_node = pcmk__inject_node_state_change(fake_cib, target,
                                                           false);

        pcmk__assert(cib_node != NULL);
        crm_xml_add(cib_node, PCMK_XA_CRM_DEBUG_ORIGIN, __func__);
        rc = fake_cib->cmds->replace(fake_cib, PCMK_XE_STATUS, cib_node,
                                     cib_sync_call);
        pcmk__assert(rc == pcmk_ok);

        // Simulate controller clearing node's resource history and attributes
        pcmk__g_strcat(xpath,
                       "//" PCMK__XE_NODE_STATE
                       "[@" PCMK_XA_UNAME "='", target, "']/" PCMK__XE_LRM,
                       NULL);
        fake_cib->cmds->remove(fake_cib, (const char *) xpath->str, NULL,
                               cib_xpath|cib_sync_call);

        g_string_truncate(xpath, 0);
        pcmk__g_strcat(xpath,
                       "//" PCMK__XE_NODE_STATE
                       "[@" PCMK_XA_UNAME "='", target, "']"
                       "/" PCMK__XE_TRANSIENT_ATTRIBUTES, NULL);
        fake_cib->cmds->remove(fake_cib, (const char *) xpath->str, NULL,
                               cib_xpath|cib_sync_call);

        pcmk__xml_free(cib_node);
        g_string_free(xpath, TRUE);
    }

    pcmk__set_graph_action_flags(action, pcmk__graph_action_confirmed);
    pcmk__update_graph(graph, action);
    free(target);
    return pcmk_rc_ok;
}

enum pcmk__graph_status
pcmk__simulate_transition(pcmk_scheduler_t *scheduler, cib_t *cib,
                          const GList *op_fail_list)
{
    pcmk__graph_t *transition = NULL;
    enum pcmk__graph_status graph_rc;

    pcmk__graph_functions_t simulation_fns = {
        simulate_pseudo_action,
        simulate_resource_action,
        simulate_cluster_action,
        simulate_fencing_action,
    };

    out = scheduler->priv->out;

    fake_cib = cib;
    fake_op_fail_list = op_fail_list;

    if (!out->is_quiet(out)) {
        out->begin_list(out, NULL, NULL, "Executing Cluster Transition");
    }

    pcmk__set_graph_functions(&simulation_fns);
    transition = pcmk__unpack_graph(scheduler->priv->graph, crm_system_name);
    pcmk__log_graph(LOG_DEBUG, transition);

    fake_resource_list = scheduler->priv->resources;
    do {
        graph_rc = pcmk__execute_graph(transition);
    } while (graph_rc == pcmk__graph_active);
    fake_resource_list = NULL;

    if (graph_rc != pcmk__graph_complete) {
        out->err(out, "Transition failed: %s",
                 pcmk__graph_status2text(graph_rc));
        pcmk__log_graph(LOG_ERR, transition);
        out->err(out, "An invalid transition was produced");
    }
    pcmk__free_graph(transition);

    if (!out->is_quiet(out)) {
        // If not quiet, we'll need the resulting CIB for later display
        xmlNode *cib_object = NULL;
        int rc = fake_cib->cmds->query(fake_cib, NULL, &cib_object,
                                       cib_sync_call);

        pcmk__assert(rc == pcmk_ok);
        pe_reset_working_set(scheduler);
        scheduler->input = cib_object;
        out->end_list(out);
    }
    return graph_rc;
}

int
pcmk__simulate(pcmk_scheduler_t *scheduler, pcmk__output_t *out,
               const pcmk_injections_t *injections, unsigned int flags,
               uint32_t section_opts, const char *use_date,
               const char *input_file, const char *graph_file,
               const char *dot_file)
{
    int printed = pcmk_rc_no_output;
    int rc = pcmk_rc_ok;
    xmlNodePtr input = NULL;
    cib_t *cib = NULL;

    rc = cib__signon_query(out, &cib, &input);
    if (rc != pcmk_rc_ok) {
        goto simulate_done;
    }

    reset(scheduler, input, out, use_date, flags);
    rc = pcmk_unpack_scheduler_input(scheduler);

    if (rc != pcmk_rc_ok) {
        goto simulate_done;
    }

    if (!out->is_quiet(out)) {
        const bool show_pending = pcmk_is_set(flags, pcmk_sim_show_pending);

        if (pcmk_is_set(scheduler->flags, pcmk__sched_in_maintenance)) {
            printed = out->message(out, "maint-mode", scheduler->flags);
        }

        if ((scheduler->priv->disabled_resources > 0)
            || (scheduler->priv->blocked_resources > 0)) {

            PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
            printed = out->info(out,
                                "%d of %d resource instances DISABLED and "
                                "%d BLOCKED from further action due to failure",
                                scheduler->priv->disabled_resources,
                                scheduler->priv->ninstances,
                                scheduler->priv->blocked_resources);
        }

        /* Most formatted output headers use caps for each word, but this one
         * only has the first word capitalized for compatibility with pcs.
         */
        print_cluster_status(scheduler, (show_pending? pcmk_show_pending : 0),
                             section_opts, "Current cluster status",
                             (printed == pcmk_rc_ok));
        printed = pcmk_rc_ok;
    }

    // If the user requested any injections, handle them
    if ((injections->node_down != NULL)
        || (injections->node_fail != NULL)
        || (injections->node_up != NULL)
        || (injections->op_inject != NULL)
        || (injections->ticket_activate != NULL)
        || (injections->ticket_grant != NULL)
        || (injections->ticket_revoke != NULL)
        || (injections->ticket_standby != NULL)
        || (injections->watchdog != NULL)) {

        PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
        pcmk__inject_scheduler_input(scheduler, cib, injections);
        printed = pcmk_rc_ok;

        rc = cib->cmds->query(cib, NULL, &input, cib_sync_call);
        if (rc != pcmk_rc_ok) {
            rc = pcmk_legacy2rc(rc);
            goto simulate_done;
        }

        cleanup_calculations(scheduler);
        reset(scheduler, input, out, use_date, flags);
        /* pcmk_unpack_scheduler_input only returns error on scheduler being
         * NULL or the feature set being unsupported.  Neither of those
         * conditions could have changed since the first call, so there's no
         * need to check the return value again.
         */
        pcmk_unpack_scheduler_input(scheduler);
    }

    if (input_file != NULL) {
        rc = pcmk__xml_write_file(input, input_file, false);
        if (rc != pcmk_rc_ok) {
            goto simulate_done;
        }
    }

    if (pcmk_any_flags_set(flags, pcmk_sim_process | pcmk_sim_simulate)) {
        pcmk__output_t *logger_out = NULL;
        unsigned long long scheduler_flags = pcmk__sched_none;

        if (pcmk_is_set(scheduler->flags, pcmk__sched_output_scores)) {
            scheduler_flags |= pcmk__sched_output_scores;
        }
        if (pcmk_is_set(scheduler->flags, pcmk__sched_show_utilization)) {
            scheduler_flags |= pcmk__sched_show_utilization;
        }

        if (pcmk_all_flags_set(scheduler->flags,
                               pcmk__sched_output_scores
                               |pcmk__sched_show_utilization)) {
            PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
            out->begin_list(out, NULL, NULL,
                            "Assignment Scores and Utilization Information");
            printed = pcmk_rc_ok;

        } else if (pcmk_is_set(scheduler->flags, pcmk__sched_output_scores)) {
            PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
            out->begin_list(out, NULL, NULL, "Assignment Scores");
            printed = pcmk_rc_ok;

        } else if (pcmk_is_set(scheduler->flags, pcmk__sched_show_utilization)) {
            PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
            out->begin_list(out, NULL, NULL, "Utilization Information");
            printed = pcmk_rc_ok;

        } else {
            rc = pcmk__log_output_new(&logger_out);
            if (rc != pcmk_rc_ok) {
                goto simulate_done;
            }
            pe__register_messages(logger_out);
            pcmk__register_lib_messages(logger_out);
            scheduler->priv->out = logger_out;
        }

        /* Likewise here - pcmk__schedule_actions only returns an error if
         * cluster_status did, and there's nothing that could have changed since
         * the first call to cause new errors here.  So we don't need to check
         * this return value either.
         */
        pcmk__schedule_actions(input, scheduler_flags, scheduler);

        if (logger_out == NULL) {
            out->end_list(out);
        } else {
            logger_out->finish(logger_out, CRM_EX_OK, true, NULL);
            pcmk__output_free(logger_out);
            scheduler->priv->out = out;
        }

        input = NULL;           /* Don't try and free it twice */

        if (graph_file != NULL) {
            rc = pcmk__xml_write_file(scheduler->priv->graph, graph_file,
                                      false);
            if (rc != pcmk_rc_ok) {
                rc = pcmk_rc_graph_error;
                goto simulate_done;
            }
        }

        if (dot_file != NULL) {
            rc = write_sim_dotfile(scheduler, dot_file,
                                   pcmk_is_set(flags, pcmk_sim_all_actions),
                                   pcmk_is_set(flags, pcmk_sim_verbose));
            if (rc != pcmk_rc_ok) {
                rc = pcmk_rc_dot_error;
                goto simulate_done;
            }
        }

        if (!out->is_quiet(out)) {
            print_transition_summary(scheduler, printed == pcmk_rc_ok);
        }
    }

    rc = pcmk_rc_ok;

    if (!pcmk_is_set(flags, pcmk_sim_simulate)) {
        goto simulate_done;
    }

    PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
    if (pcmk__simulate_transition(scheduler, cib, injections->op_fail)
            != pcmk__graph_complete) {
        rc = pcmk_rc_invalid_transition;
    }

    if (out->is_quiet(out)) {
        goto simulate_done;
    }

    set_effective_date(scheduler, true, use_date);

    if (pcmk_is_set(flags, pcmk_sim_show_scores)) {
        pcmk__set_scheduler_flags(scheduler, pcmk__sched_output_scores);
    }
    if (pcmk_is_set(flags, pcmk_sim_show_utilization)) {
        pcmk__set_scheduler_flags(scheduler, pcmk__sched_show_utilization);
    }

    rc = pcmk_unpack_scheduler_input(scheduler);
    if (rc == pcmk_rc_ok) {
        print_cluster_status(scheduler, 0, section_opts, "Revised Cluster Status",
                             true);
    }

simulate_done:
    cib__clean_up_connection(&cib);
    return rc;
}

int
pcmk_simulate(xmlNodePtr *xml, pcmk_scheduler_t *scheduler,
              const pcmk_injections_t *injections, unsigned int flags,
              unsigned int section_opts, const char *use_date,
              const char *input_file, const char *graph_file,
              const char *dot_file)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    pe__register_messages(out);
    pcmk__register_lib_messages(out);

    rc = pcmk__simulate(scheduler, out, injections, flags, section_opts,
                        use_date, input_file, graph_file, dot_file);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    return rc;
}
