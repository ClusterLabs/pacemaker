/*
 * Copyright 2021-2022 the Pacemaker project contributors
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
#include <crm/pengine/pe_types.h>
#include <pacemaker-internal.h>
#include <pacemaker.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libpacemaker_private.h"

#define STATUS_PATH_MAX 512

static pcmk__output_t *out = NULL;
static cib_t *fake_cib = NULL;
static GList *fake_resource_list = NULL;
static GList *fake_op_fail_list = NULL;

static void set_effective_date(pe_working_set_t *data_set, bool print_original,
                               char *use_date);

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
create_action_name(pe_action_t *action, bool verbose)
{
    char *action_name = NULL;
    const char *prefix = "";
    const char *action_host = NULL;
    const char *clone_name = NULL;
    const char *task = action->task;

    if (action->node != NULL) {
        action_host = action->node->details->uname;
    } else if (!pcmk_is_set(action->flags, pe_action_pseudo)) {
        action_host = "<none>";
    }

    if (pcmk__str_eq(action->task, RSC_CANCEL, pcmk__str_none)) {
        prefix = "Cancel ";
        task = action->cancel_task;
    }

    if (action->rsc != NULL) {
        clone_name = action->rsc->clone_name;
    }

    if (clone_name != NULL) {
        char *key = NULL;
        guint interval_ms = 0;

        if (pcmk__guint_from_hash(action->meta,
                                  XML_LRM_ATTR_INTERVAL_MS, 0,
                                  &interval_ms) != pcmk_rc_ok) {
            interval_ms = 0;
        }

        if (pcmk__strcase_any_of(action->task, RSC_NOTIFY, RSC_NOTIFIED,
                                 NULL)) {
            const char *n_type = g_hash_table_lookup(action->meta,
                                                     "notify_key_type");
            const char *n_task = g_hash_table_lookup(action->meta,
                                                     "notify_key_operation");

            CRM_ASSERT(n_type != NULL);
            CRM_ASSERT(n_task != NULL);
            key = pcmk__notify_key(clone_name, n_type, n_task);
        } else {
            key = pcmk__op_key(clone_name, task, interval_ms);
        }

        if (action_host != NULL) {
            action_name = crm_strdup_printf("%s%s %s",
                                            prefix, key, action_host);
        } else {
            action_name = crm_strdup_printf("%s%s", prefix, key);
        }
        free(key);

    } else if (pcmk__str_eq(action->task, CRM_OP_FENCE, pcmk__str_casei)) {
        const char *op = g_hash_table_lookup(action->meta, "stonith_action");

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
 * \param[in] data_set      Cluster working set
 * \param[in] show_opts     How to modify display (as pcmk_show_opt_e flags)
 * \param[in] section_opts  Sections to display (as pcmk_section_e flags)
 * \param[in] title         What to use as list title
 * \param[in] print_spacer  Whether to display a spacer first
 */
static void
print_cluster_status(pe_working_set_t *data_set, unsigned int show_opts,
                     unsigned int section_opts, const char *title,
                     bool print_spacer)
{
    pcmk__output_t *out = data_set->priv;
    GList *all = NULL;

    section_opts |= pcmk_section_nodes | pcmk_section_resources;

    all = g_list_prepend(all, (gpointer) "*");

    PCMK__OUTPUT_SPACER_IF(out, print_spacer);
    out->begin_list(out, NULL, NULL, "%s", title);
    out->message(out, "cluster-status", data_set, 0, NULL, FALSE,
                 section_opts,
                 show_opts | pcmk_show_inactive_rscs | pcmk_show_failed_detail,
                 NULL, all, all);
    out->end_list(out);

    g_list_free(all);
}

/*!
 * \internal
 * \brief Display a summary of all actions scheduled in a transition
 *
 * \param[in] data_set      Cluster working set (fully scheduled)
 * \param[in] print_spacer  Whether to display a spacer first
 */
static void
print_transition_summary(pe_working_set_t *data_set, bool print_spacer)
{
    pcmk__output_t *out = data_set->priv;

    PCMK__OUTPUT_SPACER_IF(out, print_spacer);
    out->begin_list(out, NULL, NULL, "Transition Summary");
    pcmk__output_actions(data_set);
    out->end_list(out);
}

/*!
 * \internal
 * \brief Reset a cluster working set's input, output, date, and flags
 *
 * \param[in] data_set  Cluster working set
 * \param[in] input     What to set as cluster input
 * \param[in] out       What to set as cluster output object
 * \param[in] use_date  What to set as cluster's current timestamp
 * \param[in] flags     Cluster flags to add (pe_flag_*)
 */
static void
reset(pe_working_set_t *data_set, xmlNodePtr input, pcmk__output_t *out,
      char *use_date, unsigned int flags)
{
    data_set->input = input;
    data_set->priv = out;
    set_effective_date(data_set, true, use_date);
    if (pcmk_is_set(flags, pcmk_sim_sanitized)) {
        pe__set_working_set_flags(data_set, pe_flag_sanitized);
    }
    if (pcmk_is_set(flags, pcmk_sim_show_scores)) {
        pe__set_working_set_flags(data_set, pe_flag_show_scores);
    }
    if (pcmk_is_set(flags, pcmk_sim_show_utilization)) {
        pe__set_working_set_flags(data_set, pe_flag_show_utilization);
    }
}

/*!
 * \brief Write out a file in dot(1) format describing the actions that will
 *        be taken by the scheduler in response to an input CIB file.
 *
 * \param[in] data_set     Working set for the cluster
 * \param[in] dot_file     The filename to write
 * \param[in] all_actions  Write all actions, even those that are optional or
 *                         are on unmanaged resources
 * \param[in] verbose      Add extra information, such as action IDs, to the
 *                         output
 *
 * \return Standard Pacemaker return code
 */
static int
write_sim_dotfile(pe_working_set_t *data_set, const char *dot_file,
                  bool all_actions, bool verbose)
{
    GList *gIter = NULL;
    FILE *dot_strm = fopen(dot_file, "w");

    if (dot_strm == NULL) {
        return errno;
    }

    fprintf(dot_strm, " digraph \"g\" {\n");
    for (gIter = data_set->actions; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;
        const char *style = "dashed";
        const char *font = "black";
        const char *color = "black";
        char *action_name = create_action_name(action, verbose);

        if (pcmk_is_set(action->flags, pe_action_pseudo)) {
            font = "orange";
        }

        if (pcmk_is_set(action->flags, pe_action_dumped)) {
            style = "bold";
            color = "green";

        } else if ((action->rsc != NULL)
                   && !pcmk_is_set(action->rsc->flags, pe_rsc_managed)) {
            color = "red";
            font = "purple";
            if (!all_actions) {
                goto do_not_write;
            }

        } else if (pcmk_is_set(action->flags, pe_action_optional)) {
            color = "blue";
            if (!all_actions) {
                goto do_not_write;
            }

        } else {
            color = "red";
            CRM_LOG_ASSERT(!pcmk_is_set(action->flags, pe_action_runnable));
        }

        pe__set_action_flags(action, pe_action_dumped);
        fprintf(dot_strm, "\"%s\" [ style=%s color=\"%s\" fontcolor=\"%s\"]\n",
                action_name, style, color, font);
  do_not_write:
        free(action_name);
    }

    for (gIter = data_set->actions; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        GList *gIter2 = NULL;

        for (gIter2 = action->actions_before; gIter2 != NULL; gIter2 = gIter2->next) {
            pe_action_wrapper_t *before = (pe_action_wrapper_t *) gIter2->data;

            char *before_name = NULL;
            char *after_name = NULL;
            const char *style = "dashed";
            bool optional = true;

            if (before->state == pe_link_dumped) {
                optional = false;
                style = "bold";
            } else if (before->type == pe_order_none) {
                continue;
            } else if (pcmk_is_set(before->action->flags, pe_action_dumped)
                       && pcmk_is_set(action->flags, pe_action_dumped)
                       && before->type != pe_order_load) {
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
 * \note \p data_set->priv must have been set to a valid \p pcmk__output_t
 *       object before this function is called.
 *
 * \param[in] xml_file  The CIB file to profile
 * \param[in] repeat    Number of times to run
 * \param[in] data_set  Working set for the cluster
 * \param[in] use_date  The date to set the cluster's time to (may be NULL)
 */
static void
profile_file(const char *xml_file, long long repeat, pe_working_set_t *data_set,
             char *use_date)
{
    pcmk__output_t *out = data_set->priv;
    xmlNode *cib_object = NULL;
    clock_t start = 0;
    clock_t end;

    CRM_ASSERT(out != NULL);

    cib_object = filename2xml(xml_file);
    start = clock();

    if (pcmk_find_cib_element(cib_object, XML_CIB_TAG_STATUS) == NULL) {
        create_xml_node(cib_object, XML_CIB_TAG_STATUS);
    }

    if (cli_config_update(&cib_object, NULL, FALSE) == FALSE) {
        free_xml(cib_object);
        return;
    }

    if (validate_xml(cib_object, NULL, FALSE) != TRUE) {
        free_xml(cib_object);
        return;
    }

    for (int i = 0; i < repeat; ++i) {
        xmlNode *input = (repeat == 1)? cib_object : copy_xml(cib_object);

        data_set->input = input;
        set_effective_date(data_set, false, use_date);
        pcmk__schedule_actions(data_set, input, NULL);
        pe_reset_working_set(data_set);
    }

    end = clock();
    out->message(out, "profile", xml_file, start, end);
}

void
pcmk__profile_dir(const char *dir, long long repeat, pe_working_set_t *data_set, char *use_date)
{
    pcmk__output_t *out = data_set->priv;
    struct dirent **namelist;

    int file_num = scandir(dir, &namelist, 0, alphasort);

    CRM_ASSERT(out != NULL);

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
            snprintf(buffer, sizeof(buffer), "%s/%s", dir, namelist[file_num]->d_name);
            if (stat(buffer, &prop) == 0 && S_ISREG(prop.st_mode)) {
                profile_file(buffer, repeat, data_set, use_date);
            }
            free(namelist[file_num]);
        }
        free(namelist);

        out->end_list(out);
    }
}

/*!
 * \brief Set the date of the cluster, either to the value given by
 *        \p use_date, or to the "execution-date" value in the CIB.
 *
 * \note \p data_set->priv must have been set to a valid \p pcmk__output_t
 *       object before this function is called.
 *
 * \param[in,out] data_set        Working set for the cluster
 * \param[in]     print_original  If \p true, the "execution-date" should
 *                                also be printed
 * \param[in]     use_date        The date to set the cluster's time to
 *                                (may be NULL)
 */
static void
set_effective_date(pe_working_set_t *data_set, bool print_original,
                   char *use_date)
{
    pcmk__output_t *out = data_set->priv;
    time_t original_date = 0;

    CRM_ASSERT(out != NULL);

    crm_element_value_epoch(data_set->input, "execution-date", &original_date);

    if (use_date) {
        data_set->now = crm_time_new(use_date);
        out->info(out, "Setting effective cluster time: %s", use_date);
        crm_time_log(LOG_NOTICE, "Pretending 'now' is", data_set->now,
                     crm_time_log_date | crm_time_log_timeofday);

    } else if (original_date) {

        data_set->now = crm_time_new(NULL);
        crm_time_set_timet(data_set->now, &original_date);

        if (print_original) {
            char *when = crm_time_as_string(data_set->now,
                            crm_time_log_date|crm_time_log_timeofday);

            out->info(out, "Using the original execution date of: %s", when);
            free(when);
        }
    }
}

/*!
 * \internal
 * \brief Simulate successfully executing a pseudo-action in a graph
 *
 * \param[in] graph   Graph to update with pseudo-action result
 * \param[in] action  Pseudo-action to simulate executing
 *
 * \return TRUE
 */
static gboolean
simulate_pseudo_action(crm_graph_t *graph, crm_action_t *action)
{
    const char *node = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
    const char *task = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);

    crm__set_graph_action_flags(action, pcmk__graph_action_confirmed);
    out->message(out, "inject-pseudo-action", node, task);

    pcmk__update_graph(graph, action);
    return TRUE;
}

/*!
 * \internal
 * \brief Simulate executing a resource action in a graph
 *
 * \param[in] graph   Graph to update with resource action result
 * \param[in] action  Resource action to simulate executing
 *
 * \return TRUE if action is validly specified, otherwise FALSE
 */
static gboolean
simulate_resource_action(crm_graph_t *graph, crm_action_t *action)
{
    int rc;
    lrmd_event_data_t *op = NULL;
    int target_outcome = PCMK_OCF_OK;

    const char *rtype = NULL;
    const char *rclass = NULL;
    const char *resource = NULL;
    const char *rprovider = NULL;
    const char *resource_config_name = NULL;
    const char *operation = crm_element_value(action->xml, "operation");
    const char *target_rc_s = crm_meta_value(action->params,
                                             XML_ATTR_TE_TARGET_RC);

    xmlNode *cib_node = NULL;
    xmlNode *cib_resource = NULL;
    xmlNode *action_rsc = first_named_child(action->xml, XML_CIB_TAG_RESOURCE);

    char *node = crm_element_value_copy(action->xml, XML_LRM_ATTR_TARGET);
    char *uuid = NULL;
    const char *router_node = crm_element_value(action->xml,
                                                XML_LRM_ATTR_ROUTER_NODE);

    // Certain actions don't need to be displayed or history entries
    if (pcmk__str_eq(operation, CRM_OP_REPROBE, pcmk__str_none)) {
        crm_debug("No history injection for %s op on %s", operation, node);
        goto done; // Confirm action and update graph
    }

    if (action_rsc == NULL) { // Shouldn't be possible
        crm_log_xml_err(action->xml, "Bad");
        free(node);
        return FALSE;
    }

    /* A resource might be known by different names in the configuration and in
     * the action (for example, a clone instance). Grab the configuration name
     * (which is preferred when writing history), and if necessary, the instance
     * name.
     */
    resource_config_name = crm_element_value(action_rsc, XML_ATTR_ID);
    if (resource_config_name == NULL) { // Shouldn't be possible
        crm_log_xml_err(action->xml, "No ID");
        free(node);
        return FALSE;
    }
    resource = resource_config_name;
    if (pe_find_resource(fake_resource_list, resource) == NULL) {
        const char *longname = crm_element_value(action_rsc, XML_ATTR_ID_LONG);

        if ((longname != NULL)
            && (pe_find_resource(fake_resource_list, longname) != NULL)) {
            resource = longname;
        }
    }

    // Certain actions need to be displayed but don't need history entries
    if (pcmk__strcase_any_of(operation, "delete", RSC_METADATA, NULL)) {
        out->message(out, "inject-rsc-action", resource, operation, node,
                     (guint) 0);
        goto done; // Confirm action and update graph
    }

    rclass = crm_element_value(action_rsc, XML_AGENT_ATTR_CLASS);
    rtype = crm_element_value(action_rsc, XML_ATTR_TYPE);
    rprovider = crm_element_value(action_rsc, XML_AGENT_ATTR_PROVIDER);

    pcmk__scan_min_int(target_rc_s, &target_outcome, 0);

    CRM_ASSERT(fake_cib->cmds->query(fake_cib, NULL, NULL,
                                     cib_sync_call|cib_scope_local) == pcmk_ok);

    // Ensure the action node is in the CIB
    uuid = crm_element_value_copy(action->xml, XML_LRM_ATTR_TARGET_UUID);
    cib_node = pcmk__inject_node(fake_cib, node,
                                 ((router_node == NULL)? uuid: node));
    free(uuid);
    CRM_ASSERT(cib_node != NULL);

    // Add a history entry for the action
    cib_resource = pcmk__inject_resource_history(out, cib_node, resource,
                                                 resource_config_name,
                                                 rclass, rtype, rprovider);
    if (cib_resource == NULL) {
        crm_err("Could not simulate action %d history for resource %s",
                action->id, resource);
        free(node);
        free_xml(cib_node);
        return FALSE;
    }

    // Simulate and display an executor event for the action result
    op = pcmk__event_from_graph_action(cib_resource, action, PCMK_EXEC_DONE,
                                       target_outcome, "User-injected result");
    out->message(out, "inject-rsc-action", resource, op->op_type, node,
                 op->interval_ms);

    // Check whether action is in a list of desired simulated failures
    for (GList *iter = fake_op_fail_list; iter != NULL; iter = iter->next) {
        char *spec = (char *) iter->data;
        char *key = NULL;
        const char *match_name = NULL;

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
        crm__set_graph_action_flags(action, pcmk__graph_action_failed);
        graph->abort_priority = INFINITY;
        pcmk__inject_failcount(out, cib_node, match_name, op->op_type,
                               op->interval_ms, op->rc);
        break;
    }

    pcmk__inject_action_result(cib_resource, op, target_outcome);
    lrmd_free_event(op);
    rc = fake_cib->cmds->modify(fake_cib, XML_CIB_TAG_STATUS, cib_node,
                                cib_sync_call|cib_scope_local);
    CRM_ASSERT(rc == pcmk_ok);

  done:
    free(node);
    free_xml(cib_node);
    crm__set_graph_action_flags(action, pcmk__graph_action_confirmed);
    pcmk__update_graph(graph, action);
    return TRUE;
}

/*!
 * \internal
 * \brief Simulate successfully executing a cluster action
 *
 * \param[in] graph   Graph to update with action result
 * \param[in] action  Cluster action to simulate
 *
 * \return TRUE
 */
static gboolean
simulate_cluster_action(crm_graph_t *graph, crm_action_t *action)
{
    const char *node = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
    const char *task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
    xmlNode *rsc = first_named_child(action->xml, XML_CIB_TAG_RESOURCE);

    crm__set_graph_action_flags(action, pcmk__graph_action_confirmed);
    out->message(out, "inject-cluster-action", node, task, rsc);
    pcmk__update_graph(graph, action);
    return TRUE;
}

/*!
 * \internal
 * \brief Simulate successfully executing a fencing action
 *
 * \param[in] graph   Graph to update with action result
 * \param[in] action  Fencing action to simulate
 *
 * \return TRUE
 */
static gboolean
simulate_fencing_action(crm_graph_t *graph, crm_action_t *action)
{
    const char *op = crm_meta_value(action->params, "stonith_action");
    char *target = crm_element_value_copy(action->xml, XML_LRM_ATTR_TARGET);

    out->message(out, "inject-fencing-action", target, op);

    if (!pcmk__str_eq(op, "on", pcmk__str_casei)) {
        int rc = pcmk_ok;
        char xpath[STATUS_PATH_MAX];

        // Set node state to offline
        xmlNode *cib_node = pcmk__inject_node_state_change(fake_cib, target,
                                                           false);

        CRM_ASSERT(cib_node != NULL);
        crm_xml_add(cib_node, XML_ATTR_ORIGIN, __func__);
        rc = fake_cib->cmds->replace(fake_cib, XML_CIB_TAG_STATUS, cib_node,
                                     cib_sync_call|cib_scope_local);
        CRM_ASSERT(rc == pcmk_ok);

        // Simulate controller clearing node's resource history and attributes
        snprintf(xpath, STATUS_PATH_MAX, "//node_state[@uname='%s']/%s",
                 target, XML_CIB_TAG_LRM);
        fake_cib->cmds->remove(fake_cib, xpath, NULL,
                               cib_xpath|cib_sync_call|cib_scope_local);

        snprintf(xpath, STATUS_PATH_MAX, "//node_state[@uname='%s']/%s",
                 target, XML_TAG_TRANSIENT_NODEATTRS);
        fake_cib->cmds->remove(fake_cib, xpath, NULL,
                               cib_xpath|cib_sync_call|cib_scope_local);

        free_xml(cib_node);
    }

    crm__set_graph_action_flags(action, pcmk__graph_action_confirmed);
    pcmk__update_graph(graph, action);
    free(target);
    return TRUE;
}

enum transition_status
pcmk__simulate_transition(pe_working_set_t *data_set, cib_t *cib,
                          GList *op_fail_list)
{
    crm_graph_t *transition = NULL;
    enum transition_status graph_rc;

    crm_graph_functions_t simulation_fns = {
        simulate_pseudo_action,
        simulate_resource_action,
        simulate_cluster_action,
        simulate_fencing_action,
    };

    out = data_set->priv;

    fake_cib = cib;
    fake_op_fail_list = op_fail_list;

    if (!out->is_quiet(out)) {
        out->begin_list(out, NULL, NULL, "Executing Cluster Transition");
    }

    pcmk__set_graph_functions(&simulation_fns);
    transition = pcmk__unpack_graph(data_set->graph, crm_system_name);
    pcmk__log_graph(LOG_DEBUG, transition);

    fake_resource_list = data_set->resources;
    do {
        graph_rc = pcmk__execute_graph(transition);
    } while (graph_rc == transition_active);
    fake_resource_list = NULL;

    if (graph_rc != transition_complete) {
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
                                       cib_sync_call|cib_scope_local);

        CRM_ASSERT(rc == pcmk_ok);
        pe_reset_working_set(data_set);
        data_set->input = cib_object;
        out->end_list(out);
    }
    return graph_rc;
}

int
pcmk__simulate(pe_working_set_t *data_set, pcmk__output_t *out,
               pcmk_injections_t *injections, unsigned int flags,
               unsigned int section_opts, char *use_date, char *input_file,
               char *graph_file, char *dot_file)
{
    int printed = pcmk_rc_no_output;
    int rc = pcmk_rc_ok;
    xmlNodePtr input = NULL;
    cib_t *cib = NULL;

    rc = cib__signon_query(&cib, &input);
    if (rc != pcmk_rc_ok) {
        goto simulate_done;
    }

    reset(data_set, input, out, use_date, flags);
    cluster_status(data_set);

    if (!out->is_quiet(out)) {
        if (pcmk_is_set(data_set->flags, pe_flag_maintenance_mode)) {
            printed = out->message(out, "maint-mode", data_set->flags);
        }

        if (data_set->disabled_resources || data_set->blocked_resources) {
            PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
            printed = out->info(out,
                                "%d of %d resource instances DISABLED and "
                                "%d BLOCKED from further action due to failure",
                                data_set->disabled_resources,
                                data_set->ninstances,
                                data_set->blocked_resources);
        }

        /* Most formatted output headers use caps for each word, but this one
         * only has the first word capitalized for compatibility with pcs.
         */
        print_cluster_status(data_set,
                             pcmk_is_set(flags, pcmk_sim_show_pending)? pcmk_show_pending : 0,
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
        pcmk__inject_scheduler_input(data_set, cib, injections);
        printed = pcmk_rc_ok;

        rc = cib->cmds->query(cib, NULL, &input, cib_sync_call);
        if (rc != pcmk_rc_ok) {
            rc = pcmk_legacy2rc(rc);
            goto simulate_done;
        }

        cleanup_calculations(data_set);
        reset(data_set, input, out, use_date, flags);
        cluster_status(data_set);
    }

    if (input_file != NULL) {
        rc = write_xml_file(input, input_file, FALSE);
        if (rc < 0) {
            rc = pcmk_legacy2rc(rc);
            goto simulate_done;
        }
    }

    if (pcmk_any_flags_set(flags, pcmk_sim_process | pcmk_sim_simulate)) {
        crm_time_t *local_date = NULL;
        pcmk__output_t *logger_out = NULL;

        if (pcmk_all_flags_set(data_set->flags,
                               pe_flag_show_scores|pe_flag_show_utilization)) {
            PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
            out->begin_list(out, NULL, NULL,
                            "Allocation Scores and Utilization Information");
            printed = pcmk_rc_ok;

        } else if (pcmk_is_set(data_set->flags, pe_flag_show_scores)) {
            PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
            out->begin_list(out, NULL, NULL, "Allocation Scores");
            printed = pcmk_rc_ok;

        } else if (pcmk_is_set(data_set->flags, pe_flag_show_utilization)) {
            PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
            out->begin_list(out, NULL, NULL, "Utilization Information");
            printed = pcmk_rc_ok;

        } else {
            logger_out = pcmk__new_logger();
            if (logger_out == NULL) {
                rc = pcmk_rc_error;
                goto simulate_done;
            }
            data_set->priv = logger_out;
        }

        pcmk__schedule_actions(data_set, input, local_date);

        if (logger_out == NULL) {
            out->end_list(out);
        } else {
            logger_out->finish(logger_out, CRM_EX_OK, true, NULL);
            pcmk__output_free(logger_out);
            data_set->priv = out;
        }

        input = NULL;           /* Don't try and free it twice */

        if (graph_file != NULL) {
            rc = write_xml_file(data_set->graph, graph_file, FALSE);
            if (rc < 0) {
                rc = pcmk_rc_graph_error;
                goto simulate_done;
            }
        }

        if (dot_file != NULL) {
            rc = write_sim_dotfile(data_set, dot_file,
                                   pcmk_is_set(flags, pcmk_sim_all_actions),
                                   pcmk_is_set(flags, pcmk_sim_verbose));
            if (rc != pcmk_rc_ok) {
                rc = pcmk_rc_dot_error;
                goto simulate_done;
            }
        }

        if (!out->is_quiet(out)) {
            print_transition_summary(data_set, printed == pcmk_rc_ok);
        }
    }

    rc = pcmk_rc_ok;

    if (!pcmk_is_set(flags, pcmk_sim_simulate)) {
        goto simulate_done;
    }

    PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
    if (pcmk__simulate_transition(data_set, cib,
                                  injections->op_fail) != transition_complete) {
        rc = pcmk_rc_invalid_transition;
    }

    if (out->is_quiet(out)) {
        goto simulate_done;
    }

    set_effective_date(data_set, true, use_date);

    if (pcmk_is_set(flags, pcmk_sim_show_scores)) {
        pe__set_working_set_flags(data_set, pe_flag_show_scores);
    }
    if (pcmk_is_set(flags, pcmk_sim_show_utilization)) {
        pe__set_working_set_flags(data_set, pe_flag_show_utilization);
    }

    cluster_status(data_set);
    print_cluster_status(data_set, 0, section_opts, "Revised Cluster Status",
                         true);

simulate_done:
    cib__clean_up_connection(&cib);
    return rc;
}

int
pcmk_simulate(xmlNodePtr *xml, pe_working_set_t *data_set,
              pcmk_injections_t *injections, unsigned int flags,
              unsigned int section_opts, char *use_date, char *input_file,
              char *graph_file, char *dot_file)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__out_prologue(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    pe__register_messages(out);
    pcmk__register_lib_messages(out);

    rc = pcmk__simulate(data_set, out, injections, flags, section_opts,
                        use_date, input_file, graph_file, dot_file);
    pcmk__out_epilogue(out, xml, rc);
    return rc;
}
