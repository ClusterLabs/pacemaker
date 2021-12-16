/*
 * Copyright 2021 the Pacemaker project contributors
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

static char *
create_action_name(pe_action_t *action, bool verbose)
{
    char *action_name = NULL;
    const char *prefix = "";
    const char *action_host = NULL;
    const char *clone_name = NULL;
    const char *task = action->task;

    if (action->node) {
        action_host = action->node->details->uname;
    } else if (!pcmk_is_set(action->flags, pe_action_pseudo)) {
        action_host = "<none>";
    }

    if (pcmk__str_eq(action->task, RSC_CANCEL, pcmk__str_casei)) {
        prefix = "Cancel ";
        task = action->cancel_task;
    }

    if (action->rsc && action->rsc->clone_name) {
        clone_name = action->rsc->clone_name;
    }

    if (clone_name) {
        char *key = NULL;
        guint interval_ms = 0;

        if (pcmk__guint_from_hash(action->meta,
                                  XML_LRM_ATTR_INTERVAL_MS, 0,
                                  &interval_ms) != pcmk_rc_ok) {
            interval_ms = 0;
        }

        if (pcmk__strcase_any_of(action->task, RSC_NOTIFY, RSC_NOTIFIED, NULL)) {
            const char *n_type = g_hash_table_lookup(action->meta, "notify_key_type");
            const char *n_task = g_hash_table_lookup(action->meta, "notify_key_operation");

            CRM_ASSERT(n_type != NULL);
            CRM_ASSERT(n_task != NULL);
            key = pcmk__notify_key(clone_name, n_type, n_task);

        } else {
            key = pcmk__op_key(clone_name, task, interval_ms);
        }

        if (action_host) {
            action_name = crm_strdup_printf("%s%s %s", prefix, key, action_host);
        } else {
            action_name = crm_strdup_printf("%s%s", prefix, key);
        }
        free(key);

    } else if (pcmk__str_eq(action->task, CRM_OP_FENCE, pcmk__str_casei)) {
        const char *op = g_hash_table_lookup(action->meta, "stonith_action");

        action_name = crm_strdup_printf("%s%s '%s' %s", prefix, action->task, op, action_host);

    } else if (action->rsc && action_host) {
        action_name = crm_strdup_printf("%s%s %s", prefix, action->uuid, action_host);

    } else if (action_host) {
        action_name = crm_strdup_printf("%s%s %s", prefix, action->task, action_host);

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

static void
print_cluster_status(pe_working_set_t * data_set, unsigned int show_opts,
                     unsigned int section_opts, const char *title, bool print_spacer)
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

static void
print_transition_summary(pe_working_set_t *data_set, bool print_spacer)
{
    pcmk__output_t *out = data_set->priv;

    PCMK__OUTPUT_SPACER_IF(out, print_spacer);
    out->begin_list(out, NULL, NULL, "Transition Summary");
    pcmk__output_actions(data_set);
    out->end_list(out);
}

static void
reset(pe_working_set_t *data_set, xmlNodePtr input, pcmk__output_t *out,
      char *use_date, unsigned int flags)
{
    data_set->input = input;
    data_set->priv = out;
    pcmk__set_effective_date(data_set, true, use_date);
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

int
pcmk__write_sim_dotfile(pe_working_set_t *data_set, const char *dot_file,
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
            CRM_CHECK(!pcmk_is_set(action->flags, pe_action_runnable), ;);
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

void
pcmk__profile_file(const char *xml_file, long long repeat, pe_working_set_t *data_set, char *use_date)
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
        pcmk__set_effective_date(data_set, false, use_date);
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
                pcmk__profile_file(buffer, repeat, data_set, use_date);
            }
            free(namelist[file_num]);
        }
        free(namelist);

        out->end_list(out);
    }
}

void
pcmk__set_effective_date(pe_working_set_t *data_set, bool print_original, char *use_date)
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

int
pcmk__simulate(pe_working_set_t *data_set, pcmk__output_t *out, pcmk_injections_t *injections,
               unsigned int flags, unsigned int section_opts, char *use_date,
               char *input_file, char *graph_file, char *dot_file)
{
    int printed = pcmk_rc_no_output;
    int rc = pcmk_rc_ok;
    xmlNodePtr input = NULL;
    cib_t *cib = NULL;
    bool modified = false;

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
            printed = out->info(out, "%d of %d resource instances DISABLED and %d BLOCKED "
                                "from further action due to failure",
                                data_set->disabled_resources, data_set->ninstances,
                                data_set->blocked_resources);
        }

        /* Most formatted output headers use caps for each word, but this one
         * only has the first word capitalized for compatibility with pcs.
         */
        print_cluster_status(data_set, pcmk_is_set(flags, pcmk_sim_show_pending) ? pcmk_show_pending : 0,
                             section_opts, "Current cluster status", printed == pcmk_rc_ok);
        printed = pcmk_rc_ok;
    }

    modified = injections->node_down != NULL || injections->node_fail != NULL ||
               injections->node_up != NULL || injections->op_inject != NULL ||
               injections->ticket_activate != NULL || injections->ticket_grant != NULL ||
               injections->ticket_revoke != NULL || injections->ticket_standby != NULL ||
               injections->watchdog != NULL || injections->watchdog != NULL;

    if (modified) {
        PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
        modify_configuration(data_set, cib, injections);
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

        if (pcmk_all_flags_set(data_set->flags, pe_flag_show_scores|pe_flag_show_utilization)) {
            PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
            out->begin_list(out, NULL, NULL, "Allocation Scores and Utilization Information");
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
            rc = pcmk__write_sim_dotfile(data_set, dot_file,
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

    if (pcmk_is_set(flags, pcmk_sim_simulate)) {
        PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
        if (run_simulation(data_set, cib, injections->op_fail) != transition_complete) {
            rc = pcmk_rc_invalid_transition;
        }

        if (!out->is_quiet(out)) {
            pcmk__set_effective_date(data_set, true, use_date);

            if (pcmk_is_set(flags, pcmk_sim_show_scores)) {
                pe__set_working_set_flags(data_set, pe_flag_show_scores);
            }
            if (pcmk_is_set(flags, pcmk_sim_show_utilization)) {
                pe__set_working_set_flags(data_set, pe_flag_show_utilization);
            }

            cluster_status(data_set);
            print_cluster_status(data_set, 0, section_opts, "Revised Cluster Status", true);
        }
    }

simulate_done:
    if (cib) {
        cib->cmds->signoff(cib);
        cib_delete(cib);
    }

    return rc;
}

int
pcmk_simulate(xmlNodePtr *xml, pe_working_set_t *data_set, pcmk_injections_t *injections,
              unsigned int flags, unsigned int section_opts, char *use_date,
              char *input_file, char *graph_file, char *dot_file)
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

void
pcmk_free_injections(pcmk_injections_t *injections)
{
    if (injections == NULL) {
        return;
    }

    g_list_free_full(injections->node_up, g_free);
    g_list_free_full(injections->node_down, g_free);
    g_list_free_full(injections->node_fail, g_free);
    g_list_free_full(injections->op_fail, g_free);
    g_list_free_full(injections->op_inject, g_free);
    g_list_free_full(injections->ticket_grant, g_free);
    g_list_free_full(injections->ticket_revoke, g_free);
    g_list_free_full(injections->ticket_standby, g_free);
    g_list_free_full(injections->ticket_activate, g_free);
    free(injections->quorum);
    free(injections->watchdog);

    free(injections);
}
