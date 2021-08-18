/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/pengine/pe_types.h>
#include <pacemaker-internal.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

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
            } else if (pcmk_is_set(action->flags, pe_action_pseudo)
                       && (before->type & pe_order_stonith_stop)) {
                continue;
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

    if (get_object_root(XML_CIB_TAG_STATUS, cib_object) == NULL) {
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
