/*
 * Copyright 2019-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/iso8601_internal.h>
#include <crm/msg_xml.h>
#include <crm/pengine/internal.h>

#define SUMMARY_HEADER(rc, out) do { \
        if (rc == pcmk_rc_no_output) { \
            out->begin_list(out, NULL, NULL, "Cluster Summary"); \
            rc = pcmk_rc_ok; \
        } \
    } while (0)

static char *
failed_action_string(xmlNodePtr xml_op) {
    const char *op_key = crm_element_value(xml_op, XML_LRM_ATTR_TASK_KEY);
    int rc = crm_parse_int(crm_element_value(xml_op, XML_LRM_ATTR_RC), "0");
    int status = crm_parse_int(crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS), "0");
    const char *exit_reason = crm_element_value(xml_op, XML_LRM_ATTR_EXIT_REASON);

    time_t last_change = 0;

    if (crm_element_value_epoch(xml_op, XML_RSC_OP_LAST_CHANGE,
                                &last_change) == pcmk_ok) {
        crm_time_t *crm_when = crm_time_new(NULL);
        char *time_s = NULL;
        char *buf = NULL;

        crm_time_set_timet(crm_when, &last_change);
        time_s = crm_time_as_string(crm_when, crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);

        buf = crm_strdup_printf("%s on %s '%s' (%d): call=%s, status='%s', "
                                "exitreason='%s', " XML_RSC_OP_LAST_CHANGE
                                "='%s', queued=%sms, exec=%sms",
                                op_key ? op_key : ID(xml_op),
                                crm_element_value(xml_op, XML_ATTR_UNAME),
                                services_ocf_exitcode_str(rc), rc,
                                crm_element_value(xml_op, XML_LRM_ATTR_CALLID),
                                services_lrm_status_str(status),
                                exit_reason ? exit_reason : "none",
                                time_s,
                                crm_element_value(xml_op, XML_RSC_OP_T_QUEUE),
                                crm_element_value(xml_op, XML_RSC_OP_T_EXEC));

        crm_time_free(crm_when);
        free(time_s);
        return buf;
    } else {
        return crm_strdup_printf("%s on %s '%s' (%d): call=%s, status=%s, exitreason='%s'",
                                 op_key ? op_key : ID(xml_op),
                                 crm_element_value(xml_op, XML_ATTR_UNAME),
                                 services_ocf_exitcode_str(rc), rc,
                                 crm_element_value(xml_op, XML_LRM_ATTR_CALLID),
                                 services_lrm_status_str(status),
                                 exit_reason ? exit_reason : "none");
    }
}

static const char *
get_cluster_stack(pe_working_set_t *data_set)
{
    xmlNode *stack = get_xpath_object("//nvpair[@name='cluster-infrastructure']",
                                      data_set->input, LOG_DEBUG);
    return stack? crm_element_value(stack, XML_NVPAIR_ATTR_VALUE) : "unknown";
}

static char *
last_changed_string(const char *last_written, const char *user,
                    const char *client, const char *origin) {
    if (last_written != NULL || user != NULL || client != NULL || origin != NULL) {
        return crm_strdup_printf("%s%s%s%s%s%s%s",
                                 last_written ? last_written : "",
                                 user ? " by " : "",
                                 user ? user : "",
                                 client ? " via " : "",
                                 client ? client : "",
                                 origin ? " on " : "",
                                 origin ? origin : "");
    } else {
        return strdup("");
    }
}

static char *
op_history_string(xmlNode *xml_op, const char *task, const char *interval_ms_s,
                  int rc, gboolean print_timing) {
    const char *call = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);
    char *interval_str = NULL;
    char *buf = NULL;

    if (interval_ms_s && safe_str_neq(interval_ms_s, "0")) {
        char *pair = pcmk_format_nvpair("interval", interval_ms_s, "ms");
        interval_str = crm_strdup_printf(" %s", pair);
        free(pair);
    }

    if (print_timing) {
        char *last_change_str = NULL;
        char *last_run_str = NULL;
        char *exec_str = NULL;
        char *queue_str = NULL;

        const char *value = NULL;

        time_t epoch = 0;

        if ((crm_element_value_epoch(xml_op, XML_RSC_OP_LAST_CHANGE, &epoch) == pcmk_ok)
            && (epoch > 0)) {
            char *time = pcmk_format_named_time(XML_RSC_OP_LAST_CHANGE, epoch);
            last_change_str = crm_strdup_printf(" %s", time);
            free(time);
        }

        if ((crm_element_value_epoch(xml_op, XML_RSC_OP_LAST_RUN, &epoch) == pcmk_ok)
            && (epoch > 0)) {
            char *time = pcmk_format_named_time(XML_RSC_OP_LAST_RUN, epoch);
            last_run_str = crm_strdup_printf(" %s", time);
            free(time);
        }

        value = crm_element_value(xml_op, XML_RSC_OP_T_EXEC);
        if (value) {
            char *pair = pcmk_format_nvpair(XML_RSC_OP_T_EXEC, value, "ms");
            exec_str = crm_strdup_printf(" %s", pair);
            free(pair);
        }

        value = crm_element_value(xml_op, XML_RSC_OP_T_QUEUE);
        if (value) {
            char *pair = pcmk_format_nvpair(XML_RSC_OP_T_QUEUE, value, "ms");
            queue_str = crm_strdup_printf(" %s", pair);
            free(pair);
        }

        buf = crm_strdup_printf("(%s) %s:%s%s%s%s%s rc=%d (%s)", call, task,
                                interval_str ? interval_str : "",
                                last_change_str ? last_change_str : "",
                                last_run_str ? last_run_str : "",
                                exec_str ? exec_str : "",
                                queue_str ? queue_str : "",
                                rc, services_ocf_exitcode_str(rc));

        if (last_change_str) {
            free(last_change_str);
        }

        if (last_run_str) {
            free(last_run_str);
        }

        if (exec_str) {
            free(exec_str);
        }

        if (queue_str) {
            free(queue_str);
        }
    } else {
        buf = crm_strdup_printf("(%s) %s%s%s", call, task,
                                interval_str ? ":" : "",
                                interval_str ? interval_str : "");
    }

    if (interval_str) {
        free(interval_str);
    }

    return buf;
}

static char *
resource_history_string(pe_resource_t *rsc, const char *rsc_id, gboolean all,
                        int failcount, time_t last_failure) {
    char *buf = NULL;

    if (rsc == NULL) {
        buf = crm_strdup_printf("%s: orphan", rsc_id);
    } else if (all || failcount || last_failure > 0) {
        char *failcount_s = NULL;
        char *lastfail_s = NULL;

        if (failcount > 0) {
            failcount_s = crm_strdup_printf(" %s=%d", PCMK__FAIL_COUNT_PREFIX,
                                            failcount);
        } else {
            failcount_s = strdup("");
        }
        if (last_failure > 0) {
            lastfail_s = crm_strdup_printf(" %s='%s'",
                                           PCMK__LAST_FAILURE_PREFIX,
                                           pcmk__epoch2str(&last_failure));
        }

        buf = crm_strdup_printf("%s: migration-threshold=%d%s%s",
                                rsc_id, rsc->migration_threshold, failcount_s,
                                lastfail_s? lastfail_s : "");
        free(failcount_s);
        free(lastfail_s);
    } else {
        buf = crm_strdup_printf("%s:", rsc_id);
    }

    return buf;
}

int
pe__cluster_summary(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    gboolean print_clone_detail = va_arg(args, gboolean);
    gboolean show_stack = va_arg(args, gboolean);
    gboolean show_dc = va_arg(args, gboolean);
    gboolean show_times = va_arg(args, gboolean);
    gboolean show_counts = va_arg(args, gboolean);
    gboolean show_options = va_arg(args, gboolean);
    int rc = pcmk_rc_no_output;

    const char *stack_s = get_cluster_stack(data_set);

    if (show_stack) {
        SUMMARY_HEADER(rc, out);
        out->message(out, "cluster-stack", stack_s);
    }

    /* Always print DC if none, even if not requested */
    if (data_set->dc_node == NULL || show_dc) {
        xmlNode *dc_version = get_xpath_object("//nvpair[@name='dc-version']",
                                               data_set->input, LOG_DEBUG);
        const char *dc_version_s = dc_version?
                                   crm_element_value(dc_version, XML_NVPAIR_ATTR_VALUE)
                                   : NULL;
        const char *quorum = crm_element_value(data_set->input, XML_ATTR_HAVE_QUORUM);
        char *dc_name = data_set->dc_node ? pe__node_display_name(data_set->dc_node, print_clone_detail) : NULL;

        SUMMARY_HEADER(rc, out);
        out->message(out, "cluster-dc", data_set->dc_node, quorum, dc_version_s, dc_name);
        free(dc_name);
    }

    if (show_times) {
        const char *last_written = crm_element_value(data_set->input, XML_CIB_ATTR_WRITTEN);
        const char *user = crm_element_value(data_set->input, XML_ATTR_UPDATE_USER);
        const char *client = crm_element_value(data_set->input, XML_ATTR_UPDATE_CLIENT);
        const char *origin = crm_element_value(data_set->input, XML_ATTR_UPDATE_ORIG);

        SUMMARY_HEADER(rc, out);
        out->message(out, "cluster-times", last_written, user, client, origin);
    }

    if (show_counts) {
        SUMMARY_HEADER(rc, out);
        out->message(out, "cluster-counts", g_list_length(data_set->nodes),
                     data_set->ninstances, data_set->disabled_resources,
                     data_set->blocked_resources);
    }

    if (show_options) {
        SUMMARY_HEADER(rc, out);
        out->message(out, "cluster-options", data_set);
    }

    if (rc == pcmk_rc_ok) {
        out->end_list(out);
    }

    if (is_set(data_set->flags, pe_flag_maintenance_mode)) {
        out->message(out, "maint-mode");
        rc = pcmk_rc_ok;
    }

    return rc;
}

int
pe__cluster_summary_html(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);
    gboolean print_clone_detail = va_arg(args, gboolean);
    gboolean show_stack = va_arg(args, gboolean);
    gboolean show_dc = va_arg(args, gboolean);
    gboolean show_times = va_arg(args, gboolean);
    gboolean show_counts = va_arg(args, gboolean);
    gboolean show_options = va_arg(args, gboolean);
    int rc = pcmk_rc_no_output;

    const char *stack_s = get_cluster_stack(data_set);

    if (show_stack) {
        SUMMARY_HEADER(rc, out);
        out->message(out, "cluster-stack", stack_s);
    }

    /* Always print DC if none, even if not requested */
    if (data_set->dc_node == NULL || show_dc) {
        xmlNode *dc_version = get_xpath_object("//nvpair[@name='dc-version']",
                                               data_set->input, LOG_DEBUG);
        const char *dc_version_s = dc_version?
                                   crm_element_value(dc_version, XML_NVPAIR_ATTR_VALUE)
                                   : NULL;
        const char *quorum = crm_element_value(data_set->input, XML_ATTR_HAVE_QUORUM);
        char *dc_name = data_set->dc_node ? pe__node_display_name(data_set->dc_node, print_clone_detail) : NULL;

        SUMMARY_HEADER(rc, out);
        out->message(out, "cluster-dc", data_set->dc_node, quorum, dc_version_s, dc_name);
        free(dc_name);
    }

    if (show_times) {
        const char *last_written = crm_element_value(data_set->input, XML_CIB_ATTR_WRITTEN);
        const char *user = crm_element_value(data_set->input, XML_ATTR_UPDATE_USER);
        const char *client = crm_element_value(data_set->input, XML_ATTR_UPDATE_CLIENT);
        const char *origin = crm_element_value(data_set->input, XML_ATTR_UPDATE_ORIG);

        SUMMARY_HEADER(rc, out);
        out->message(out, "cluster-times", last_written, user, client, origin);
    }

    if (show_counts) {
        SUMMARY_HEADER(rc, out);
        out->message(out, "cluster-counts", g_list_length(data_set->nodes),
                     data_set->ninstances, data_set->disabled_resources,
                     data_set->blocked_resources);
    }

    if (show_options) {
        /* Kind of a hack - close the list we may have opened earlier in this
         * function so we can put all the options into their own list.  We
         * only want to do this on HTML output, though.
         */
        if (rc == pcmk_rc_ok) {
            out->end_list(out);
        }

        out->begin_list(out, NULL, NULL, "Config Options");
        out->message(out, "cluster-options", data_set);
    }

    if (rc == pcmk_rc_ok) {
        out->end_list(out);
    }

    if (is_set(data_set->flags, pe_flag_maintenance_mode)) {
        out->message(out, "maint-mode");
        rc = pcmk_rc_ok;
    }

    return rc;
}

char *
pe__node_display_name(pe_node_t *node, bool print_detail)
{
    char *node_name;
    const char *node_host = NULL;
    const char *node_id = NULL;
    int name_len;

    CRM_ASSERT((node != NULL) && (node->details != NULL) && (node->details->uname != NULL));

    /* Host is displayed only if this is a guest node */
    if (pe__is_guest_node(node)) {
        pe_node_t *host_node = pe__current_node(node->details->remote_rsc);

        if (host_node && host_node->details) {
            node_host = host_node->details->uname;
        }
        if (node_host == NULL) {
            node_host = ""; /* so we at least get "uname@" to indicate guest */
        }
    }

    /* Node ID is displayed if different from uname and detail is requested */
    if (print_detail && safe_str_neq(node->details->uname, node->details->id)) {
        node_id = node->details->id;
    }

    /* Determine name length */
    name_len = strlen(node->details->uname) + 1;
    if (node_host) {
        name_len += strlen(node_host) + 1; /* "@node_host" */
    }
    if (node_id) {
        name_len += strlen(node_id) + 3; /* + " (node_id)" */
    }

    /* Allocate and populate display name */
    node_name = malloc(name_len);
    CRM_ASSERT(node_name != NULL);
    strcpy(node_name, node->details->uname);
    if (node_host) {
        strcat(node_name, "@");
        strcat(node_name, node_host);
    }
    if (node_id) {
        strcat(node_name, " (");
        strcat(node_name, node_id);
        strcat(node_name, ")");
    }
    return node_name;
}

int
pe__name_and_nvpairs_xml(pcmk__output_t *out, bool is_list, const char *tag_name
                         , size_t pairs_count, ...)
{
    xmlNodePtr xml_node = NULL;
    va_list args;

    CRM_ASSERT(tag_name != NULL);

    xml_node = pcmk__output_xml_peek_parent(out);
    CRM_ASSERT(xml_node != NULL);
    xml_node = is_list
        ? create_xml_node(xml_node, tag_name)
        : xmlNewChild(xml_node, NULL, (pcmkXmlStr) tag_name, NULL);

    va_start(args, pairs_count);
    while(pairs_count--) {
        const char *param_name = va_arg(args, const char *);
        const char *param_value = va_arg(args, const char *);
        if (param_name && param_value) {
            xmlSetProp(xml_node, (pcmkXmlStr)param_name, (pcmkXmlStr)param_value);
        }
    };
    va_end(args);

    if (is_list) {
        pcmk__output_xml_push_parent(out, xml_node);
    }
    return pcmk_rc_ok;
}

int
pe__ban_html(pcmk__output_t *out, va_list args) {
    pe_node_t *pe_node = va_arg(args, pe_node_t *);
    pe__location_t *location = va_arg(args, pe__location_t *);
    gboolean print_clone_detail = va_arg(args, gboolean);

    char *node_name = pe__node_display_name(pe_node, print_clone_detail);
    char *buf = crm_strdup_printf("%s\tprevents %s from running %son %s",
                                  location->id, location->rsc_lh->id,
                                  location->role_filter == RSC_ROLE_MASTER ? "as Master " : "",
                                  node_name);

    pcmk__output_create_html_node(out, "li", NULL, NULL, buf);

    free(node_name);
    free(buf);
    return pcmk_rc_ok;
}

int
pe__ban_text(pcmk__output_t *out, va_list args) {
    pe_node_t *pe_node = va_arg(args, pe_node_t *);
    pe__location_t *location = va_arg(args, pe__location_t *);
    gboolean print_clone_detail = va_arg(args, gboolean);

    char *node_name = pe__node_display_name(pe_node, print_clone_detail);
    out->list_item(out, NULL, "%s\tprevents %s from running %son %s",
                   location->id, location->rsc_lh->id,
                   location->role_filter == RSC_ROLE_MASTER ? "as Master " : "",
                   node_name);

    free(node_name);
    return pcmk_rc_ok;
}

int
pe__ban_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "ban");
    pe_node_t *pe_node = va_arg(args, pe_node_t *);
    pe__location_t *location = va_arg(args, pe__location_t *);
    gboolean print_clone_detail G_GNUC_UNUSED = va_arg(args, gboolean);

    char *weight_s = crm_itoa(pe_node->weight);

    xmlSetProp(node, (pcmkXmlStr) "id", (pcmkXmlStr) location->id);
    xmlSetProp(node, (pcmkXmlStr) "resource", (pcmkXmlStr) location->rsc_lh->id);
    xmlSetProp(node, (pcmkXmlStr) "node", (pcmkXmlStr) pe_node->details->uname);
    xmlSetProp(node, (pcmkXmlStr) "weight", (pcmkXmlStr) weight_s);
    xmlSetProp(node, (pcmkXmlStr) "master_only",
               (pcmkXmlStr) (location->role_filter == RSC_ROLE_MASTER ? "true" : "false"));

    free(weight_s);
    return pcmk_rc_ok;
}

int
pe__cluster_counts_html(pcmk__output_t *out, va_list args) {
    xmlNodePtr nodes_node = pcmk__output_create_xml_node(out, "li");
    xmlNodePtr resources_node = pcmk__output_create_xml_node(out, "li");

    unsigned int nnodes = va_arg(args, unsigned int);
    int nresources = va_arg(args, int);
    int ndisabled = va_arg(args, int);
    int nblocked = va_arg(args, int);

    char *nnodes_str = crm_strdup_printf("%d node%s configured",
                                         nnodes, pcmk__plural_s(nnodes));

    pcmk_create_html_node(nodes_node, "span", NULL, NULL, nnodes_str);
    free(nnodes_str);

    if (ndisabled && nblocked) {
        char *s = crm_strdup_printf("%d resource instance%s configured (%d ",
                                    nresources, pcmk__plural_s(nresources),
                                    ndisabled);
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);

        pcmk_create_html_node(resources_node, "span", NULL, "bold", "DISABLED");

        s = crm_strdup_printf(", %d ", nblocked);
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);

        pcmk_create_html_node(resources_node, "span", NULL, "bold", "BLOCKED");
        pcmk_create_html_node(resources_node, "span", NULL, NULL,
                              " from further action due to failure)");
    } else if (ndisabled && !nblocked) {
        char *s = crm_strdup_printf("%d resource instance%s configured (%d ",
                                    nresources, pcmk__plural_s(nresources),
                                    ndisabled);
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);

        pcmk_create_html_node(resources_node, "span", NULL, "bold", "DISABLED");
        pcmk_create_html_node(resources_node, "span", NULL, NULL, ")");
    } else if (!ndisabled && nblocked) {
        char *s = crm_strdup_printf("%d resource instance%s configured (%d ",
                                    nresources, pcmk__plural_s(nresources),
                                    nblocked);
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);

        pcmk_create_html_node(resources_node, "span", NULL, "bold", "BLOCKED");
        pcmk_create_html_node(resources_node, "span", NULL, NULL,
                              " from further action due to failure)");
    } else {
        char *s = crm_strdup_printf("%d resource instance%s configured",
                                    nresources, pcmk__plural_s(nresources));
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);
    }

    return pcmk_rc_ok;
}

int
pe__cluster_counts_text(pcmk__output_t *out, va_list args) {
    unsigned int nnodes = va_arg(args, unsigned int);
    int nresources = va_arg(args, int);
    int ndisabled = va_arg(args, int);
    int nblocked = va_arg(args, int);

    out->list_item(out, NULL, "%d node%s configured",
                   nnodes, pcmk__plural_s(nnodes));

    if (ndisabled && nblocked) {
        out->list_item(out, NULL, "%d resource instance%s configured "
                                  "(%d DISABLED, %d BLOCKED from "
                                  "further action due to failure)",
                       nresources, pcmk__plural_s(nresources), ndisabled,
                       nblocked);
    } else if (ndisabled && !nblocked) {
        out->list_item(out, NULL, "%d resource instance%s configured "
                                  "(%d DISABLED)",
                       nresources, pcmk__plural_s(nresources), ndisabled);
    } else if (!ndisabled && nblocked) {
        out->list_item(out, NULL, "%d resource instance%s configured "
                                  "(%d BLOCKED from further action "
                                  "due to failure)",
                       nresources, pcmk__plural_s(nresources), nblocked);
    } else {
        out->list_item(out, NULL, "%d resource instance%s configured",
                       nresources, pcmk__plural_s(nresources));
    }

    return pcmk_rc_ok;
}

int
pe__cluster_counts_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr nodes_node = pcmk__output_create_xml_node(out, "nodes_configured");
    xmlNodePtr resources_node = pcmk__output_create_xml_node(out, "resources_configured");

    unsigned int nnodes = va_arg(args, unsigned int);
    int nresources = va_arg(args, int);
    int ndisabled = va_arg(args, int);
    int nblocked = va_arg(args, int);

    char *s = crm_itoa(nnodes);
    xmlSetProp(nodes_node, (pcmkXmlStr) "number", (pcmkXmlStr) s);
    free(s);

    s = crm_itoa(nresources);
    xmlSetProp(resources_node, (pcmkXmlStr) "number", (pcmkXmlStr) s);
    free(s);

    s = crm_itoa(ndisabled);
    xmlSetProp(resources_node, (pcmkXmlStr) "disabled", (pcmkXmlStr) s);
    free(s);

    s = crm_itoa(nblocked);
    xmlSetProp(resources_node, (pcmkXmlStr) "blocked", (pcmkXmlStr) s);
    free(s);

    return pcmk_rc_ok;
}

int
pe__cluster_dc_html(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "li");

    pe_node_t *dc = va_arg(args, pe_node_t *);
    const char *quorum = va_arg(args, const char *);
    const char *dc_version_s = va_arg(args, const char *);
    char *dc_name = va_arg(args, char *);

    pcmk_create_html_node(node, "span", NULL, "bold", "Current DC: ");

    if (dc) {
        if (crm_is_true(quorum)) {
            char *buf = crm_strdup_printf("%s (version %s) - partition with quorum",
                                          dc_name, dc_version_s ? dc_version_s : "unknown");
            pcmk_create_html_node(node, "span", NULL, NULL, buf);
            free(buf);
        } else {
            char *buf = crm_strdup_printf("%s (version %s) - partition",
                                          dc_name, dc_version_s ? dc_version_s : "unknown");
            pcmk_create_html_node(node, "span", NULL, NULL, buf);
            free(buf);

            pcmk_create_html_node(node, "span", NULL, "warning", "WITHOUT");
            pcmk_create_html_node(node, "span", NULL, NULL, "quorum");
        }
    } else {
        pcmk_create_html_node(node ,"span", NULL, "warning", "NONE");
    }

    return pcmk_rc_ok;
}

int
pe__cluster_dc_text(pcmk__output_t *out, va_list args) {
    pe_node_t *dc = va_arg(args, pe_node_t *);
    const char *quorum = va_arg(args, const char *);
    const char *dc_version_s = va_arg(args, const char *);
    char *dc_name = va_arg(args, char *);

    if (dc) {
        out->list_item(out, "Current DC", "%s (version %s) - partition %s quorum",
                       dc_name, dc_version_s ? dc_version_s : "unknown",
                       crm_is_true(quorum) ? "with" : "WITHOUT");
    } else {
        out->list_item(out, "Current DC", "NONE");
    }

    return pcmk_rc_ok;
}

int
pe__cluster_dc_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "current_dc");

    pe_node_t *dc = va_arg(args, pe_node_t *);
    const char *quorum = va_arg(args, const char *);
    const char *dc_version_s = va_arg(args, const char *);
    char *dc_name G_GNUC_UNUSED = va_arg(args, char *);

    if (dc) {
        xmlSetProp(node, (pcmkXmlStr) "present", (pcmkXmlStr) "true");
        xmlSetProp(node, (pcmkXmlStr) "version", (pcmkXmlStr) (dc_version_s ? dc_version_s : ""));
        xmlSetProp(node, (pcmkXmlStr) "name", (pcmkXmlStr) dc->details->uname);
        xmlSetProp(node, (pcmkXmlStr) "id", (pcmkXmlStr) dc->details->id);
        xmlSetProp(node, (pcmkXmlStr) "with_quorum", (pcmkXmlStr) (crm_is_true(quorum) ? "true" : "false"));
    } else {
        xmlSetProp(node, (pcmkXmlStr) "present", (pcmkXmlStr) "false");
    }

    return pcmk_rc_ok;
}

int
pe__cluster_maint_mode_text(pcmk__output_t *out, va_list args) {
    fprintf(out->dest, "\n              *** Resource management is DISABLED ***");
    fprintf(out->dest, "\n  The cluster will not attempt to start, stop or recover services");
    fprintf(out->dest, "\n");
    return pcmk_rc_ok;
}

int
pe__cluster_options_html(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);

    out->list_item(out, NULL, "STONITH of failed nodes %s",
                   is_set(data_set->flags, pe_flag_stonith_enabled) ? "enabled" : "disabled");

    out->list_item(out, NULL, "Cluster is %s",
                   is_set(data_set->flags, pe_flag_symmetric_cluster) ? "symmetric" : "asymmetric");

    switch (data_set->no_quorum_policy) {
        case no_quorum_freeze:
            out->list_item(out, NULL, "No quorum policy: Freeze resources");
            break;

        case no_quorum_stop:
            out->list_item(out, NULL, "No quorum policy: Stop ALL resources");
            break;

        case no_quorum_ignore:
            out->list_item(out, NULL, "No quorum policy: Ignore");
            break;

        case no_quorum_suicide:
            out->list_item(out, NULL, "No quorum policy: Suicide");
            break;
    }

    if (is_set(data_set->flags, pe_flag_maintenance_mode)) {
        xmlNodePtr node = pcmk__output_create_xml_node(out, "li");

        pcmk_create_html_node(node, "span", NULL, NULL, "Resource management: ");
        pcmk_create_html_node(node, "span", NULL, "bold", "DISABLED");
        pcmk_create_html_node(node, "span", NULL, NULL,
                              " (the cluster will not attempt to start, stop, or recover services)");
    } else {
        out->list_item(out, NULL, "Resource management: enabled");
    }

    return pcmk_rc_ok;
}

int
pe__cluster_options_log(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);

    if (is_set(data_set->flags, pe_flag_maintenance_mode)) {
        out->info(out, "Resource management is DISABLED.  The cluster will not attempt to start, stop or recover services.");
        return pcmk_rc_ok;
    } else {
        return pcmk_rc_no_output;
    }
}

int
pe__cluster_options_text(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);

    out->list_item(out, NULL, "STONITH of failed nodes %s",
                   is_set(data_set->flags, pe_flag_stonith_enabled) ? "enabled" : "disabled");

    out->list_item(out, NULL, "Cluster is %s",
                   is_set(data_set->flags, pe_flag_symmetric_cluster) ? "symmetric" : "asymmetric");

    switch (data_set->no_quorum_policy) {
        case no_quorum_freeze:
            out->list_item(out, NULL, "No quorum policy: Freeze resources");
            break;

        case no_quorum_stop:
            out->list_item(out, NULL, "No quorum policy: Stop ALL resources");
            break;

        case no_quorum_ignore:
            out->list_item(out, NULL, "No quorum policy: Ignore");
            break;

        case no_quorum_suicide:
            out->list_item(out, NULL, "No quorum policy: Suicide");
            break;
    }

    return pcmk_rc_ok;
}

int
pe__cluster_options_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "cluster_options");
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);

    xmlSetProp(node, (pcmkXmlStr) "stonith-enabled",
               (pcmkXmlStr) (is_set(data_set->flags, pe_flag_stonith_enabled) ? "true" : "false"));
    xmlSetProp(node, (pcmkXmlStr) "symmetric-cluster",
               (pcmkXmlStr) (is_set(data_set->flags, pe_flag_symmetric_cluster) ? "true" : "false"));

    switch (data_set->no_quorum_policy) {
        case no_quorum_freeze:
            xmlSetProp(node, (pcmkXmlStr) "no-quorum-policy", (pcmkXmlStr) "freeze");
            break;

        case no_quorum_stop:
            xmlSetProp(node, (pcmkXmlStr) "no-quorum-policy", (pcmkXmlStr) "stop");
            break;

        case no_quorum_ignore:
            xmlSetProp(node, (pcmkXmlStr) "no-quorum-policy", (pcmkXmlStr) "ignore");
            break;

        case no_quorum_suicide:
            xmlSetProp(node, (pcmkXmlStr) "no-quorum-policy", (pcmkXmlStr) "suicide");
            break;
    }

    xmlSetProp(node, (pcmkXmlStr) "maintenance-mode",
               (pcmkXmlStr) (is_set(data_set->flags, pe_flag_maintenance_mode) ? "true" : "false"));

    return pcmk_rc_ok;
}

int
pe__cluster_stack_html(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "li");
    const char *stack_s = va_arg(args, const char *);

    pcmk_create_html_node(node, "span", NULL, "bold", "Stack: ");
    pcmk_create_html_node(node, "span", NULL, NULL, stack_s);

    return pcmk_rc_ok;
}

int
pe__cluster_stack_text(pcmk__output_t *out, va_list args) {
    const char *stack_s = va_arg(args, const char *);
    out->list_item(out, "Stack", "%s", stack_s);
    return pcmk_rc_ok;
}

int
pe__cluster_stack_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "stack");
    const char *stack_s = va_arg(args, const char *);

    xmlSetProp(node, (pcmkXmlStr) "type", (pcmkXmlStr) stack_s);

    return pcmk_rc_ok;
}

int
pe__cluster_times_html(pcmk__output_t *out, va_list args) {
    xmlNodePtr updated_node = pcmk__output_create_xml_node(out, "li");
    xmlNodePtr changed_node = pcmk__output_create_xml_node(out, "li");

    const char *last_written = va_arg(args, const char *);
    const char *user = va_arg(args, const char *);
    const char *client = va_arg(args, const char *);
    const char *origin = va_arg(args, const char *);

    char *buf = last_changed_string(last_written, user, client, origin);

    pcmk_create_html_node(updated_node, "span", NULL, "bold", "Last updated: ");
    pcmk_create_html_node(updated_node, "span", NULL, NULL,
                          pcmk__epoch2str(NULL));

    pcmk_create_html_node(changed_node, "span", NULL, "bold", "Last change: ");
    pcmk_create_html_node(changed_node, "span", NULL, NULL, buf);

    free(buf);
    return pcmk_rc_ok;
}

int
pe__cluster_times_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr updated_node = pcmk__output_create_xml_node(out, "last_update");
    xmlNodePtr changed_node = pcmk__output_create_xml_node(out, "last_change");

    const char *last_written = va_arg(args, const char *);
    const char *user = va_arg(args, const char *);
    const char *client = va_arg(args, const char *);
    const char *origin = va_arg(args, const char *);

    xmlSetProp(updated_node, (pcmkXmlStr) "time",
               (pcmkXmlStr) pcmk__epoch2str(NULL));
    xmlSetProp(changed_node, (pcmkXmlStr) "time", (pcmkXmlStr) (last_written ? last_written : ""));
    xmlSetProp(changed_node, (pcmkXmlStr) "user", (pcmkXmlStr) (user ? user : ""));
    xmlSetProp(changed_node, (pcmkXmlStr) "client", (pcmkXmlStr) (client ? client : ""));
    xmlSetProp(changed_node, (pcmkXmlStr) "origin", (pcmkXmlStr) (origin ? origin : ""));

    return pcmk_rc_ok;
}

int
pe__cluster_times_text(pcmk__output_t *out, va_list args) {
    const char *last_written = va_arg(args, const char *);
    const char *user = va_arg(args, const char *);
    const char *client = va_arg(args, const char *);
    const char *origin = va_arg(args, const char *);

    char *buf = last_changed_string(last_written, user, client, origin);

    out->list_item(out, "Last updated", "%s", pcmk__epoch2str(NULL));
    out->list_item(out, "Last change", " %s", buf);

    free(buf);
    return pcmk_rc_ok;
}

int
pe__failed_action_text(pcmk__output_t *out, va_list args) {
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);
    char *s = failed_action_string(xml_op);

    out->list_item(out, NULL, "%s", s);
    free(s);
    return pcmk_rc_ok;
}

int
pe__failed_action_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);

    const char *op_key = crm_element_value(xml_op, XML_LRM_ATTR_TASK_KEY);
    const char *last = crm_element_value(xml_op, XML_RSC_OP_LAST_CHANGE);
    int rc = crm_parse_int(crm_element_value(xml_op, XML_LRM_ATTR_RC), "0");
    int status = crm_parse_int(crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS), "0");
    const char *exit_reason = crm_element_value(xml_op, XML_LRM_ATTR_EXIT_REASON);

    char *rc_s = crm_itoa(rc);
    char *reason_s = crm_xml_escape(exit_reason ? exit_reason : "none");
    xmlNodePtr node = pcmk__output_create_xml_node(out, "failure");

    xmlSetProp(node, (pcmkXmlStr) (op_key ? "op_key" : "id"),
               (pcmkXmlStr) (op_key ? op_key : "id"));
    xmlSetProp(node, (pcmkXmlStr) "node",
               (pcmkXmlStr) crm_element_value(xml_op, XML_ATTR_UNAME));
    xmlSetProp(node, (pcmkXmlStr) "exitstatus",
               (pcmkXmlStr) services_ocf_exitcode_str(rc));
    xmlSetProp(node, (pcmkXmlStr) "exitreason", (pcmkXmlStr) reason_s);
    xmlSetProp(node, (pcmkXmlStr) "exitcode", (pcmkXmlStr) rc_s);
    xmlSetProp(node, (pcmkXmlStr) "call",
               (pcmkXmlStr) crm_element_value(xml_op, XML_LRM_ATTR_CALLID));
    xmlSetProp(node, (pcmkXmlStr) "status",
               (pcmkXmlStr) services_lrm_status_str(status));

    if (last) {
        guint interval_ms = 0;
        char *s = NULL;
        time_t when = crm_parse_int(last, "0");
        crm_time_t *crm_when = crm_time_new(NULL);
        char *rc_change = NULL;

        crm_element_value_ms(xml_op, XML_LRM_ATTR_INTERVAL_MS, &interval_ms);
        s = crm_itoa(interval_ms);

        crm_time_set_timet(crm_when, &when);
        rc_change = crm_time_as_string(crm_when, crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);

        xmlSetProp(node, (pcmkXmlStr) XML_RSC_OP_LAST_CHANGE, (pcmkXmlStr) rc_change);
        xmlSetProp(node, (pcmkXmlStr) "queued",
                   (pcmkXmlStr) crm_element_value(xml_op, XML_RSC_OP_T_QUEUE));
        xmlSetProp(node, (pcmkXmlStr) "exec",
                   (pcmkXmlStr) crm_element_value(xml_op, XML_RSC_OP_T_EXEC));
        xmlSetProp(node, (pcmkXmlStr) "interval", (pcmkXmlStr) s);
        xmlSetProp(node, (pcmkXmlStr) "task",
                   (pcmkXmlStr) crm_element_value(xml_op, XML_LRM_ATTR_TASK));

        free(s);
        free(rc_change);
        crm_time_free(crm_when);
    }

    free(reason_s);
    free(rc_s);
    return pcmk_rc_ok;
}

int
pe__node_html(pcmk__output_t *out, va_list args) {
    pe_node_t *node = va_arg(args, pe_node_t *);
    unsigned int print_opts = va_arg(args, unsigned int);
    gboolean full = va_arg(args, gboolean);
    const char *node_mode G_GNUC_UNUSED = va_arg(args, const char *);
    gboolean print_clone_detail = va_arg(args, gboolean);
    gboolean print_brief = va_arg(args, gboolean);
    gboolean group_by_node = va_arg(args, gboolean);
    GListPtr only_show = va_arg(args, GListPtr);

    char *node_name = pe__node_display_name(node, print_clone_detail);
    char *buf = crm_strdup_printf("Node: %s", node_name);

    if (full) {
        xmlNodePtr item_node = pcmk__output_create_xml_node(out, "li");

        pcmk_create_html_node(item_node, "span", NULL, NULL, buf);

        if (node->details->standby_onfail && node->details->online) {
            pcmk_create_html_node(item_node, "span", NULL, "standby", " standby (on-fail)");
        } else if (node->details->standby && node->details->online) {
            char *s = crm_strdup_printf(" standby%s", node->details->running_rsc ? " (with active resources)" : "");
            pcmk_create_html_node(item_node, "span", NULL, " standby", s);
            free(s);
        } else if (node->details->standby) {
            pcmk_create_html_node(item_node, "span", NULL, "offline", " OFFLINE (standby)");
        } else if (node->details->maintenance && node->details->online) {
            pcmk_create_html_node(item_node, "span", NULL, "maint", " maintenance");
        } else if (node->details->maintenance) {
            pcmk_create_html_node(item_node, "span", NULL, "offline", " OFFLINE (maintenance)");
        } else if (node->details->online) {
            pcmk_create_html_node(item_node, "span", NULL, "online", " online");
        } else {
            pcmk_create_html_node(item_node, "span", NULL, "offline", " OFFLINE");
        }
        if (print_brief && group_by_node) {
            out->begin_list(out, NULL, NULL, NULL);
            pe__rscs_brief_output(out, node->details->running_rsc, print_opts | pe_print_rsconly,
                                  FALSE);
            out->end_list(out);

        } else if (group_by_node) {
            GListPtr lpc2 = NULL;

            out->begin_list(out, NULL, NULL, NULL);
            for (lpc2 = node->details->running_rsc; lpc2 != NULL; lpc2 = lpc2->next) {
                pe_resource_t *rsc = (pe_resource_t *) lpc2->data;
                out->message(out, crm_map_element_name(rsc->xml), print_opts | pe_print_rsconly, rsc, only_show);
            }
            out->end_list(out);
        }
    } else {
        out->begin_list(out, NULL, NULL, "%s", buf);
    }

    free(buf);
    free(node_name);
    return pcmk_rc_ok;
}

int
pe__node_text(pcmk__output_t *out, va_list args) {
    pe_node_t *node = va_arg(args, pe_node_t *);
    unsigned int print_opts = va_arg(args, unsigned int);
    gboolean full = va_arg(args, gboolean);
    const char *node_mode = va_arg(args, const char *);
    gboolean print_clone_detail = va_arg(args, gboolean);
    gboolean print_brief = va_arg(args, gboolean);
    gboolean group_by_node = va_arg(args, gboolean);
    GListPtr only_show = va_arg(args, GListPtr);

    if (full) {
        char *node_name = pe__node_display_name(node, print_clone_detail);
        char *buf = NULL;

        /* Print the node name and status */
        if (pe__is_guest_node(node)) {
            buf = crm_strdup_printf("GuestNode %s: %s", node_name, node_mode);
        } else if (pe__is_remote_node(node)) {
            buf = crm_strdup_printf("RemoteNode %s: %s", node_name, node_mode);
        } else {
            buf = crm_strdup_printf("Node %s: %s", node_name, node_mode);
        }

        /* If we're grouping by node, print its resources */
        if (group_by_node) {
            out->begin_list(out, NULL, NULL, "%s", buf);
            out->begin_list(out, NULL, NULL, "Resources");

            if (print_brief) {
                pe__rscs_brief_output(out, node->details->running_rsc,
                                      print_opts | pe_print_rsconly, FALSE);
            } else {
                GListPtr gIter2 = NULL;

                for (gIter2 = node->details->running_rsc; gIter2 != NULL; gIter2 = gIter2->next) {
                    pe_resource_t *rsc = (pe_resource_t *) gIter2->data;
                    out->message(out, crm_map_element_name(rsc->xml), print_opts | pe_print_rsconly, rsc, only_show);
                }
            }

            out->end_list(out);
            out->end_list(out);
        } else {
            out->list_item(out, NULL, "%s", buf);
        }

        free(buf);
        free(node_name);
    } else {
        out->begin_list(out, NULL, NULL, "Node: %s", pe__node_display_name(node, print_clone_detail));
    }

    return pcmk_rc_ok;
}

int
pe__node_xml(pcmk__output_t *out, va_list args) {
    pe_node_t *node = va_arg(args, pe_node_t *);
    unsigned int print_opts = va_arg(args, unsigned int);
    gboolean full = va_arg(args, gboolean);
    const char *node_mode G_GNUC_UNUSED = va_arg(args, const char *);
    gboolean print_clone_detail G_GNUC_UNUSED = va_arg(args, gboolean);
    gboolean print_brief G_GNUC_UNUSED = va_arg(args, gboolean);
    gboolean group_by_node = va_arg(args, gboolean);
    GListPtr only_show = va_arg(args, GListPtr);

    if (full) {
        const char *node_type = "unknown";
        char *length_s = crm_itoa(g_list_length(node->details->running_rsc));

        switch (node->details->type) {
            case node_member:
                node_type = "member";
                break;
            case node_remote:
                node_type = "remote";
                break;
            case node_ping:
                node_type = "ping";
                break;
        }
        pe__name_and_nvpairs_xml(out, true, "node", 13,
                                 "name", node->details->uname,
                                 "id", node->details->id,
                                 "online", node->details->online ? "true" : "false",
                                 "standby", node->details->standby ? "true" : "false",
                                 "standby_onfail", node->details->standby_onfail ? "true" : "false",
                                 "maintenance", node->details->maintenance ? "true" : "false",
                                 "pending", node->details->pending ? "true" : "false",
                                 "unclean", node->details->unclean ? "true" : "false",
                                 "shutdown", node->details->shutdown ? "true" : "false",
                                 "expected_up", node->details->expected_up ? "true" : "false",
                                 "is_dc", node->details->is_dc ? "true" : "false",
                                 "resources_running", length_s,
                                 "type", node_type);

        if (pe__is_guest_node(node)) {
            xmlNodePtr xml_node = pcmk__output_xml_peek_parent(out);
            xmlSetProp(xml_node, (pcmkXmlStr) "id_as_resource",
                                 (pcmkXmlStr) node->details->remote_rsc->container->id);
        }

        if (group_by_node) {
            GListPtr lpc = NULL;

            for (lpc = node->details->running_rsc; lpc != NULL; lpc = lpc->next) {
                pe_resource_t *rsc = (pe_resource_t *) lpc->data;
                out->message(out, crm_map_element_name(rsc->xml), print_opts | pe_print_rsconly, rsc, only_show);
            }
        }

        free(length_s);

        out->end_list(out);
    } else {
        xmlNodePtr parent = pcmk__output_xml_create_parent(out, "node");
        xmlSetProp(parent, (pcmkXmlStr) "name", (pcmkXmlStr) node->details->uname);
    }

    return pcmk_rc_ok;
}

int
pe__node_attribute_text(pcmk__output_t *out, va_list args) {
    const char *name = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);
    gboolean add_extra = va_arg(args, gboolean);
    int expected_score = va_arg(args, int);


    if (add_extra) {
        int v = crm_parse_int(value, "0");

        if (v <= 0) {
            out->list_item(out, NULL, "%-32s\t: %-10s\t: Connectivity is lost", name, value);
        } else if (v < expected_score) {
            out->list_item(out, NULL, "%-32s\t: %-10s\t: Connectivity is degraded (Expected=%d)", name, value, expected_score);
        } else {
            out->list_item(out, NULL, "%-32s\t: %-10s", name, value);
        }
    } else {
        out->list_item(out, NULL, "%-32s\t: %-10s", name, value);
    }

    return pcmk_rc_ok;
}

int
pe__node_attribute_html(pcmk__output_t *out, va_list args) {
    const char *name = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);
    gboolean add_extra = va_arg(args, gboolean);
    int expected_score = va_arg(args, int);

    if (add_extra) {
        int v = crm_parse_int(value, "0");
        char *s = crm_strdup_printf("%s: %s", name, value);
        xmlNodePtr item_node = pcmk__output_create_xml_node(out, "li");

        pcmk_create_html_node(item_node, "span", NULL, NULL, s);
        free(s);

        if (v <= 0) {
            pcmk_create_html_node(item_node, "span", NULL, "bold", "(connectivity is lost)");
        } else if (v < expected_score) {
            char *buf = crm_strdup_printf("(connectivity is degraded -- expected %d", expected_score);
            pcmk_create_html_node(item_node, "span", NULL, "bold", buf);
            free(buf);
        }
    } else {
        out->list_item(out, NULL, "%s: %s", name, value);
    }

    return pcmk_rc_ok;
}

int
pe__node_attribute_xml(pcmk__output_t *out, va_list args) {
    const char *name = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);
    gboolean add_extra = va_arg(args, gboolean);
    int expected_score = va_arg(args, int);

    xmlNodePtr node = pcmk__output_create_xml_node(out, "attribute");
    xmlSetProp(node, (pcmkXmlStr) "name", (pcmkXmlStr) name);
    xmlSetProp(node, (pcmkXmlStr) "value", (pcmkXmlStr) value);

    if (add_extra) {
        char *buf = crm_itoa(expected_score);
        xmlSetProp(node, (pcmkXmlStr) "expected", (pcmkXmlStr) buf);
        free(buf);
    }

    return pcmk_rc_ok;
}

int
pe__op_history_text(pcmk__output_t *out, va_list args) {
    xmlNode *xml_op = va_arg(args, xmlNode *);
    const char *task = va_arg(args, const char *);
    const char *interval_ms_s = va_arg(args, const char *);
    int rc = va_arg(args, int);
    gboolean print_timing = va_arg(args, gboolean);

    char *buf = op_history_string(xml_op, task, interval_ms_s, rc, print_timing);

    out->list_item(out, NULL, "%s", buf);

    free(buf);
    return pcmk_rc_ok;
}

int
pe__op_history_xml(pcmk__output_t *out, va_list args) {
    xmlNode *xml_op = va_arg(args, xmlNode *);
    const char *task = va_arg(args, const char *);
    const char *interval_ms_s = va_arg(args, const char *);
    int rc = va_arg(args, int);
    gboolean print_timing = va_arg(args, gboolean);

    char *rc_s = NULL;

    xmlNodePtr node = pcmk__output_create_xml_node(out, "operation_history");

    xmlSetProp(node, (pcmkXmlStr) "call",
               (pcmkXmlStr) crm_element_value(xml_op, XML_LRM_ATTR_CALLID));
    xmlSetProp(node, (pcmkXmlStr) "task", (pcmkXmlStr) task);

    if (interval_ms_s && safe_str_neq(interval_ms_s, "0")) {
        char *s = crm_strdup_printf("%sms", interval_ms_s);
        xmlSetProp(node, (pcmkXmlStr) "interval", (pcmkXmlStr) s);
        free(s);
    }

    if (print_timing) {
        const char *value = NULL;

        value = crm_element_value(xml_op, XML_RSC_OP_LAST_CHANGE);
        if (value) {
            time_t int_value = (time_t) crm_parse_int(value, NULL);
            if (int_value > 0) {
                xmlSetProp(node, (pcmkXmlStr) XML_RSC_OP_LAST_CHANGE,
                           (pcmkXmlStr) pcmk__epoch2str(&int_value));
            }
        }

        value = crm_element_value(xml_op, XML_RSC_OP_LAST_RUN);
        if (value) {
            time_t int_value = (time_t) crm_parse_int(value, NULL);
            if (int_value > 0) {
                xmlSetProp(node, (pcmkXmlStr) XML_RSC_OP_LAST_RUN,
                           (pcmkXmlStr) pcmk__epoch2str(&int_value));
            }
        }

        value = crm_element_value(xml_op, XML_RSC_OP_T_EXEC);
        if (value) {
            char *s = crm_strdup_printf("%sms", value);
            xmlSetProp(node, (pcmkXmlStr) XML_RSC_OP_T_EXEC, (pcmkXmlStr) s);
            free(s);
        }
        value = crm_element_value(xml_op, XML_RSC_OP_T_QUEUE);
        if (value) {
            char *s = crm_strdup_printf("%sms", value);
            xmlSetProp(node, (pcmkXmlStr) XML_RSC_OP_T_QUEUE, (pcmkXmlStr) s);
            free(s);
        }
    }

    rc_s = crm_itoa(rc);
    xmlSetProp(node, (pcmkXmlStr) "rc", (pcmkXmlStr) rc_s);
    xmlSetProp(node, (pcmkXmlStr) "rc_text", (pcmkXmlStr) services_ocf_exitcode_str(rc));
    free(rc_s);
    return pcmk_rc_ok;
}

int
pe__resource_history_text(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    const char *rsc_id = va_arg(args, const char *);
    gboolean all = va_arg(args, gboolean);
    int failcount = va_arg(args, int);
    time_t last_failure = va_arg(args, int);
    gboolean as_header = va_arg(args, gboolean);

    char *buf = resource_history_string(rsc, rsc_id, all, failcount, last_failure);

    if (as_header) {
        out->begin_list(out, NULL, NULL, "%s", buf);
    } else {
        out->list_item(out, NULL, "%s", buf);
    }

    free(buf);
    return pcmk_rc_ok;
}

int
pe__resource_history_xml(pcmk__output_t *out, va_list args) {
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    const char *rsc_id = va_arg(args, const char *);
    gboolean all = va_arg(args, gboolean);
    int failcount = va_arg(args, int);
    time_t last_failure = va_arg(args, int);
    gboolean as_header = va_arg(args, gboolean);

    xmlNodePtr node = pcmk__output_xml_create_parent(out, "resource_history");
    xmlSetProp(node, (pcmkXmlStr) "id", (pcmkXmlStr) rsc_id);

    if (rsc == NULL) {
        xmlSetProp(node, (pcmkXmlStr) "orphan", (pcmkXmlStr) "true");
    } else if (all || failcount || last_failure > 0) {
        char *migration_s = crm_itoa(rsc->migration_threshold);

        xmlSetProp(node, (pcmkXmlStr) "orphan", (pcmkXmlStr) "false");
        xmlSetProp(node, (pcmkXmlStr) "migration-threshold",
                   (pcmkXmlStr) migration_s);
        free(migration_s);

        if (failcount > 0) {
            char *s = crm_itoa(failcount);

            xmlSetProp(node, (pcmkXmlStr) PCMK__FAIL_COUNT_PREFIX,
                       (pcmkXmlStr) s);
            free(s);
        }

        if (last_failure > 0) {
            xmlSetProp(node, (pcmkXmlStr) PCMK__LAST_FAILURE_PREFIX,
                       (pcmkXmlStr) pcmk__epoch2str(&last_failure));
        }
    }

    if (as_header == FALSE) {
        pcmk__output_xml_pop_parent(out);
    }

    return pcmk_rc_ok;
}

int
pe__ticket_html(pcmk__output_t *out, va_list args) {
    pe_ticket_t *ticket = va_arg(args, pe_ticket_t *);

    if (ticket->last_granted > -1) {
        char *time = pcmk_format_named_time("last-granted", ticket->last_granted);
        out->list_item(out, NULL, "%s:\t%s%s %s", ticket->id,
                       ticket->granted ? "granted" : "revoked",
                       ticket->standby ? " [standby]" : "",
                       time);
        free(time);
    } else {
        out->list_item(out, NULL, "%s:\t%s%s", ticket->id,
                       ticket->granted ? "granted" : "revoked",
                       ticket->standby ? " [standby]" : "");
    }

    return pcmk_rc_ok;
}

int
pe__ticket_text(pcmk__output_t *out, va_list args) {
    pe_ticket_t *ticket = va_arg(args, pe_ticket_t *);

    if (ticket->last_granted > -1) {
        char *time = pcmk_format_named_time("last-granted", ticket->last_granted);
        out->list_item(out, ticket->id, "\t%s%s %s",
                       ticket->granted ? "granted" : "revoked",
                       ticket->standby ? " [standby]" : "",
                       time);
        free(time);
    } else {
        out->list_item(out, ticket->id, "\t%s%s",
                       ticket->granted ? "granted" : "revoked",
                       ticket->standby ? " [standby]" : "");
    }

    return pcmk_rc_ok;
}

int
pe__ticket_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = NULL;

    pe_ticket_t *ticket = va_arg(args, pe_ticket_t *);

    node = pcmk__output_create_xml_node(out, "ticket");
    xmlSetProp(node, (pcmkXmlStr) "id", (pcmkXmlStr) ticket->id);
    xmlSetProp(node, (pcmkXmlStr) "status", (pcmkXmlStr) (ticket->granted ? "granted" : "revoked"));
    xmlSetProp(node, (pcmkXmlStr) "standby", (pcmkXmlStr) (ticket->standby ? "true" : "false"));

    if (ticket->last_granted > -1) {
        xmlSetProp(node, (pcmkXmlStr) "last-granted",
                   (pcmkXmlStr) pcmk__epoch2str(&ticket->last_granted));
    }

    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "ban", "html", pe__ban_html },
    { "ban", "log", pe__ban_text },
    { "ban", "text", pe__ban_text },
    { "ban", "xml", pe__ban_xml },
    { "bundle", "xml",  pe__bundle_xml },
    { "bundle", "html",  pe__bundle_html },
    { "bundle", "text",  pe__bundle_text },
    { "bundle", "log",  pe__bundle_text },
    { "clone", "xml",  pe__clone_xml },
    { "clone", "html",  pe__clone_html },
    { "clone", "text",  pe__clone_text },
    { "clone", "log",  pe__clone_text },
    { "cluster-counts", "html", pe__cluster_counts_html },
    { "cluster-counts", "log", pe__cluster_counts_text },
    { "cluster-counts", "text", pe__cluster_counts_text },
    { "cluster-counts", "xml", pe__cluster_counts_xml },
    { "cluster-dc", "html", pe__cluster_dc_html },
    { "cluster-dc", "log", pe__cluster_dc_text },
    { "cluster-dc", "text", pe__cluster_dc_text },
    { "cluster-dc", "xml", pe__cluster_dc_xml },
    { "cluster-options", "html", pe__cluster_options_html },
    { "cluster-options", "log", pe__cluster_options_log },
    { "cluster-options", "text", pe__cluster_options_text },
    { "cluster-options", "xml", pe__cluster_options_xml },
    { "cluster-summary", "html", pe__cluster_summary_html },
    { "cluster-summary", "log", pe__cluster_summary },
    { "cluster-summary", "text", pe__cluster_summary },
    { "cluster-summary", "xml", pe__cluster_summary },
    { "cluster-stack", "html", pe__cluster_stack_html },
    { "cluster-stack", "log", pe__cluster_stack_text },
    { "cluster-stack", "text", pe__cluster_stack_text },
    { "cluster-stack", "xml", pe__cluster_stack_xml },
    { "cluster-times", "html", pe__cluster_times_html },
    { "cluster-times", "log", pe__cluster_times_text },
    { "cluster-times", "text", pe__cluster_times_text },
    { "cluster-times", "xml", pe__cluster_times_xml },
    { "failed-action", "html", pe__failed_action_text },
    { "failed-action", "log", pe__failed_action_text },
    { "failed-action", "text", pe__failed_action_text },
    { "failed-action", "xml", pe__failed_action_xml },
    { "group", "xml",  pe__group_xml },
    { "group", "html",  pe__group_html },
    { "group", "text",  pe__group_text },
    { "group", "log",  pe__group_text },
    /* maint-mode only exists for text and log.  Other formatters output it as
     * part of the cluster-options handler.
     */
    { "maint-mode", "log", pe__cluster_maint_mode_text },
    { "maint-mode", "text", pe__cluster_maint_mode_text },
    { "node", "html", pe__node_html },
    { "node", "log", pe__node_text },
    { "node", "text", pe__node_text },
    { "node", "xml", pe__node_xml },
    { "node-attribute", "html", pe__node_attribute_html },
    { "node-attribute", "log", pe__node_attribute_text },
    { "node-attribute", "text", pe__node_attribute_text },
    { "node-attribute", "xml", pe__node_attribute_xml },
    { "op-history", "html", pe__op_history_text },
    { "op-history", "log", pe__op_history_text },
    { "op-history", "text", pe__op_history_text },
    { "op-history", "xml", pe__op_history_xml },
    { "primitive", "xml",  pe__resource_xml },
    { "primitive", "html",  pe__resource_html },
    { "primitive", "text",  pe__resource_text },
    { "primitive", "log",  pe__resource_text },
    { "resource-history", "html", pe__resource_history_text },
    { "resource-history", "log", pe__resource_history_text },
    { "resource-history", "text", pe__resource_history_text },
    { "resource-history", "xml", pe__resource_history_xml },
    { "ticket", "html", pe__ticket_html },
    { "ticket", "log", pe__ticket_text },
    { "ticket", "text", pe__ticket_text },
    { "ticket", "xml", pe__ticket_xml },

    { NULL, NULL, NULL }
};

void
pe__register_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}

void
pe__output_node(pe_node_t *node, gboolean details, pcmk__output_t *out)
{
    if (node == NULL) {
        crm_trace("<NULL>");
        return;
    }

    CRM_ASSERT(node->details);
    crm_trace("%sNode %s: (weight=%d, fixed=%s)",
              node->details->online ? "" : "Unavailable/Unclean ",
              node->details->uname, node->weight, node->fixed ? "True" : "False");

    if (details) {
        char *pe_mutable = strdup("\t\t");
        GListPtr gIter = node->details->running_rsc;
        GListPtr unames = NULL;

        unames = g_list_prepend(unames, strdup("*"));

        crm_trace("\t\t===Node Attributes");
        g_hash_table_foreach(node->details->attrs, print_str_str, pe_mutable);
        free(pe_mutable);

        crm_trace("\t\t=== Resources");

        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *rsc = (pe_resource_t *) gIter->data;

            out->message(out, crm_map_element_name(rsc->xml),
                         pe_print_pending, rsc, unames);
        }

        g_list_free_full(unames, free);
    }
}
