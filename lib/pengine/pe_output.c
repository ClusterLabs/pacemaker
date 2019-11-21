/*
 * Copyright 2019 the Pacemaker project contributors
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

#define s_if_plural(i) (((i) == 1)? "" : "s")

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
        buf = crm_strdup_printf("(%s) %s:%s", call, task,
                                interval_str ? interval_str : "");
    }

    if (interval_str) {
        free(interval_str);
    }

    return buf;
}

static char *
resource_history_string(resource_t *rsc, const char *rsc_id, gboolean all,
                        int failcount, time_t last_failure) {
    char *buf = NULL;

    if (rsc == NULL) {
        buf = crm_strdup_printf("%s: orphan", rsc_id);
    } else if (all || failcount || last_failure > 0) {
        char *failcount_s = failcount > 0 ? crm_strdup_printf(" %s=%d", CRM_FAIL_COUNT_PREFIX, failcount) : strdup("");
        char *lastfail_s = last_failure > 0 ? crm_strdup_printf(" %s=%s", CRM_LAST_FAILURE_PREFIX,
                                                                crm_now_string(&last_failure)) : strdup("");

        buf = crm_strdup_printf("%s: migration-threshold=%d%s%s",
                                rsc_id, rsc->migration_threshold, failcount_s, lastfail_s);
        free(failcount_s);
        free(lastfail_s);
    } else {
        buf = crm_strdup_printf("%s:", rsc_id);
    }

    return buf;
}

char *
pe__node_display_name(node_t *node, bool print_detail)
{
    char *node_name;
    const char *node_host = NULL;
    const char *node_id = NULL;
    int name_len;

    CRM_ASSERT((node != NULL) && (node->details != NULL) && (node->details->uname != NULL));

    /* Host is displayed only if this is a guest node */
    if (pe__is_guest_node(node)) {
        node_t *host_node = pe__current_node(node->details->remote_rsc);

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
    return 0;
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
    return 0;
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
    return 0;
}

int
pe__ban_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "ban");
    pe_node_t *pe_node = va_arg(args, pe_node_t *);
    pe__location_t *location = va_arg(args, pe__location_t *);

    char *weight_s = crm_itoa(pe_node->weight);

    xmlSetProp(node, (pcmkXmlStr) "id", (pcmkXmlStr) location->id);
    xmlSetProp(node, (pcmkXmlStr) "resource", (pcmkXmlStr) location->rsc_lh->id);
    xmlSetProp(node, (pcmkXmlStr) "node", (pcmkXmlStr) pe_node->details->uname);
    xmlSetProp(node, (pcmkXmlStr) "weight", (pcmkXmlStr) weight_s);
    xmlSetProp(node, (pcmkXmlStr) "master_only",
               (pcmkXmlStr) (location->role_filter == RSC_ROLE_MASTER ? "true" : "false"));

    free(weight_s);
    return 0;
}

int
pe__cluster_counts_html(pcmk__output_t *out, va_list args) {
    xmlNodePtr nodes_node = pcmk__output_create_xml_node(out, "li");
    xmlNodePtr resources_node = pcmk__output_create_xml_node(out, "li");

    unsigned int nnodes = va_arg(args, unsigned int);
    unsigned int nresources = va_arg(args, unsigned int);
    unsigned int ndisabled = va_arg(args, unsigned int);
    unsigned int nblocked = va_arg(args, unsigned int);

    char *nnodes_str = crm_strdup_printf("%d node%s configured", nnodes, s_if_plural(nnodes));

    pcmk_create_html_node(nodes_node, "span", NULL, NULL, nnodes_str);
    free(nnodes_str);

    if (ndisabled && nblocked) {
        char *s = crm_strdup_printf("%d resource instance%s configured (%d ",
                                    nresources, s_if_plural(nresources),
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
                                    nresources, s_if_plural(nresources),
                                    ndisabled);
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);

        pcmk_create_html_node(resources_node, "span", NULL, "bold", "DISABLED");
        pcmk_create_html_node(resources_node, "span", NULL, NULL, ")");
    } else if (!ndisabled && nblocked) {
        char *s = crm_strdup_printf("%d resource instance%s configured (%d ",
                                    nresources, s_if_plural(nresources),
                                    nblocked);
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);

        pcmk_create_html_node(resources_node, "span", NULL, "bold", "BLOCKED");
        pcmk_create_html_node(resources_node, "span", NULL, NULL,
                              " from further action due to failure)");
    } else {
        char *s = crm_strdup_printf("%d resource instance%s configured",
                                    nresources, s_if_plural(nresources));
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);
    }

    return 0;
}

int
pe__cluster_counts_text(pcmk__output_t *out, va_list args) {
    unsigned int nnodes = va_arg(args, unsigned int);
    unsigned int nresources = va_arg(args, unsigned int);
    unsigned int ndisabled = va_arg(args, unsigned int);
    unsigned int nblocked = va_arg(args, unsigned int);

    out->list_item(out, NULL, "%d node%s configured", nnodes, s_if_plural(nnodes));

    if (ndisabled && nblocked) {
        out->list_item(out, NULL, "%d resource instance%s configured "
                                  "(%d DISABLED, %d BLOCKED from "
                                  "further action due to failure)",
                       nresources, s_if_plural(nresources), ndisabled,
                       nblocked);
    } else if (ndisabled && !nblocked) {
        out->list_item(out, NULL, "%d resource instance%s configured "
                                  "(%d DISABLED)",
                       nresources, s_if_plural(nresources), ndisabled);
    } else if (!ndisabled && nblocked) {
        out->list_item(out, NULL, "%d resource instance%s configured "
                                  "(%d BLOCKED from further action "
                                  "due to failure)",
                       nresources, s_if_plural(nresources), nblocked);
    } else {
        out->list_item(out, NULL, "%d resource instance%s configured",
                       nresources, s_if_plural(nresources));
    }

    return 0;
}

int
pe__cluster_counts_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr nodes_node = pcmk__output_create_xml_node(out, "nodes_configured");
    xmlNodePtr resources_node = pcmk__output_create_xml_node(out, "resources_configured");

    unsigned int nnodes = va_arg(args, unsigned int);
    unsigned int nresources = va_arg(args, unsigned int);
    unsigned int ndisabled = va_arg(args, unsigned int);
    unsigned int nblocked = va_arg(args, unsigned int);

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

    return 0;
}

int
pe__cluster_dc_html(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "li");

    node_t *dc = va_arg(args, node_t *);
    const char *quorum = va_arg(args, const char *);
    const char *dc_version_s = va_arg(args, const char *);
    const char *dc_name = va_arg(args, const char *);

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

    return 0;
}

int
pe__cluster_dc_text(pcmk__output_t *out, va_list args) {
    node_t *dc = va_arg(args, node_t *);
    const char *quorum = va_arg(args, const char *);
    const char *dc_version_s = va_arg(args, const char *);
    const char *dc_name = va_arg(args, const char *);

    if (dc) {
        out->list_item(out, "Current DC", "%s (version %s) - partition %s quorum",
                       dc_name, dc_version_s ? dc_version_s : "unknown",
                       crm_is_true(quorum) ? "with" : "WITHOUT");
    } else {
        out->list_item(out, "Current DC", "NONE");
    }

    return 0;
}

int
pe__cluster_dc_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "current_dc");

    node_t *dc = va_arg(args, node_t *);
    const char *quorum = va_arg(args, const char *);
    const char *dc_version_s = va_arg(args, const char *);

    if (dc) {
        xmlSetProp(node, (pcmkXmlStr) "present", (pcmkXmlStr) "true");
        xmlSetProp(node, (pcmkXmlStr) "version", (pcmkXmlStr) (dc_version_s ? dc_version_s : ""));
        xmlSetProp(node, (pcmkXmlStr) "name", (pcmkXmlStr) dc->details->uname);
        xmlSetProp(node, (pcmkXmlStr) "id", (pcmkXmlStr) dc->details->id);
        xmlSetProp(node, (pcmkXmlStr) "with_quorum", (pcmkXmlStr) (crm_is_true(quorum) ? "true" : "false"));
    } else {
        xmlSetProp(node, (pcmkXmlStr) "present", (pcmkXmlStr) "false");
    }

    return 0;
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
            out->list_item(out, NULL, "No Quorum policy: Freeze resources");
            break;

        case no_quorum_stop:
            out->list_item(out, NULL, "No Quorum policy: Stop ALL resources");
            break;

        case no_quorum_ignore:
            out->list_item(out, NULL, "No Quorum policy: Ignore");
            break;

        case no_quorum_suicide:
            out->list_item(out, NULL, "No Quorum policy: Suicide");
            break;
    }

    if (is_set(data_set->flags, pe_flag_maintenance_mode)) {
        xmlNodePtr node = pcmk__output_create_xml_node(out, "li");

        pcmk_create_html_node(node, "span", NULL, "bold", "DISABLED");
        pcmk_create_html_node(node, "span", NULL, NULL,
                              " (the cluster will not attempt to start, stop, or recover services)");
    } else {
        out->list_item(out, NULL, "Resource management enabled");
    }

    return 0;
}

int
pe__cluster_options_text(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);

    if (is_set(data_set->flags, pe_flag_maintenance_mode)) {
        fprintf(out->dest, "\n              *** Resource management is DISABLED ***");
        fprintf(out->dest, "\n  The cluster will not attempt to start, stop or recover services");
        fprintf(out->dest, "\n");
    }

    return 0;
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

    return 0;
}

int
pe__cluster_stack_html(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "li");
    const char *stack_s = va_arg(args, const char *);

    pcmk_create_html_node(node, "span", NULL, "bold", "Stack: ");
    pcmk_create_html_node(node, "span", NULL, NULL, stack_s);

    return 0;
}

int
pe__cluster_stack_text(pcmk__output_t *out, va_list args) {
    const char *stack_s = va_arg(args, const char *);
    out->list_item(out, "Stack", "%s", stack_s);
    return 0;
}

int
pe__cluster_stack_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "stack");
    const char *stack_s = va_arg(args, const char *);

    xmlSetProp(node, (pcmkXmlStr) "type", (pcmkXmlStr) stack_s);

    return 0;
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
    pcmk_create_html_node(updated_node, "span", NULL, NULL, crm_now_string(NULL));

    pcmk_create_html_node(changed_node, "span", NULL, "bold", "Last change: ");
    pcmk_create_html_node(changed_node, "span", NULL, NULL, buf);

    free(buf);
    return 0;
}

int
pe__cluster_times_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr updated_node = pcmk__output_create_xml_node(out, "last_update");
    xmlNodePtr changed_node = pcmk__output_create_xml_node(out, "last_change");

    const char *last_written = va_arg(args, const char *);
    const char *user = va_arg(args, const char *);
    const char *client = va_arg(args, const char *);
    const char *origin = va_arg(args, const char *);

    xmlSetProp(updated_node, (pcmkXmlStr) "time", (pcmkXmlStr) crm_now_string(NULL));

    xmlSetProp(changed_node, (pcmkXmlStr) "time", (pcmkXmlStr) (last_written ? last_written : ""));
    xmlSetProp(changed_node, (pcmkXmlStr) "user", (pcmkXmlStr) (user ? user : ""));
    xmlSetProp(changed_node, (pcmkXmlStr) "client", (pcmkXmlStr) (client ? client : ""));
    xmlSetProp(changed_node, (pcmkXmlStr) "origin", (pcmkXmlStr) (origin ? origin : ""));

    return 0;
}

int
pe__cluster_times_text(pcmk__output_t *out, va_list args) {
    const char *last_written = va_arg(args, const char *);
    const char *user = va_arg(args, const char *);
    const char *client = va_arg(args, const char *);
    const char *origin = va_arg(args, const char *);

    char *buf = last_changed_string(last_written, user, client, origin);

    out->list_item(out, "Last updated", "%s", crm_now_string(NULL));
    out->list_item(out, "Last change", " %s", buf);

    free(buf);
    return 0;
}

int
pe__node_html(pcmk__output_t *out, va_list args) {
    node_t *node = va_arg(args, node_t *);
    unsigned int print_opts = va_arg(args, unsigned int);
    gboolean full = va_arg(args, gboolean);
    const char *node_mode G_GNUC_UNUSED = va_arg(args, const char *);
    gboolean print_clone_detail = va_arg(args, gboolean);
    gboolean print_brief = va_arg(args, gboolean);
    gboolean group_by_node = va_arg(args, gboolean);

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
                resource_t *rsc = (resource_t *) lpc2->data;
                out->message(out, crm_map_element_name(rsc->xml), print_opts | pe_print_rsconly, rsc);
            }
            out->end_list(out);
        }
    } else {
        out->begin_list(out, NULL, NULL, "%s", buf);
    }

    free(buf);
    free(node_name);
    return 0;
}

int
pe__node_text(pcmk__output_t *out, va_list args) {
    node_t *node = va_arg(args, node_t *);
    unsigned int print_opts = va_arg(args, unsigned int);
    gboolean full = va_arg(args, gboolean);
    const char *node_mode = va_arg(args, const char *);
    gboolean print_clone_detail = va_arg(args, gboolean);
    gboolean print_brief = va_arg(args, gboolean);
    gboolean group_by_node = va_arg(args, gboolean);

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
                    resource_t *rsc = (resource_t *) gIter2->data;
                    out->message(out, crm_map_element_name(rsc->xml), print_opts | pe_print_rsconly, rsc);
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

    return 0;
}

int
pe__node_xml(pcmk__output_t *out, va_list args) {
    node_t *node = va_arg(args, node_t *);
    unsigned int print_opts = va_arg(args, unsigned int);
    gboolean full = va_arg(args, gboolean);
    const char *node_mode G_GNUC_UNUSED = va_arg(args, const char *);
    gboolean print_clone_detail G_GNUC_UNUSED = va_arg(args, gboolean);
    gboolean print_brief G_GNUC_UNUSED = va_arg(args, gboolean);
    gboolean group_by_node = va_arg(args, gboolean);

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
                resource_t *rsc = (resource_t *) lpc->data;
                out->message(out, crm_map_element_name(rsc->xml), print_opts | pe_print_rsconly, rsc);
            }
        }

        free(length_s);

        out->end_list(out);
    } else {
        xmlNodePtr parent = pcmk__output_xml_create_parent(out, "node");
        xmlSetProp(parent, (pcmkXmlStr) "name", (pcmkXmlStr) node->details->uname);
    }

    return 0;
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

    return 0;
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

    return 0;
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

    return 0;
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
    return 0;
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
                           (pcmkXmlStr) crm_now_string(&int_value));
            }
        }

        value = crm_element_value(xml_op, XML_RSC_OP_LAST_RUN);
        if (value) {
            time_t int_value = (time_t) crm_parse_int(value, NULL);
            if (int_value > 0) {
                xmlSetProp(node, (pcmkXmlStr) XML_RSC_OP_LAST_RUN,
                           (pcmkXmlStr) crm_now_string(&int_value));
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
    return 0;
}

int
pe__resource_history_text(pcmk__output_t *out, va_list args) {
    resource_t *rsc = va_arg(args, resource_t *);
    const char *rsc_id = va_arg(args, const char *);
    gboolean all = va_arg(args, gboolean);
    int failcount = va_arg(args, int);
    time_t last_failure = va_arg(args, int);

    char *buf = resource_history_string(rsc, rsc_id, all, failcount, last_failure);

    out->begin_list(out, NULL, NULL, "%s", buf);
    free(buf);
    return 0;
}

int
pe__resource_history_xml(pcmk__output_t *out, va_list args) {
    resource_t *rsc = va_arg(args, resource_t *);
    const char *rsc_id = va_arg(args, const char *);
    gboolean all = va_arg(args, gboolean);
    int failcount = va_arg(args, int);
    time_t last_failure = va_arg(args, int);

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
            xmlSetProp(node, (pcmkXmlStr) CRM_FAIL_COUNT_PREFIX, (pcmkXmlStr) s);
            free(s);
        }

        if (last_failure > 0) {
            xmlSetProp(node, (pcmkXmlStr) CRM_LAST_FAILURE_PREFIX,
                       (pcmkXmlStr) crm_now_string(&last_failure));
        }
    }

    return 0;
}

static int
pe__ticket_html(pcmk__output_t *out, va_list args) {
    ticket_t *ticket = va_arg(args, ticket_t *);

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

    return 0;
}

static int
pe__ticket_text(pcmk__output_t *out, va_list args) {
    ticket_t *ticket = va_arg(args, ticket_t *);

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

    return 0;
}

static int
pe__ticket_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = NULL;

    ticket_t *ticket = va_arg(args, ticket_t *);

    node = pcmk__output_create_xml_node(out, "ticket");
    xmlSetProp(node, (pcmkXmlStr) "id", (pcmkXmlStr) ticket->id);
    xmlSetProp(node, (pcmkXmlStr) "status", (pcmkXmlStr) (ticket->granted ? "granted" : "revoked"));
    xmlSetProp(node, (pcmkXmlStr) "standby", (pcmkXmlStr) (ticket->standby ? "true" : "false"));

    if (ticket->last_granted > -1) {
        xmlSetProp(node, (pcmkXmlStr) "last-granted",
                   (pcmkXmlStr) crm_now_string(&ticket->last_granted));
    }

    return 0;
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
    { "cluster-options", "log", pe__cluster_options_text },
    { "cluster-options", "text", pe__cluster_options_text },
    { "cluster-options", "xml", pe__cluster_options_xml },
    { "cluster-stack", "html", pe__cluster_stack_html },
    { "cluster-stack", "log", pe__cluster_stack_text },
    { "cluster-stack", "text", pe__cluster_stack_text },
    { "cluster-stack", "xml", pe__cluster_stack_xml },
    { "cluster-times", "html", pe__cluster_times_html },
    { "cluster-times", "log", pe__cluster_times_text },
    { "cluster-times", "text", pe__cluster_times_text },
    { "cluster-times", "xml", pe__cluster_times_xml },
    { "group", "xml",  pe__group_xml },
    { "group", "html",  pe__group_html },
    { "group", "text",  pe__group_text },
    { "group", "log",  pe__group_text },
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
    { "ticket", "text", pe__ticket_text },
    { "ticket", "xml", pe__ticket_xml },

    { NULL, NULL, NULL }
};

void
pe__register_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}

void
pe__output_node(node_t *node, gboolean details, pcmk__output_t *out)
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

        crm_trace("\t\t===Node Attributes");
        g_hash_table_foreach(node->details->attrs, print_str_str, pe_mutable);
        free(pe_mutable);

        crm_trace("\t\t=== Resources");

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *rsc = (resource_t *) gIter->data;

            // @TODO pe_print_log probably doesn't belong here
            out->message(out, crm_map_element_name(rsc->xml),
                         pe_print_log|pe_print_pending, rsc);
        }
    }
}
