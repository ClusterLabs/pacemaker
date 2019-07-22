/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <glib.h>
#include <stdarg.h>

#include <crm/stonith-ng.h>
#include <crm/common/iso8601_internal.h>
#include <crm/common/output.h>
#include <crm/common/util.h>
#include <crm/common/xml.h>

#include "crm_mon.h"

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
                                 origin ? " origin " : "",
                                 origin ? origin : "");
    } else {
        return strdup("");
    }
}

static int
cluster_counts_html(pcmk__output_t *out, va_list args) {
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
        char *s = crm_strdup_printf("%d resource%s configured (%d ", nresources, s_if_plural(nresources), ndisabled);
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);

        pcmk_create_html_node(resources_node, "span", NULL, "bold", "DISABLED");

        s = crm_strdup_printf(", %d ", nblocked);
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);

        pcmk_create_html_node(resources_node, "span", NULL, "bold", "BLOCKED");
        pcmk_create_html_node(resources_node, "span", NULL, NULL, " from starting due to failure)");
    } else if (ndisabled && !nblocked) {
        char *s = crm_strdup_printf("%d resource%s configured (%d ", nresources, s_if_plural(nresources), ndisabled);
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);

        pcmk_create_html_node(resources_node, "span", NULL, "bold", "DISABLED");
        pcmk_create_html_node(resources_node, "span", NULL, NULL, ")");
    } else if (!ndisabled && nblocked) {
        char *s = crm_strdup_printf("%d resource%s configured (%d ", nresources, s_if_plural(nresources), nblocked);
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);

        pcmk_create_html_node(resources_node, "span", NULL, "bold", "BLOCKED");
        pcmk_create_html_node(resources_node, "span", NULL, NULL, " from starting due to failure)");
    } else {
        char *s = crm_strdup_printf("%d resource%s configured", nresources, s_if_plural(nresources));
        pcmk_create_html_node(resources_node, "span", NULL, NULL, s);
        free(s);
    }

    return 0;
}

static int
cluster_counts_text(pcmk__output_t *out, va_list args) {
    unsigned int nnodes = va_arg(args, unsigned int);
    unsigned int nresources = va_arg(args, unsigned int);
    unsigned int ndisabled = va_arg(args, unsigned int);
    unsigned int nblocked = va_arg(args, unsigned int);

    out->list_item(out, NULL, "%d node%s configured", nnodes, s_if_plural(nnodes));

    if (ndisabled && nblocked) {
        out->list_item(out, NULL, "%d resource%s configured (%d DISABLED, %d BLOCKED from starting due to failure",
                       nresources, s_if_plural(nresources), ndisabled, nblocked);
    } else if (ndisabled && !nblocked) {
        out->list_item(out, NULL, "%d resource%s configured (%d DISABLED)",
                       nresources, s_if_plural(nresources), ndisabled);
    } else if (!ndisabled && nblocked) {
        out->list_item(out, NULL, "%d resource%s configured (%d BLOCKED from starting due to failure)",
                       nresources, s_if_plural(nresources), nblocked);
    } else {
        out->list_item(out, NULL, "%d resource%s configured", nresources, s_if_plural(nresources));
    }

    return 0;
}

static int
cluster_counts_xml(pcmk__output_t *out, va_list args) {
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

static int
cluster_dc_html(pcmk__output_t *out, va_list args) {
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

static int
cluster_dc_text(pcmk__output_t *out, va_list args) {
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

static int
cluster_dc_xml(pcmk__output_t *out, va_list args) {
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

static int
cluster_options_html(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);

    /* Kind of a hack - close the list started by print_cluster_summary so we
     * can put all the options in their own list, but just for HTML output.
     */
    out->end_list(out);

    /* And then this list will be closed by print_cluster_summary since it
     * wants to close the list it created unconditionally.
     */
    out->begin_list(out, NULL, NULL, "Config Options");

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

static int
cluster_options_text(pcmk__output_t *out, va_list args) {
    pe_working_set_t *data_set = va_arg(args, pe_working_set_t *);

    if (is_set(data_set->flags, pe_flag_maintenance_mode)) {
        fprintf(out->dest, "\n              *** Resource management is DISABLED ***");
        fprintf(out->dest, "\n  The cluster will not attempt to start, stop or recover services");
        fprintf(out->dest, "\n");
    }

    return 0;
}

static int
cluster_options_xml(pcmk__output_t *out, va_list args) {
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

static int
cluster_stack_html(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "li");
    const char *stack_s = va_arg(args, const char *);

    pcmk_create_html_node(node, "span", NULL, "bold", "Stack: ");
    pcmk_create_html_node(node, "span", NULL, NULL, stack_s);

    return 0;
}

static int
cluster_stack_text(pcmk__output_t *out, va_list args) {
    const char *stack_s = va_arg(args, const char *);
    out->list_item(out, "Stack", "%s", stack_s);
    return 0;
}

static int
cluster_stack_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "stack");
    const char *stack_s = va_arg(args, const char *);

    xmlSetProp(node, (pcmkXmlStr) "type", (pcmkXmlStr) stack_s);

    return 0;
}

static int
cluster_times_html(pcmk__output_t *out, va_list args) {
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

static int
cluster_times_xml(pcmk__output_t *out, va_list args) {
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

static int
cluster_times_text(pcmk__output_t *out, va_list args) {
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


static int
ticket_console(pcmk__output_t *out, va_list args) {
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

static pcmk__message_entry_t fmt_functions[] = {
    { "cluster-counts", "console", cluster_counts_text },
    { "cluster-counts", "html", cluster_counts_html },
    { "cluster-counts", "text", cluster_counts_text },
    { "cluster-counts", "xml", cluster_counts_xml },
    { "cluster-dc", "console", cluster_dc_text },
    { "cluster-dc", "html", cluster_dc_html },
    { "cluster-dc", "text", cluster_dc_text },
    { "cluster-dc", "xml", cluster_dc_xml },
    { "cluster-options", "console", cluster_options_text },
    { "cluster-options", "html", cluster_options_html },
    { "cluster-options", "text", cluster_options_text },
    { "cluster-options", "xml", cluster_options_xml },
    { "cluster-stack", "console", cluster_stack_text },
    { "cluster-stack", "html", cluster_stack_html },
    { "cluster-stack", "text", cluster_stack_text },
    { "cluster-stack", "xml", cluster_stack_xml },
    { "cluster-times", "console", cluster_times_text },
    { "cluster-times", "html", cluster_times_html },
    { "cluster-times", "text", cluster_times_text },
    { "cluster-times", "xml", cluster_times_xml },
    { "ticket", "console", ticket_console },

    { NULL, NULL, NULL }
};

void
crm_mon_register_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
