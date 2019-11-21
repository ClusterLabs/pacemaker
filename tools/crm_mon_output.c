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
#include <crm/common/iso8601.h>
#include <crm/common/iso8601_internal.h>
#include <crm/common/output.h>
#include <crm/common/util.h>
#include <crm/common/xml.h>
#include <crm/common/internal.h>
#include <crm/pengine/internal.h>
#include <crm/msg_xml.h>
#include <crm/pengine/pe_types.h>

#include "crm_mon.h"

static char *
time_t_string(time_t when) {
    crm_time_t *crm_when = crm_time_new(NULL);
    char *buf = NULL;

    crm_time_set_timet(crm_when, &when);
    buf = crm_time_as_string(crm_when, crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);
    crm_time_free(crm_when);
    return buf;
}

static char *
failed_action_string(xmlNodePtr xml_op) {
    const char *op_key = crm_element_value(xml_op, XML_LRM_ATTR_TASK_KEY);
    int rc = crm_parse_int(crm_element_value(xml_op, XML_LRM_ATTR_RC), "0");
    int status = crm_parse_int(crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS), "0");
    const char *exit_reason = crm_element_value(xml_op, XML_LRM_ATTR_EXIT_REASON);

    time_t last_change = 0;
    
    if (crm_element_value_epoch(xml_op, XML_RSC_OP_LAST_CHANGE,
                                &last_change) == pcmk_ok) {
        char *time = time_t_string(last_change);
        char *buf = crm_strdup_printf("%s on %s '%s' (%d): call=%s, status='%s', exitreason='%s', last-rc-change='%s', queued=%sms, exec=%sms",
                                      op_key ? op_key : ID(xml_op),
                                      crm_element_value(xml_op, XML_ATTR_UNAME),
                                      services_ocf_exitcode_str(rc), rc,
                                      crm_element_value(xml_op, XML_LRM_ATTR_CALLID),
                                      services_lrm_status_str(status),
                                      exit_reason ? exit_reason : "none",
                                      time,
                                      crm_element_value(xml_op, XML_RSC_OP_T_QUEUE),
                                      crm_element_value(xml_op, XML_RSC_OP_T_EXEC));

        free(time);
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

static char *
op_history_string(xmlNode *xml_op, const char *task, const char *interval_ms_s,
                  int rc, unsigned int mon_ops) {
    const char *call = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);
    char *interval_str = NULL;
    char *buf = NULL;

    if (interval_ms_s && safe_str_neq(interval_ms_s, "0")) {
        char *pair = pcmk_format_nvpair("interval", interval_ms_s, "ms");
        interval_str = crm_strdup_printf(" %s", pair);
        free(pair);
    }

    if (is_set(mon_ops, mon_op_print_timing)) {
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

static int
failed_action_console(pcmk__output_t *out, va_list args) {
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);
    char *s = failed_action_string(xml_op);

    curses_indented_printf(out, "%s\n", s);
    free(s);
    return 0;
}

static int
failed_action_html(pcmk__output_t *out, va_list args) {
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);
    char *s = failed_action_string(xml_op);

    pcmk__output_create_html_node(out, "li", NULL, NULL, s);
    free(s);
    return 0;
}

static int
failed_action_text(pcmk__output_t *out, va_list args) {
    xmlNodePtr xml_op = va_arg(args, xmlNodePtr);
    char *s = failed_action_string(xml_op);

    pcmk__indented_printf(out, "%s\n", s);
    free(s);
    return 0;
}

static int
failed_action_xml(pcmk__output_t *out, va_list args) {
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
        char *s = crm_itoa(crm_parse_ms(crm_element_value(xml_op, XML_LRM_ATTR_INTERVAL_MS)));
        char *rc_change = time_t_string(crm_parse_int(last, "0"));

        xmlSetProp(node, (pcmkXmlStr) "last-rc-change", (pcmkXmlStr) rc_change);
        xmlSetProp(node, (pcmkXmlStr) "queued",
                   (pcmkXmlStr) crm_element_value(xml_op, XML_RSC_OP_T_QUEUE));
        xmlSetProp(node, (pcmkXmlStr) "exec",
                   (pcmkXmlStr) crm_element_value(xml_op, XML_RSC_OP_T_EXEC));
        xmlSetProp(node, (pcmkXmlStr) "interval", (pcmkXmlStr) s);
        xmlSetProp(node, (pcmkXmlStr) "task",
                   (pcmkXmlStr) crm_element_value(xml_op, XML_LRM_ATTR_TASK));

        free(s);
        free(rc_change);
    }

    free(reason_s);
    free(rc_s);
    return 0;
}

static int
node_html(pcmk__output_t *out, va_list args) {
    node_t *node = va_arg(args, node_t *);
    unsigned int mon_ops = va_arg(args, unsigned int);
    gboolean full = va_arg(args, gboolean);

    char *node_name = pe__node_display_name(node, is_set(mon_ops, mon_op_print_clone_detail));
    char *buf = crm_strdup_printf("Node: %s", node_name);
    int print_opts = get_resource_display_options(mon_ops, mon_output_html);

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
        if (is_set(mon_ops, mon_op_print_brief) && is_set(mon_ops, mon_op_group_by_node)) {
            out->begin_list(out, NULL, NULL, NULL);
            pe__rscs_brief_output(out, node->details->running_rsc, print_opts | pe_print_rsconly,
                                  FALSE);
            out->end_list(out);

        } else if (is_set(mon_ops, mon_op_group_by_node)) {
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

static int
node_text(pcmk__output_t *out, va_list args) {
    node_t *node = va_arg(args, node_t *);
    unsigned int mon_ops = va_arg(args, unsigned int);
    gboolean full = va_arg(args, gboolean);

    if (full) {
        const char *node_mode = va_arg(args, const char *);

        char *node_name = pe__node_display_name(node, is_set(mon_ops, mon_op_print_clone_detail));
        int print_opts = get_resource_display_options(mon_ops, mon_output_xml);
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
        if (is_set(mon_ops, mon_op_group_by_node)) {
            out->begin_list(out, NULL, NULL, "%s", buf);
            out->begin_list(out, NULL, NULL, "Resources");

            if (is_set(mon_ops, mon_op_print_brief)) {
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
        out->begin_list(out, NULL, NULL, "Node: %s", pe__node_display_name(node, is_set(mon_ops, mon_op_print_clone_detail)));
    }

    return 0;
}

static int
node_xml(pcmk__output_t *out, va_list args) {
    node_t *node = va_arg(args, node_t *);
    unsigned int mon_ops G_GNUC_UNUSED = va_arg(args, unsigned int);
    gboolean full = va_arg(args, gboolean);

    if (full) {
        const char *node_type = "unknown";
        int print_opts = get_resource_display_options(mon_ops, mon_output_xml);
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

        if (is_set(mon_ops, mon_op_group_by_node)) {
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

static int
op_history_text(pcmk__output_t *out, va_list args) {
    xmlNode *xml_op = va_arg(args, xmlNode *);
    const char *task = va_arg(args, const char *);
    const char *interval_ms_s = va_arg(args, const char *);
    int rc = va_arg(args, int);
    unsigned int mon_ops = va_arg(args, unsigned int);

    char *buf = op_history_string(xml_op, task, interval_ms_s, rc, mon_ops);

    out->list_item(out, NULL, "%s", buf);

    free(buf);
    return 0;
}

static int
op_history_xml(pcmk__output_t *out, va_list args) {
    xmlNode *xml_op = va_arg(args, xmlNode *);
    const char *task = va_arg(args, const char *);
    const char *interval_ms_s = va_arg(args, const char *);
    int rc = va_arg(args, int);
    unsigned int mon_ops = va_arg(args, unsigned int);

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

    if (is_set(mon_ops, mon_op_print_timing)) {
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

static int
stonith_event_console(pcmk__output_t *out, va_list args) {
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    int full_history = va_arg(args, int);
    gboolean later_succeeded = va_arg(args, gboolean);

    char *buf = NULL;

    buf = time_t_string(event->completed);

    switch (event->state) {
        case st_failed:
            curses_indented_printf(out, "%s of %s failed: delegate=%s, client=%s, origin=%s, %s='%s %s'\n",
                                   stonith_action_str(event->action), event->target,
                                   event->delegate ? event->delegate : "",
                                   event->client, event->origin,
                                   full_history ? "completed" : "last-failed", buf,
                                   later_succeeded ? "(a later attempt succeeded)" : "");
            break;

        case st_done:
            curses_indented_printf(out, "%s of %s successful: delegate=%s, client=%s, origin=%s, %s='%s'\n",
                                   stonith_action_str(event->action), event->target,
                                   event->delegate ? event->delegate : "",
                                   event->client, event->origin,
                                   full_history ? "completed" : "last-successful", buf);
            break;

        default:
            curses_indented_printf(out, "%s of %s pending: client=%s, origin=%s\n",
                                   stonith_action_str(event->action), event->target,
                                   event->client, event->origin);
            break;
    }

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
    { "ban", "console", pe__ban_text },
    { "bundle", "console", pe__bundle_text },
    { "clone", "console", pe__clone_text },
    { "cluster-counts", "console", pe__cluster_counts_text },
    { "cluster-dc", "console", pe__cluster_dc_text },
    { "cluster-options", "console", pe__cluster_options_text },
    { "cluster-stack", "console", pe__cluster_stack_text },
    { "cluster-times", "console", pe__cluster_times_text },
    { "failed-action", "console", failed_action_console },
    { "failed-action", "html", failed_action_html },
    { "failed-action", "text", failed_action_text },
    { "failed-action", "xml", failed_action_xml },
    { "group", "console", pe__group_text },
    { "node", "console", node_text },
    { "node", "html", node_html },
    { "node", "text", node_text },
    { "node", "xml", node_xml },
    { "node-attribute", "console", pe__node_attribute_text },
    { "op-history", "console", op_history_text },
    { "op-history", "html", op_history_text },
    { "op-history", "text", op_history_text },
    { "op-history", "xml", op_history_xml },
    { "primitive", "console", pe__resource_text },
    { "resource-history", "console", pe__resource_history_text },
    { "stonith-event", "console", stonith_event_console },
    { "ticket", "console", ticket_console },

    { NULL, NULL, NULL }
};

void
crm_mon_register_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
