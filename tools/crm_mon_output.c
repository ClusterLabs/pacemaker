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

        buf = crm_strdup_printf("%s on %s '%s' (%d): call=%s, status='%s', exitreason='%s', last-rc-change='%s', queued=%sms, exec=%sms",
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
        time_t when = crm_parse_int(last, "0");
        crm_time_t *crm_when = crm_time_new(NULL);
        char *rc_change = NULL;

        crm_time_set_timet(crm_when, &when);
        rc_change = crm_time_as_string(crm_when, crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);

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
        crm_time_free(crm_when);
    }

    free(reason_s);
    free(rc_s);
    return 0;
}

static int
stonith_event_console(pcmk__output_t *out, va_list args) {
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    int full_history = va_arg(args, int);
    gboolean later_succeeded = va_arg(args, gboolean);

    crm_time_t *crm_when = crm_time_new(NULL);
    char *buf = NULL;

    crm_time_set_timet(crm_when, &(event->completed));
    buf = crm_time_as_string(crm_when, crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);

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
    crm_time_free(crm_when);
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
    { "node", "console", pe__node_text },
    { "node-attribute", "console", pe__node_attribute_text },
    { "op-history", "console", pe__op_history_text },
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
