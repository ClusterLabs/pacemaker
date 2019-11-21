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
    { "failed-action", "console", pe__failed_action_text },
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
