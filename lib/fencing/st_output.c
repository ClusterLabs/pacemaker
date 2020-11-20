/*
 * Copyright 2019-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <stdarg.h>

#include <crm/stonith-ng.h>
#include <crm/common/iso8601.h>
#include <crm/common/util.h>
#include <crm/common/xml.h>
#include <crm/common/output_internal.h>
#include <crm/common/xml_internal.h>
#include <crm/fencing/internal.h>
#include <crm/pengine/internal.h>

static char *
time_t_string(time_t when) {
    crm_time_t *crm_when = crm_time_new(NULL);
    char *buf = NULL;

    crm_time_set_timet(crm_when, &when);
    buf = crm_time_as_string(crm_when, crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);
    crm_time_free(crm_when);
    return buf;
}

PCMK__OUTPUT_ARGS("failed-fencing-history", "stonith_history_t *", "GList *", "gboolean", "gboolean")
int
stonith__failed_history(pcmk__output_t *out, va_list args) {
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GList *only_node = va_arg(args, GList *);
    gboolean full_history = va_arg(args, gboolean);
    gboolean print_spacer = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    for (stonith_history_t *hp = history; hp; hp = hp->next) {
        if (hp->state != st_failed) {
            continue;
        }

        if (!pcmk__str_in_list(only_node, hp->target)) {
            continue;
        }

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Failed Fencing Actions");
        out->message(out, "stonith-event", hp, full_history, stonith__later_succeeded(hp, history));
        out->increment_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("fencing-history", "stonith_history_t *", "GList *", "gboolean", "gboolean")
int
stonith__history(pcmk__output_t *out, va_list args) {
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GList *only_node = va_arg(args, GList *);
    gboolean full_history = va_arg(args, gboolean);
    gboolean print_spacer = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    for (stonith_history_t *hp = history; hp; hp = hp->next) {
        if (!pcmk__str_in_list(only_node, hp->target)) {
            continue;
        }

        if (hp->state != st_failed) {
            PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Fencing History");
            out->message(out, "stonith-event", hp, full_history, stonith__later_succeeded(hp, history));
            out->increment_list(out);
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("full-fencing-history", "crm_exit_t", "stonith_history_t *", "GList *", "gboolean", "gboolean")
int
stonith__full_history(pcmk__output_t *out, va_list args) {
    crm_exit_t history_rc G_GNUC_UNUSED = va_arg(args, crm_exit_t);
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GList *only_node = va_arg(args, GList *);
    gboolean full_history = va_arg(args, gboolean);
    gboolean print_spacer = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    for (stonith_history_t *hp = history; hp; hp = hp->next) {
        if (!pcmk__str_in_list(only_node, hp->target)) {
            continue;
        }

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Fencing History");
        out->message(out, "stonith-event", hp, full_history, stonith__later_succeeded(hp, history));
        out->increment_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}
 
PCMK__OUTPUT_ARGS("full-fencing-history", "crm_exit_t", "stonith_history_t *", "GList *", "gboolean", "gboolean")
int
stonith__full_history_xml(pcmk__output_t *out, va_list args) {
    crm_exit_t history_rc = va_arg(args, crm_exit_t);
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GList *only_node = va_arg(args, GList *);
    gboolean full_history = va_arg(args, gboolean);
    gboolean print_spacer G_GNUC_UNUSED = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    if (history_rc == 0) {
        for (stonith_history_t *hp = history; hp; hp = hp->next) {
            if (!pcmk__str_in_list(only_node, hp->target)) {
                continue;
            }

            PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc, "Fencing History");
            out->message(out, "stonith-event", hp, full_history, stonith__later_succeeded(hp, history));
            out->increment_list(out);
        }

        PCMK__OUTPUT_LIST_FOOTER(out, rc);
    } else {
        char *rc_s = crm_itoa(history_rc);

        pcmk__output_create_xml_node(out, "fence_history",
                                     "status", rc_s,
                                     NULL);
        free(rc_s);

        rc = pcmk_rc_ok;
    }

    return rc;
}

PCMK__OUTPUT_ARGS("last-fenced", "const char *", "time_t")
int
stonith__last_fenced_html(pcmk__output_t *out, va_list args) {
    const char *target = va_arg(args, const char *);
    time_t when = va_arg(args, time_t);

    if (when) {
        char *buf = crm_strdup_printf("Node %s last fenced at: %s", target, ctime(&when));
        pcmk__output_create_html_node(out, "div", NULL, NULL, buf);
        free(buf);
        return pcmk_rc_ok;
    } else {
        return pcmk_rc_no_output;
    }
}

PCMK__OUTPUT_ARGS("last-fenced", "const char *", "time_t")
int
stonith__last_fenced_text(pcmk__output_t *out, va_list args) {
    const char *target = va_arg(args, const char *);
    time_t when = va_arg(args, time_t);

    if (when) {
        pcmk__indented_printf(out, "Node %s last fenced at: %s", target, ctime(&when));
    } else {
        pcmk__indented_printf(out, "Node %s has never been fenced\n", target);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("last-fenced", "const char *", "time_t")
int
stonith__last_fenced_xml(pcmk__output_t *out, va_list args) {
    const char *target = va_arg(args, const char *);
    time_t when = va_arg(args, time_t);

    if (when) {
        char *buf = time_t_string(when);

        pcmk__output_create_xml_node(out, "last-fenced",
                                     "target", target,
                                     "when", buf,
                                     NULL);

        free(buf);
        return pcmk_rc_ok;
    } else {
        return pcmk_rc_no_output;
    }
}

PCMK__OUTPUT_ARGS("pending-fencing-actions", "stonith_history_t *", "GList *", "gboolean", "gboolean")
int
stonith__pending_actions(pcmk__output_t *out, va_list args) {
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GList *only_node = va_arg(args, GList *);
    gboolean full_history = va_arg(args, gboolean);
    gboolean print_spacer = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    for (stonith_history_t *hp = history; hp; hp = hp->next) {
        if (!pcmk__str_in_list(only_node, hp->target)) {
            continue;
        }

        /* Skip the rest of the history after we see a failed/done action */
        if ((hp->state == st_failed) || (hp->state == st_done)) {
            break;
        }

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Pending Fencing Actions");
        out->message(out, "stonith-event", hp, full_history, stonith__later_succeeded(hp, history));
        out->increment_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("stonith-event", "stonith_history_t *", "gboolean", "gboolean")
int
stonith__event_html(pcmk__output_t *out, va_list args) {
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    gboolean full_history = va_arg(args, gboolean);
    gboolean later_succeeded = va_arg(args, gboolean);

    switch(event->state) {
        case st_done: {
            char *completed_s = time_t_string(event->completed);

            out->list_item(out, "successful-stonith-event",
                           "%s of %s successful: delegate=%s, client=%s, origin=%s, %s='%s'",
                           stonith_action_str(event->action), event->target,
                           event->delegate ? event->delegate : "",
                           event->client, event->origin,
                           full_history ? "completed" : "last-successful",
                           completed_s);
            free(completed_s);
            break;
        }

        case st_failed: {
            char *failed_s = time_t_string(event->completed);

            out->list_item(out, "failed-stonith-event",
                           "%s of %s failed : delegate=%s, client=%s, origin=%s, %s='%s' %s",
                           stonith_action_str(event->action), event->target,
                           event->delegate ? event->delegate : "",
                           event->client, event->origin,
                           full_history ? "completed" : "last-failed",
                           failed_s,
                           later_succeeded ? "(a later attempt succeeded)" : "");
            free(failed_s);
            break;
        }

        default:
            out->list_item(out, "pending-stonith-event",
                           "%s of %s pending: client=%s, origin=%s",
                           stonith_action_str(event->action), event->target,
                           event->client, event->origin);
            break;
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("stonith-event", "stonith_history_t *", "gboolean", "gboolean")
int
stonith__event_text(pcmk__output_t *out, va_list args) {
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    gboolean full_history = va_arg(args, gboolean);
    gboolean later_succeeded = va_arg(args, gboolean);

    char *buf = time_t_string(event->completed);

    switch (event->state) {
        case st_failed:
            pcmk__indented_printf(out, "%s of %s failed: delegate=%s, client=%s, origin=%s, %s='%s' %s\n",
                                  stonith_action_str(event->action), event->target,
                                  event->delegate ? event->delegate : "",
                                  event->client, event->origin,
                                  full_history ? "completed" : "last-failed", buf,
                                  later_succeeded ? "(a later attempt succeeded)" : "");
            break;

        case st_done:
            pcmk__indented_printf(out, "%s of %s successful: delegate=%s, client=%s, origin=%s, %s='%s'\n",
                                  stonith_action_str(event->action), event->target,
                                  event->delegate ? event->delegate : "",
                                  event->client, event->origin,
                                  full_history ? "completed" : "last-successful", buf);
            break;

        default:
            pcmk__indented_printf(out, "%s of %s pending: client=%s, origin=%s\n",
                                  stonith_action_str(event->action), event->target,
                                  event->client, event->origin);
            break;
    }

    free(buf);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("stonith-event", "stonith_history_t *", "gboolean", "gboolean")
int
stonith__event_xml(pcmk__output_t *out, va_list args) {
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    gboolean full_history G_GNUC_UNUSED = va_arg(args, gboolean);
    gboolean later_succeeded G_GNUC_UNUSED = va_arg(args, gboolean);

    char *buf = NULL;

    xmlNodePtr node = pcmk__output_create_xml_node(out, "fence_event",
                                                   "action", event->action,
                                                   "target", event->target,
                                                   "client", event->client,
                                                   "origin", event->origin,
                                                   NULL);

    switch (event->state) {
        case st_failed:
            crm_xml_add(node, "status", "failed");
            break;

        case st_done:
            crm_xml_add(node, "status", "success");
            break;

        default: {
            char *state = crm_itoa(event->state);
            pcmk__xe_set_props(node, "status", "pending",
                               "extended-status", state,
                               NULL);
            free(state);
            break;
        }
    }

    if (event->delegate != NULL) {
        crm_xml_add(node, "delegate", event->delegate);
    }

    if (event->state == st_failed || event->state == st_done) {
        buf = time_t_string(event->completed);
        crm_xml_add(node, "completed", buf);
        free(buf);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("validate", "const char *", "const char *", "char *", "char *", "int")
int
stonith__validate_agent_html(pcmk__output_t *out, va_list args) {
    const char *agent = va_arg(args, const char *);
    const char *device = va_arg(args, const char *);
    char *output = va_arg(args, char *);
    char *error_output = va_arg(args, char *);
    int rc = va_arg(args, int);

    if (device) {
        char *buf = crm_strdup_printf("Validation of %s on %s %s", agent, device,
                                      rc ? "failed" : "succeeded");
        pcmk__output_create_html_node(out, "div", NULL, NULL, buf);
        free(buf);
    } else {
        char *buf = crm_strdup_printf("Validation of %s %s", agent,
                                      rc ? "failed" : "succeeded");
        pcmk__output_create_html_node(out, "div", NULL, NULL, buf);
        free(buf);
    }

    out->subprocess_output(out, rc, output, error_output);
    return rc;
}

PCMK__OUTPUT_ARGS("validate", "const char *", "const char *", "char *", "char *", "int")
int
stonith__validate_agent_text(pcmk__output_t *out, va_list args) {
    const char *agent = va_arg(args, const char *);
    const char *device = va_arg(args, const char *);
    char *output = va_arg(args, char *);
    char *error_output = va_arg(args, char *);
    int rc = va_arg(args, int);

    if (device) {
        pcmk__indented_printf(out, "Validation of %s on %s %s\n", agent, device,
                              rc ? "failed" : "succeeded");
    } else {
        pcmk__indented_printf(out, "Validation of %s %s\n", agent,
                              rc ? "failed" : "succeeded");
    }

    if (output) {
        puts(output);
    }

    if (error_output) {
        puts(error_output);
    }

    return rc;
}

PCMK__OUTPUT_ARGS("validate", "const char *", "const char *", "char *", "char *", "int")
int
stonith__validate_agent_xml(pcmk__output_t *out, va_list args) {
    const char *agent = va_arg(args, const char *);
    const char *device = va_arg(args, const char *);
    char *output = va_arg(args, char *);
    char *error_output = va_arg(args, char *);
    int rc = va_arg(args, int);

    xmlNodePtr node = pcmk__output_create_xml_node(out, "validate",
                                                   "agent", agent,
                                                   "valid", pcmk__btoa(rc),
                                                   NULL);

    if (device != NULL) {
        crm_xml_add(node, "device", device);
    }

    pcmk__output_xml_push_parent(out, node);
    out->subprocess_output(out, rc, output, error_output);
    pcmk__output_xml_pop_parent(out);

    return rc;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "failed-fencing-history", "default", stonith__failed_history },
    { "fencing-history", "default", stonith__history },
    { "full-fencing-history", "default", stonith__full_history },
    { "full-fencing-history", "xml", stonith__full_history_xml },
    { "last-fenced", "html", stonith__last_fenced_html },
    { "last-fenced", "log", stonith__last_fenced_text },
    { "last-fenced", "text", stonith__last_fenced_text },
    { "last-fenced", "xml", stonith__last_fenced_xml },
    { "pending-fencing-actions", "default", stonith__pending_actions },
    { "stonith-event", "html", stonith__event_html },
    { "stonith-event", "log", stonith__event_text },
    { "stonith-event", "text", stonith__event_text },
    { "stonith-event", "xml", stonith__event_xml },
    { "validate", "html", stonith__validate_agent_html },
    { "validate", "log", stonith__validate_agent_text },
    { "validate", "text", stonith__validate_agent_text },
    { "validate", "xml", stonith__validate_agent_xml },

    { NULL, NULL, NULL }
};

void
stonith__register_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
