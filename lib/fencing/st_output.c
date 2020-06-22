/*
 * Copyright 2019 the Pacemaker project contributors
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
#include <crm/common/output.h>
#include <crm/common/util.h>
#include <crm/common/xml.h>
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

PCMK__OUTPUT_ARGS("failed-fencing-history", "struct stonith_history_t *", "GListPtr", "gboolean", "gboolean")
int
stonith__failed_history(pcmk__output_t *out, va_list args) {
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GListPtr only_show = va_arg(args, GListPtr);
    gboolean full_history = va_arg(args, gboolean);
    gboolean print_spacer = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    for (stonith_history_t *hp = history; hp; hp = hp->next) {
        if (hp->state != st_failed) {
            continue;
        }

        if (!pcmk__str_in_list(only_show, hp->target)) {
            continue;
        }

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Failed Fencing Actions");
        out->message(out, "stonith-event", hp, full_history, stonith__later_succeeded(hp, history));
        out->increment_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("fencing-history", "struct stonith_history_t *", "GListPtr", "gboolean", "gboolean")
int
stonith__history(pcmk__output_t *out, va_list args) {
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GListPtr only_show = va_arg(args, GListPtr);
    gboolean full_history = va_arg(args, gboolean);
    gboolean print_spacer = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    for (stonith_history_t *hp = history; hp; hp = hp->next) {
        if (!pcmk__str_in_list(only_show, hp->target)) {
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

PCMK__OUTPUT_ARGS("full-fencing-history", "crm_exit_t", "struct stonith_history_t *", "GListPtr", "gboolean", "gboolean")
int
stonith__full_history(pcmk__output_t *out, va_list args) {
    crm_exit_t history_rc G_GNUC_UNUSED = va_arg(args, crm_exit_t);
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GListPtr only_show = va_arg(args, GListPtr);
    gboolean full_history = va_arg(args, gboolean);
    gboolean print_spacer = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    for (stonith_history_t *hp = history; hp; hp = hp->next) {
        if (!pcmk__str_in_list(only_show, hp->target)) {
            continue;
        }

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Fencing History");
        out->message(out, "stonith-event", hp, full_history, stonith__later_succeeded(hp, history));
        out->increment_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}
 
PCMK__OUTPUT_ARGS("full-fencing-history", "crm_exit_t", "struct stonith_history_t *", "GListPtr", "gboolean", "gboolean")
int
stonith__full_history_xml(pcmk__output_t *out, va_list args) {
    crm_exit_t history_rc = va_arg(args, crm_exit_t);
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GListPtr only_show = va_arg(args, GListPtr);
    gboolean full_history = va_arg(args, gboolean);
    gboolean print_spacer G_GNUC_UNUSED = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    if (history_rc == 0) {
        for (stonith_history_t *hp = history; hp; hp = hp->next) {
            if (!pcmk__str_in_list(only_show, hp->target)) {
                continue;
            }

            PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc, "Fencing History");
            out->message(out, "stonith-event", hp, full_history, stonith__later_succeeded(hp, history));
            out->increment_list(out);
        }

        PCMK__OUTPUT_LIST_FOOTER(out, rc);
    } else {
        xmlNodePtr node = pcmk__output_create_xml_node(out, "fence_history");
        char *rc_s = crm_itoa(history_rc);

        xmlSetProp(node, (pcmkXmlStr) "status", (pcmkXmlStr) rc_s);
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
        xmlNodePtr node = pcmk__output_create_xml_node(out, "last-fenced");
        char *buf = time_t_string(when);

        xmlSetProp(node, (pcmkXmlStr) "target", (pcmkXmlStr) target);
        xmlSetProp(node, (pcmkXmlStr) "when", (pcmkXmlStr) buf);

        free(buf);
        return pcmk_rc_ok;
    } else {
        return pcmk_rc_no_output;
    }
}

PCMK__OUTPUT_ARGS("pending-fencing-actions", "struct stonith_history_t *", "GListPtr", "gboolean", "gboolean")
int
stonith__pending_actions(pcmk__output_t *out, va_list args) {
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GListPtr only_show = va_arg(args, GListPtr);
    gboolean full_history = va_arg(args, gboolean);
    gboolean print_spacer = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    for (stonith_history_t *hp = history; hp; hp = hp->next) {
        if (!pcmk__str_in_list(only_show, hp->target)) {
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

PCMK__OUTPUT_ARGS("stonith-event", "struct stonith_history_t *", "gboolean", "gboolean")
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

PCMK__OUTPUT_ARGS("stonith-event", "struct stonith_history_t *", "gboolean", "gboolean")
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

PCMK__OUTPUT_ARGS("stonith-event", "struct stonith_history_t *", "gboolean", "gboolean")
int
stonith__event_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "fence_event");
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    gboolean full_history G_GNUC_UNUSED = va_arg(args, gboolean);
    gboolean later_succeeded G_GNUC_UNUSED = va_arg(args, gboolean);

    char *buf = NULL;

    switch (event->state) {
        case st_failed:
            xmlSetProp(node, (pcmkXmlStr) "status", (pcmkXmlStr) "failed");
            break;

        case st_done:
            xmlSetProp(node, (pcmkXmlStr) "status", (pcmkXmlStr) "success");
            break;

        default: {
            char *state = crm_itoa(event->state);
            xmlSetProp(node, (pcmkXmlStr) "status", (pcmkXmlStr) "pending");
            xmlSetProp(node, (pcmkXmlStr) "extended-status", (pcmkXmlStr) state);
            free(state);
            break;
        }
    }

    if (event->delegate != NULL) {
        xmlSetProp(node, (pcmkXmlStr) "delegate", (pcmkXmlStr) event->delegate);
    }

    xmlSetProp(node, (pcmkXmlStr) "action", (pcmkXmlStr) event->action);
    xmlSetProp(node, (pcmkXmlStr) "target", (pcmkXmlStr) event->target);
    xmlSetProp(node, (pcmkXmlStr) "client", (pcmkXmlStr) event->client);
    xmlSetProp(node, (pcmkXmlStr) "origin", (pcmkXmlStr) event->origin);

    if (event->state == st_failed || event->state == st_done) {
        buf = time_t_string(event->completed);
        xmlSetProp(node, (pcmkXmlStr) "completed", (pcmkXmlStr) buf);
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
    xmlNodePtr node = pcmk__output_create_xml_node(out, "validate");

    const char *agent = va_arg(args, const char *);
    const char *device = va_arg(args, const char *);
    char *output = va_arg(args, char *);
    char *error_output = va_arg(args, char *);
    int rc = va_arg(args, int);

    xmlSetProp(node, (pcmkXmlStr) "agent", (pcmkXmlStr) agent);
    if (device != NULL) {
        xmlSetProp(node, (pcmkXmlStr) "device", (pcmkXmlStr) device);
    }
    xmlSetProp(node, (pcmkXmlStr) "valid", (pcmkXmlStr) (rc ? "false" : "true"));

    pcmk__output_xml_push_parent(out, node);
    out->subprocess_output(out, rc, output, error_output);
    pcmk__output_xml_pop_parent(out);

    return rc;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "failed-fencing-history", "html", stonith__failed_history },
    { "failed-fencing-history", "log", stonith__failed_history },
    { "failed-fencing-history", "text", stonith__failed_history },
    { "failed-fencing-history", "xml", stonith__failed_history },
    { "fencing-history", "html", stonith__history },
    { "fencing-history", "log", stonith__history },
    { "fencing-history", "text", stonith__history },
    { "fencing-history", "xml", stonith__history },
    { "full-fencing-history", "html", stonith__full_history },
    { "full-fencing-history", "log", stonith__full_history },
    { "full-fencing-history", "text", stonith__full_history },
    { "full-fencing-history", "xml", stonith__full_history_xml },
    { "last-fenced", "html", stonith__last_fenced_html },
    { "last-fenced", "log", stonith__last_fenced_text },
    { "last-fenced", "text", stonith__last_fenced_text },
    { "last-fenced", "xml", stonith__last_fenced_xml },
    { "pending-fencing-actions", "html", stonith__pending_actions },
    { "pending-fencing-actions", "log", stonith__pending_actions },
    { "pending-fencing-actions", "text", stonith__pending_actions },
    { "pending-fencing-actions", "xml", stonith__pending_actions },
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
