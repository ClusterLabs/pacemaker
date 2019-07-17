/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <stdarg.h>

#include <crm/stonith-ng.h>
#include <crm/common/iso8601.h>
#include <crm/common/output.h>
#include <crm/common/util.h>
#include <crm/common/xml.h>
#include <crm/fencing/internal.h>

static char *
time_t_string(time_t when) {
    crm_time_t *crm_when = crm_time_new(NULL);
    char *buf = NULL;

    crm_time_set_timet(crm_when, &when);
    buf = crm_time_as_string(crm_when, crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);
    crm_time_free(crm_when);
    return buf;
}

static int
last_fenced_html(pcmk__output_t *out, va_list args) {
    const char *target = va_arg(args, const char *);
    time_t when = va_arg(args, time_t);

    if (when) {
        char *buf = crm_strdup_printf("Node %s last fenced at: %s", target, ctime(&when));
        pcmk__output_create_html_node(out, "div", NULL, NULL, buf);
        free(buf);
    }

    return 0;
}

static int
last_fenced_text(pcmk__output_t *out, va_list args) {
    const char *target = va_arg(args, const char *);
    time_t when = va_arg(args, time_t);

    if (when) {
        pcmk__indented_printf(out, "Node %s last fenced at: %s", target, ctime(&when));
    } else {
        pcmk__indented_printf(out, "Node %s has never been fenced\n", target);
    }

    return 0;
}

static int
last_fenced_xml(pcmk__output_t *out, va_list args) {
    const char *target = va_arg(args, const char *);
    time_t when = va_arg(args, time_t);

    if (when) {
        xmlNodePtr node = pcmk__output_create_xml_node(out, "last-fenced");
        char *buf = time_t_string(when);

        xmlSetProp(node, (pcmkXmlStr) "target", (pcmkXmlStr) target);
        xmlSetProp(node, (pcmkXmlStr) "when", (pcmkXmlStr) buf);

        free(buf);
    }

    return 0;
}

static int
stonith_event_html(pcmk__output_t *out, va_list args) {
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    int full_history = va_arg(args, int);
    char *buf = NULL;

    switch(event->state) {
        case st_done:
            buf = crm_strdup_printf("%s of %s successful: delegate=%s, client=%s, origin=%s, %s='%s'",
                                    stonith_action_str(event->action), event->target,
                                    event->delegate ? event->delegate : "",
                                    event->client, event->origin,
                                    full_history ? "completed" : "last-successful",
                                    time_t_string(event->completed));
            out->list_item(out, "successful-stonith-event", buf);
            free(buf);
            break;

        case st_failed:
            buf = crm_strdup_printf("%s of %s failed : delegate=%s, client=%s, origin=%s, %s='%s'",
                                    stonith_action_str(event->action), event->target,
                                    event->delegate ? event->delegate : "",
                                    event->client, event->origin,
                                    full_history ? "completed" : "last-failed",
                                    time_t_string(event->completed));
            out->list_item(out, "failed-stonith-event", buf);
            free(buf);
            break;

        default:
            buf = crm_strdup_printf("%s of %s pending: client=%s, origin=%s",
                                    stonith_action_str(event->action), event->target,
                                    event->client, event->origin);
            out->list_item(out, "pending-stonith-event", buf);
            free(buf);
            break;
    }

    return 0;
}

static int
stonith_event_text(pcmk__output_t *out, va_list args) {
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    int full_history = va_arg(args, int);
    char *buf = time_t_string(event->completed);

    switch (event->state) {
        case st_failed:
            pcmk__indented_printf(out, "%s of %s failed: delegate=%s, client=%s, origin=%s, %s='%s'\n",
                                  stonith_action_str(event->action), event->target,
                                  event->delegate ? event->delegate : "",
                                  event->client, event->origin,
                                  full_history ? "completed" : "last-failed", buf);
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
    return 0;
}

static int
stonith_event_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "fence_event");
    stonith_history_t *event = va_arg(args, stonith_history_t *);
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

    return 0;
}

static int
validate_agent_html(pcmk__output_t *out, va_list args) {
    const char *agent = va_arg(args, const char *);
    const char *device = va_arg(args, const char *);
    const char *output = va_arg(args, const char *);
    const char *error_output = va_arg(args, const char *);
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

static int
validate_agent_text(pcmk__output_t *out, va_list args) {
    const char *agent = va_arg(args, const char *);
    const char *device = va_arg(args, const char *);
    const char *output = va_arg(args, const char *);
    const char *error_output = va_arg(args, const char *);
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

static int
validate_agent_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = pcmk__output_create_xml_node(out, "validate");

    const char *agent = va_arg(args, const char *);
    const char *device = va_arg(args, const char *);
    const char *output = va_arg(args, const char *);
    const char *error_output = va_arg(args, const char *);
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
    { "last-fenced", "html", last_fenced_html },
    { "last-fenced", "text", last_fenced_text },
    { "last-fenced", "xml", last_fenced_xml },
    { "stonith-event", "html", stonith_event_html },
    { "stonith-event", "text", stonith_event_text },
    { "stonith-event", "xml", stonith_event_xml },
    { "validate", "html", validate_agent_html },
    { "validate", "text", validate_agent_text },
    { "validate", "xml", validate_agent_xml },

    { NULL, NULL, NULL }
};

void
stonith__register_messages(pcmk__output_t *out) {
    static bool registered = FALSE;

    if (!registered) {
        pcmk__register_messages(out, fmt_functions);
        registered = TRUE;
    }
}
