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

static int
fence_target_text(pcmk__output_t *out, va_list args) {
    const char *hostname = va_arg(args, const char *);
    const char *uuid = va_arg(args, const char *);
    const char *status = va_arg(args, const char *);

    pcmk__indented_printf(out, "%s\t%s\t%s\n", hostname, uuid, status);
    return 0;
}

static int
fence_target_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = NULL;
    const char *hostname = va_arg(args, const char *);
    const char *uuid = va_arg(args, const char *);
    const char *status = va_arg(args, const char *);

    node = xmlNewNode(NULL, (pcmkXmlStr) "target");
    xmlSetProp(node, (pcmkXmlStr) "hostname", (pcmkXmlStr) hostname);
    xmlSetProp(node, (pcmkXmlStr) "uuid", (pcmkXmlStr) uuid);
    xmlSetProp(node, (pcmkXmlStr) "status", (pcmkXmlStr) status);

    pcmk__xml_add_node(out, node);
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
        crm_time_t *crm_when = crm_time_new(NULL);
        xmlNodePtr node = xmlNewNode(NULL, (pcmkXmlStr) "last-fenced");
        char *buf = NULL;

        crm_time_set_timet(crm_when, &when);
        buf = crm_time_as_string(crm_when, crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);

        xmlSetProp(node, (pcmkXmlStr) "target", (pcmkXmlStr) target);
        xmlSetProp(node, (pcmkXmlStr) "when", (pcmkXmlStr) buf);

        pcmk__xml_add_node(out, node);

        crm_time_free(crm_when);
        free(buf);
    }

    return 0;
}

static int
stonith_event_text(pcmk__output_t *out, va_list args) {
    stonith_history_t *event = va_arg(args, stonith_history_t *);

    switch (event->state) {
        case st_failed:
            pcmk__indented_printf(out, "%s failed %s node %s on behalf of %s from %s at %s",
                                  event->delegate ? event->delegate : "We",
                                  stonith_action_str(event->action), event->target,
                                  event->client, event->origin, ctime(&event->completed));
            break;

        case st_done:
            pcmk__indented_printf(out, "%s succeeded %s node %s on behalf of %s from %s at %s",
                                  event->delegate ? event->delegate : "This node",
                                  stonith_action_str(event->action), event->target,
                                  event->client, event->origin, ctime(&event->completed));
            break;

        default:
            /* ocf:pacemaker:controld depends on "wishes to" being
             * in this output, when used with older versions of DLM
             * that don't report stateful_merge_wait
             */
            pcmk__indented_printf(out, "%s at %s wishes to %s node %s - %d %lld\n",
                                  event->client, event->origin, stonith_action_str(event->action),
                                  event->target, event->state, (long long) event->completed);
            break;
    }

    return 0;
}

static int
stonith_event_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = NULL;
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    crm_time_t *crm_when = crm_time_new(NULL);
    char *buf = NULL;

    node = xmlNewNode(NULL, (pcmkXmlStr) "stonith-event");

    switch (event->state) {
        case st_failed:
            xmlSetProp(node, (pcmkXmlStr) "status", (pcmkXmlStr) "failed");
            break;

        case st_done:
            xmlSetProp(node, (pcmkXmlStr) "status", (pcmkXmlStr) "done");
            break;

        default: {
            char *state = crm_itoa(event->state);
            xmlSetProp(node, (pcmkXmlStr) "status", (pcmkXmlStr) state);
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

    crm_time_set_timet(crm_when, &event->completed);
    buf = crm_time_as_string(crm_when, crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);
    xmlSetProp(node, (pcmkXmlStr) "when", (pcmkXmlStr) buf);

    pcmk__xml_add_node(out, node);

    crm_time_free(crm_when);
    free(buf);
    return 0;
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
    xmlNodePtr node = NULL;

    const char *agent = va_arg(args, const char *);
    const char *device = va_arg(args, const char *);
    const char *output = va_arg(args, const char *);
    const char *error_output = va_arg(args, const char *);
    int rc = va_arg(args, int);

    node = xmlNewNode(NULL, (pcmkXmlStr) "validate");
    xmlSetProp(node, (pcmkXmlStr) "agent", (pcmkXmlStr) agent);
    if (device != NULL) {
        xmlSetProp(node, (pcmkXmlStr) "device", (pcmkXmlStr) device);
    }
    xmlSetProp(node, (pcmkXmlStr) "valid", (pcmkXmlStr) (rc ? "false" : "true"));

    pcmk__xml_push_parent(out, node);
    out->subprocess_output(out, rc, output, error_output);
    pcmk__xml_pop_parent(out);

    pcmk__xml_add_node(out, node);
    return rc;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "fence-target", "text", fence_target_text },
    { "fence-target", "xml", fence_target_xml },
    { "last-fenced", "text", last_fenced_text },
    { "last-fenced", "xml", last_fenced_xml },
    { "stonith-event", "text", stonith_event_text },
    { "stonith-event", "xml", stonith_event_xml },
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
