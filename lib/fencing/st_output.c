/*
 * Copyright 2019-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <stdarg.h>
#include <stdint.h>

#include <crm/stonith-ng.h>
#include <crm/msg_xml.h>
#include <crm/common/iso8601.h>
#include <crm/common/util.h>
#include <crm/common/xml.h>
#include <crm/common/output.h>
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

/*!
 * \internal
 * \brief Return a status-friendly description of fence history entry state
 *
 * \param[in] history  Fence history entry to describe
 *
 * \return One-word description of history entry state
 * \note This is similar to stonith_op_state_str() except user-oriented (i.e.
 *       for cluster status) instead of developer-oriented (for debug logs).
 */
static const char *
state_str(stonith_history_t *history)
{
    switch (history->state) {
        case st_failed: return "failed";
        case st_done:   return "successful";
        default:        return "pending";
    }
}

/*!
 * \internal
 * \brief Create a description of a fencing history entry for status displays
 *
 * \param[in] history          Fencing history entry to describe
 * \param[in] full_history     Whether this is for full or condensed history
 * \param[in] later_succeeded  Node that a later equivalent attempt succeeded
 *                             from, or NULL if none
 * \param[in] show_opts        Flag group of pcmk_show_opt_e
 *
 * \return Newly created string with fencing history entry description
 *
 * \note The caller is responsible for freeing the return value with g_free().
 * \note This is similar to stonith__event_description(), except this is used
 *       for history entries (stonith_history_t) in status displays rather than
 *       event notifications (stonith_event_t) in log messages.
 */
gchar *
stonith__history_description(stonith_history_t *history, bool full_history,
                             const char *later_succeeded, uint32_t show_opts)
{
    GString *str = g_string_sized_new(256); // Generous starting size
    char *retval = NULL;
    char *completed_time = NULL;

    if ((history->state == st_failed) || (history->state == st_done)) {
        completed_time = time_t_string(history->completed);
    }

    g_string_printf(str, "%s of %s",
                    stonith_action_str(history->action), history->target);

    if (!pcmk_is_set(show_opts, pcmk_show_failed_detail)) {
        // More human-friendly
        if (((history->state == st_failed) || (history->state == st_done))
            && (history->delegate != NULL)) {
            g_string_append_printf(str, " by %s", history->delegate);
        }
        g_string_append_printf(str, " for %s@%s",
                               history->client, history->origin);
        if (!full_history) {
            g_string_append(str, " last"); // For example, "last failed at ..."
        }
    }

    g_string_append_printf(str, " %s", state_str(history));

    // For failed actions, add exit reason if available
    if ((history->state == st_failed) && (history->exit_reason != NULL)) {
        g_string_append_printf(str, " (%s)", history->exit_reason);
    }

    if (pcmk_is_set(show_opts, pcmk_show_failed_detail)) {
        // More technical
        g_string_append(str, ": ");

        // For completed actions, add delegate if available
        if (((history->state == st_failed) || (history->state == st_done))
            && (history->delegate != NULL)) {

            g_string_append_printf(str, "delegate=%s, ", history->delegate);
        }

        // Add information about originator
        g_string_append_printf(str, "client=%s, origin=%s",
                               history->client, history->origin);

        // For completed actions, add completion time
        if (completed_time != NULL) {
            if (full_history) {
                g_string_append(str, ", completed");
            } else if (history->state == st_failed) {
                g_string_append(str, ", last-failed");
            } else {
                g_string_append(str, ", last-successful");
            }
            g_string_append_printf(str, "='%s'", completed_time);
        }
    } else { // More human-friendly
        if (completed_time != NULL) {
            g_string_append_printf(str, " at %s", completed_time);
        }
    }

    if ((history->state == st_failed) && (later_succeeded != NULL)) {
        g_string_append_printf(str, " (a later attempt from %s succeeded)",
                               later_succeeded);
    }

    retval = str->str;
    g_string_free(str, FALSE);
    free(completed_time);
    return retval;
}

PCMK__OUTPUT_ARGS("failed-fencing-list", "stonith_history_t *", "GList *",
                  "uint32_t", "uint32_t", "gboolean")
int
stonith__failed_history(pcmk__output_t *out, va_list args)
{
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GList *only_node = va_arg(args, GList *);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);
    gboolean print_spacer = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    for (stonith_history_t *hp = history; hp; hp = hp->next) {
        if (hp->state != st_failed) {
            continue;
        }

        if (!pcmk__str_in_list(hp->target, only_node, pcmk__str_star_matches|pcmk__str_casei)) {
            continue;
        }

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Failed Fencing Actions");
        out->message(out, "stonith-event", hp,
                     pcmk_all_flags_set(section_opts, pcmk_section_fencing_all),
                     stonith__later_succeeded(hp, history), show_opts);
        out->increment_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("fencing-list", "stonith_history_t *", "GList *", "uint32_t",
                  "uint32_t", "gboolean")
int
stonith__history(pcmk__output_t *out, va_list args)
{
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GList *only_node = va_arg(args, GList *);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);
    gboolean print_spacer = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    for (stonith_history_t *hp = history; hp; hp = hp->next) {
        if (!pcmk__str_in_list(hp->target, only_node, pcmk__str_star_matches|pcmk__str_casei)) {
            continue;
        }

        if (hp->state != st_failed) {
            PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Fencing History");
            out->message(out, "stonith-event", hp,
                         pcmk_all_flags_set(section_opts,
                                            pcmk_section_fencing_all),
                         stonith__later_succeeded(hp, history), show_opts);
            out->increment_list(out);
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("full-fencing-list", "crm_exit_t", "stonith_history_t *",
                  "GList *", "uint32_t", "uint32_t", "gboolean")
int
stonith__full_history(pcmk__output_t *out, va_list args)
{
    crm_exit_t history_rc G_GNUC_UNUSED = va_arg(args, crm_exit_t);
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GList *only_node = va_arg(args, GList *);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);
    gboolean print_spacer = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    for (stonith_history_t *hp = history; hp; hp = hp->next) {
        if (!pcmk__str_in_list(hp->target, only_node, pcmk__str_star_matches|pcmk__str_casei)) {
            continue;
        }

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Fencing History");
        out->message(out, "stonith-event", hp,
                     pcmk_all_flags_set(section_opts, pcmk_section_fencing_all),
                     stonith__later_succeeded(hp, history), show_opts);
        out->increment_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("full-fencing-list", "crm_exit_t", "stonith_history_t *",
                  "GList *", "uint32_t", "uint32_t", "gboolean")
static int
full_history_xml(pcmk__output_t *out, va_list args)
{
    crm_exit_t history_rc = va_arg(args, crm_exit_t);
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GList *only_node = va_arg(args, GList *);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);
    gboolean print_spacer G_GNUC_UNUSED = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    if (history_rc == 0) {
        for (stonith_history_t *hp = history; hp; hp = hp->next) {
            if (!pcmk__str_in_list(hp->target, only_node, pcmk__str_star_matches|pcmk__str_casei)) {
                continue;
            }

            PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc, "Fencing History");
            out->message(out, "stonith-event", hp,
                         pcmk_all_flags_set(section_opts,
                                            pcmk_section_fencing_all),
                         stonith__later_succeeded(hp, history), show_opts);
            out->increment_list(out);
        }

        PCMK__OUTPUT_LIST_FOOTER(out, rc);
    } else {
        char *rc_s = pcmk__itoa(history_rc);

        pcmk__output_create_xml_node(out, "fence_history",
                                     "status", rc_s,
                                     NULL);
        free(rc_s);

        rc = pcmk_rc_ok;
    }

    return rc;
}

PCMK__OUTPUT_ARGS("last-fenced", "const char *", "time_t")
static int
last_fenced_html(pcmk__output_t *out, va_list args) {
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
static int
last_fenced_text(pcmk__output_t *out, va_list args) {
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
static int
last_fenced_xml(pcmk__output_t *out, va_list args) {
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

PCMK__OUTPUT_ARGS("pending-fencing-list", "stonith_history_t *", "GList *",
                  "uint32_t", "uint32_t", "gboolean")
int
stonith__pending_actions(pcmk__output_t *out, va_list args)
{
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GList *only_node = va_arg(args, GList *);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);
    gboolean print_spacer = va_arg(args, gboolean);

    int rc = pcmk_rc_no_output;

    for (stonith_history_t *hp = history; hp; hp = hp->next) {
        if (!pcmk__str_in_list(hp->target, only_node, pcmk__str_star_matches|pcmk__str_casei)) {
            continue;
        }

        /* Skip the rest of the history after we see a failed/done action */
        if ((hp->state == st_failed) || (hp->state == st_done)) {
            break;
        }

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Pending Fencing Actions");
        out->message(out, "stonith-event", hp,
                     pcmk_all_flags_set(section_opts, pcmk_section_fencing_all),
                     stonith__later_succeeded(hp, history), show_opts);
        out->increment_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("stonith-event", "stonith_history_t *", "int", "const char *",
                  "uint32_t")
static int
stonith_event_html(pcmk__output_t *out, va_list args)
{
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    int full_history = va_arg(args, int);
    const char *succeeded = va_arg(args, const char *);
    uint32_t show_opts = va_arg(args, uint32_t);

    gchar *desc = stonith__history_description(event, full_history, succeeded,
                                               show_opts);

    switch(event->state) {
        case st_done:
            out->list_item(out, "successful-stonith-event", "%s", desc);
            break;

        case st_failed:
            out->list_item(out, "failed-stonith-event", "%s", desc);
            break;

        default:
            out->list_item(out, "pending-stonith-event", "%s", desc);
            break;
    }
    g_free(desc);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("stonith-event", "stonith_history_t *", "int", "const char *",
                  "uint32_t")
static int
stonith_event_text(pcmk__output_t *out, va_list args)
{
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    int full_history = va_arg(args, int);
    const char *succeeded = va_arg(args, const char *);
    uint32_t show_opts = va_arg(args, uint32_t);

    if (out->is_quiet(out)) {
        pcmk__formatted_printf(out, "%lld\n", (long long) event->completed);
    } else {
        gchar *desc = stonith__history_description(event, full_history, succeeded,
                                                   show_opts);

        pcmk__indented_printf(out, "%s\n", desc);
        g_free(desc);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("stonith-event", "stonith_history_t *", "int", "const char *",
                  "uint32_t")
static int
stonith_event_xml(pcmk__output_t *out, va_list args)
{
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    int full_history G_GNUC_UNUSED = va_arg(args, int);
    const char *succeeded G_GNUC_UNUSED = va_arg(args, const char *);
    uint32_t show_opts G_GNUC_UNUSED = va_arg(args, uint32_t);

    char *buf = NULL;

    xmlNodePtr node = pcmk__output_create_xml_node(out, "fence_event",
                                                   "action", event->action,
                                                   "target", event->target,
                                                   "client", event->client,
                                                   "origin", event->origin,
                                                   NULL);

    switch (event->state) {
        case st_failed:
            pcmk__xe_set_props(node, "status", "failed",
                               XML_LRM_ATTR_EXIT_REASON, event->exit_reason,
                               NULL);
            break;

        case st_done:
            crm_xml_add(node, "status", "success");
            break;

        default: {
            char *state = pcmk__itoa(event->state);
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
static int
validate_agent_html(pcmk__output_t *out, va_list args) {
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
static int
validate_agent_text(pcmk__output_t *out, va_list args) {
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

    out->subprocess_output(out, rc, output, error_output);
    return rc;
}

PCMK__OUTPUT_ARGS("validate", "const char *", "const char *", "char *", "char *", "int")
static int
validate_agent_xml(pcmk__output_t *out, va_list args) {
    const char *agent = va_arg(args, const char *);
    const char *device = va_arg(args, const char *);
    char *output = va_arg(args, char *);
    char *error_output = va_arg(args, char *);
    int rc = va_arg(args, int);

    xmlNodePtr node = pcmk__output_create_xml_node(
        out, "validate", "agent", agent, "valid", pcmk__btoa(rc == pcmk_ok),
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
    { "failed-fencing-list", "default", stonith__failed_history },
    { "fencing-list", "default", stonith__history },
    { "full-fencing-list", "default", stonith__full_history },
    { "full-fencing-list", "xml", full_history_xml },
    { "last-fenced", "html", last_fenced_html },
    { "last-fenced", "log", last_fenced_text },
    { "last-fenced", "text", last_fenced_text },
    { "last-fenced", "xml", last_fenced_xml },
    { "pending-fencing-list", "default", stonith__pending_actions },
    { "stonith-event", "html", stonith_event_html },
    { "stonith-event", "log", stonith_event_text },
    { "stonith-event", "text", stonith_event_text },
    { "stonith-event", "xml", stonith_event_xml },
    { "validate", "html", validate_agent_html },
    { "validate", "log", validate_agent_text },
    { "validate", "text", validate_agent_text },
    { "validate", "xml", validate_agent_xml },

    { NULL, NULL, NULL }
};

void
stonith__register_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}
