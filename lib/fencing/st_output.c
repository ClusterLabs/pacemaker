/*
 * Copyright 2019-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include <crm/stonith-ng.h>
#include <crm/common/iso8601.h>
#include <crm/common/util.h>
#include <crm/common/xml.h>
#include <crm/common/output.h>
#include <crm/fencing/internal.h>
#include <crm/pengine/internal.h>

/*!
 * \internal
 * \brief Convert seconds and nanoseconds to a date/time/time-zone string
 *
 * \param[in] sec        Seconds
 * \param[in] nsec       Nanoseconds
 * \param[in] show_usec  Whether to show time in microseconds resolution (if
 *                       false, use seconds resolution)
 *
 * \return A string representation of \p sec and \nsec
 *
 * \note The caller is responsible for freeing the return value using \p free().
 */
static char *
timespec_string(time_t sec, long nsec, bool show_usec) {
    const struct timespec ts = {
        .tv_sec = sec,
        .tv_nsec = nsec,
    };

    return pcmk__timespec2str(&ts,
                              crm_time_log_date
                              |crm_time_log_timeofday
                              |crm_time_log_with_timezone
                              |(show_usec? crm_time_usecs : 0));
}

/*!
 * \internal
 * \brief Return a readable string equivalent of a fencing history item's action
 *
 * \param[in] history  Fencing history entry
 *
 * \return Readable string equivalent of action belonging to \p history
 */
static const char *
history_action_text(const stonith_history_t *history)
{
    if (pcmk__str_eq(history->action, PCMK_ACTION_ON, pcmk__str_none)) {
        return "unfencing";
    }
    if (pcmk__str_eq(history->action, PCMK_ACTION_OFF, pcmk__str_none)) {
        return "turning off";
    }
    return pcmk__s(history->action, "fencing");
}

/*!
 * \internal
 * \brief Return a status-friendly description of fence history entry state
 *
 * \param[in] history  Fence history entry to describe
 *
 * \return One-word description of history entry state
 * \note This is similar to stonith__op_state_text() except user-oriented (i.e.,
 *       for cluster status) instead of developer-oriented (for debug logs).
 */
static const char *
state_str(const stonith_history_t *history)
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
stonith__history_description(const stonith_history_t *history,
                             bool full_history, const char *later_succeeded,
                             uint32_t show_opts)
{
    GString *str = g_string_sized_new(256); // Generous starting size
    char *completed_time_s = NULL;

    if ((history->state == st_failed) || (history->state == st_done)) {
        completed_time_s = timespec_string(history->completed,
                                           history->completed_nsec, true);
    }

    pcmk__g_strcat(str, history_action_text(history), " of ", history->target,
                   NULL);

    if (!pcmk__is_set(show_opts, pcmk_show_failed_detail)) {
        // More human-friendly
        if (((history->state == st_failed) || (history->state == st_done))
            && (history->delegate != NULL)) {

            pcmk__g_strcat(str, " by ", history->delegate, NULL);
        }
        pcmk__g_strcat(str, " for ", history->client, "@", history->origin,
                       NULL);
        if (!full_history) {
            g_string_append(str, " last"); // For example, "last failed at ..."
        }
    }

    pcmk__add_word(&str, 0, state_str(history));

    // For failed actions, add exit reason if available
    if ((history->state == st_failed) && (history->exit_reason != NULL)) {
        pcmk__g_strcat(str, " (", history->exit_reason, ")", NULL);
    }

    if (pcmk__is_set(show_opts, pcmk_show_failed_detail)) {
        // More technical
        g_string_append(str, ": ");

        // For completed actions, add delegate if available
        if (((history->state == st_failed) || (history->state == st_done))
            && (history->delegate != NULL)) {

            pcmk__g_strcat(str, PCMK_XA_DELEGATE "=", history->delegate, ", ",
                           NULL);
        }

        // Add information about originator
        pcmk__g_strcat(str,
                       PCMK_XA_CLIENT "=", history->client, ", "
                       PCMK_XA_ORIGIN "=", history->origin, NULL);

        // For completed actions, add completion time
        if (completed_time_s != NULL) {
            if (full_history) {
                g_string_append(str, ", completed");
            } else if (history->state == st_failed) {
                g_string_append(str, ", last-failed");
            } else {
                g_string_append(str, ", last-successful");
            }
            pcmk__g_strcat(str, "='", completed_time_s, "'", NULL);
        }
    } else if (completed_time_s != NULL) {
        // More human-friendly
        pcmk__g_strcat(str, " at ", completed_time_s, NULL);
    }

    if ((history->state == st_failed) && (later_succeeded != NULL)) {
        pcmk__g_strcat(str,
                       " (a later attempt from ", later_succeeded,
                       " succeeded)", NULL);
    }

    free(completed_time_s);
    return g_string_free(str, FALSE);
}

PCMK__OUTPUT_ARGS("failed-fencing-list", "stonith_history_t *", "GList *",
                  "uint32_t", "uint32_t", "bool")
static int
failed_history(pcmk__output_t *out, va_list args)
{
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GList *only_node = va_arg(args, GList *);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer = va_arg(args, int);

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
                     pcmk__all_flags_set(section_opts,
                                         pcmk_section_fencing_all),
                     false, stonith__later_succeeded(hp, history), show_opts);
        out->increment_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("fencing-list", "stonith_history_t *", "GList *", "uint32_t",
                  "uint32_t", "bool")
static int
stonith_history(pcmk__output_t *out, va_list args)
{
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GList *only_node = va_arg(args, GList *);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer = va_arg(args, int);

    int rc = pcmk_rc_no_output;

    for (stonith_history_t *hp = history; hp; hp = hp->next) {
        if (!pcmk__str_in_list(hp->target, only_node, pcmk__str_star_matches|pcmk__str_casei)) {
            continue;
        }

        if (hp->state != st_failed) {
            PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Fencing History");
            out->message(out, "stonith-event", hp,
                         pcmk__all_flags_set(section_opts,
                                             pcmk_section_fencing_all),
                         false, stonith__later_succeeded(hp, history), show_opts);
            out->increment_list(out);
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("full-fencing-list", "crm_exit_t", "stonith_history_t *",
                  "GList *", "uint32_t", "uint32_t", "bool")
static int
full_history(pcmk__output_t *out, va_list args)
{
    crm_exit_t history_rc G_GNUC_UNUSED = va_arg(args, crm_exit_t);
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GList *only_node = va_arg(args, GList *);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer = va_arg(args, int);

    int rc = pcmk_rc_no_output;

    for (stonith_history_t *hp = history; hp; hp = hp->next) {
        if (!pcmk__str_in_list(hp->target, only_node, pcmk__str_star_matches|pcmk__str_casei)) {
            continue;
        }

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Fencing History");
        out->message(out, "stonith-event", hp,
                     pcmk__all_flags_set(section_opts,
                                         pcmk_section_fencing_all),
                     false, stonith__later_succeeded(hp, history), show_opts);
        out->increment_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("full-fencing-list", "crm_exit_t", "stonith_history_t *",
                  "GList *", "uint32_t", "uint32_t", "bool")
static int
full_history_xml(pcmk__output_t *out, va_list args)
{
    crm_exit_t history_rc = va_arg(args, crm_exit_t);
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GList *only_node = va_arg(args, GList *);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer G_GNUC_UNUSED = va_arg(args, int);

    int rc = pcmk_rc_no_output;

    if (history_rc == 0) {
        for (stonith_history_t *hp = history; hp; hp = hp->next) {
            if (!pcmk__str_in_list(hp->target, only_node, pcmk__str_star_matches|pcmk__str_casei)) {
                continue;
            }

            PCMK__OUTPUT_LIST_HEADER(out, false, rc, "Fencing History");
            out->message(out, "stonith-event", hp,
                         pcmk__all_flags_set(section_opts,
                                             pcmk_section_fencing_all),
                         false, stonith__later_succeeded(hp, history), show_opts);
            out->increment_list(out);
        }

        PCMK__OUTPUT_LIST_FOOTER(out, rc);
    } else {
        xmlNode *xml = pcmk__output_create_xml_node(out, PCMK_XE_FENCE_HISTORY);

        pcmk__xe_set_int(xml, PCMK_XA_STATUS, history_rc);
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
        char *buf = pcmk__assert_asprintf("Node %s last fenced at: %s", target,
                                          ctime(&when));
        pcmk__output_create_html_node(out, PCMK__XE_DIV, NULL, NULL, buf);
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
        char *buf = timespec_string(when, 0, false);
        xmlNode *xml = pcmk__output_create_xml_node(out, PCMK_XE_LAST_FENCED);

        pcmk__xe_set(xml, PCMK_XA_TARGET, target);
        pcmk__xe_set(xml, PCMK_XA_WHEN, buf);

        free(buf);
        return pcmk_rc_ok;
    } else {
        return pcmk_rc_no_output;
    }
}

PCMK__OUTPUT_ARGS("pending-fencing-list", "stonith_history_t *", "GList *",
                  "uint32_t", "uint32_t", "bool")
static int
pending_actions(pcmk__output_t *out, va_list args)
{
    stonith_history_t *history = va_arg(args, stonith_history_t *);
    GList *only_node = va_arg(args, GList *);
    uint32_t section_opts = va_arg(args, uint32_t);
    uint32_t show_opts = va_arg(args, uint32_t);
    bool print_spacer = va_arg(args, int);

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
                     pcmk__all_flags_set(section_opts,
                                         pcmk_section_fencing_all),
                     false, stonith__later_succeeded(hp, history), show_opts);
        out->increment_list(out);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

PCMK__OUTPUT_ARGS("stonith-event", "stonith_history_t *", "bool", "bool",
                  "const char *", "uint32_t")
static int
stonith_event_html(pcmk__output_t *out, va_list args)
{
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    bool full_history = va_arg(args, int);
    bool completed_only G_GNUC_UNUSED = va_arg(args, int);
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

PCMK__OUTPUT_ARGS("stonith-event", "stonith_history_t *", "bool", "bool",
                  "const char *", "uint32_t")
static int
stonith_event_text(pcmk__output_t *out, va_list args)
{
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    bool full_history = va_arg(args, int);
    bool completed_only = va_arg(args, int);
    const char *succeeded = va_arg(args, const char *);
    uint32_t show_opts = va_arg(args, uint32_t);

    if (completed_only) {
        pcmk__formatted_printf(out, "%lld\n", (long long) event->completed);
    } else {
        gchar *desc = stonith__history_description(event, full_history, succeeded,
                                                   show_opts);

        pcmk__indented_printf(out, "%s\n", desc);
        g_free(desc);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("stonith-event", "stonith_history_t *", "bool", "bool",
                  "const char *", "uint32_t")
static int
stonith_event_xml(pcmk__output_t *out, va_list args)
{
    stonith_history_t *event = va_arg(args, stonith_history_t *);
    bool full_history G_GNUC_UNUSED = va_arg(args, int);
    bool completed_only G_GNUC_UNUSED = va_arg(args, int);
    const char *succeeded G_GNUC_UNUSED = va_arg(args, const char *);
    uint32_t show_opts G_GNUC_UNUSED = va_arg(args, uint32_t);

    xmlNode *xml = NULL;

    xml = pcmk__output_create_xml_node(out, PCMK_XE_FENCE_EVENT);
    pcmk__xe_set(xml, PCMK_XA_ACTION, event->action);
    pcmk__xe_set(xml, PCMK_XA_TARGET, event->target);
    pcmk__xe_set(xml, PCMK_XA_CLIENT, event->client);
    pcmk__xe_set(xml, PCMK_XA_ORIGIN, event->origin);

    switch (event->state) {
        case st_failed:
            pcmk__xe_set(xml, PCMK_XA_STATUS, PCMK_VALUE_FAILED);
            pcmk__xe_set(xml, PCMK_XA_EXIT_REASON, event->exit_reason);
            break;

        case st_done:
            pcmk__xe_set(xml, PCMK_XA_STATUS, PCMK_VALUE_SUCCESS);
            break;

        default:
            pcmk__xe_set(xml, PCMK_XA_STATUS, PCMK_VALUE_PENDING);
            pcmk__xe_set_int(xml, PCMK_XA_EXTENDED_STATUS, event->state);
            break;
    }

    if (event->delegate != NULL) {
        pcmk__xe_set(xml, PCMK_XA_DELEGATE, event->delegate);
    }

    if ((event->state == st_failed) || (event->state == st_done)) {
        char *time_s = timespec_string(event->completed, event->completed_nsec,
                                       true);

        pcmk__xe_set(xml, PCMK_XA_COMPLETED, time_s);
        free(time_s);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("validate", "const char *", "const char *", "const char *",
                  "const char *", "int")
static int
validate_agent_html(pcmk__output_t *out, va_list args) {
    const char *agent = va_arg(args, const char *);
    const char *device = va_arg(args, const char *);
    const char *output = va_arg(args, const char *);
    const char *error_output = va_arg(args, const char *);
    int rc = va_arg(args, int);
    const char *rc_s = (rc == pcmk_rc_ok)? "succeeded" : "failed";

    if (device) {
        char *buf = pcmk__assert_asprintf("Validation of %s on %s %s", agent,
                                          device, rc_s);

        pcmk__output_create_html_node(out, PCMK__XE_DIV, NULL, NULL, buf);
        free(buf);
    } else {
        char *buf = pcmk__assert_asprintf("Validation of %s %s", agent, rc_s);

        pcmk__output_create_html_node(out, PCMK__XE_DIV, NULL, NULL, buf);
        free(buf);
    }

    out->subprocess_output(out, rc, output, error_output);
    return rc;
}

PCMK__OUTPUT_ARGS("validate", "const char *", "const char *", "const char *",
                  "const char *", "int")
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

    out->subprocess_output(out, rc, output, error_output);
    return rc;
}

PCMK__OUTPUT_ARGS("validate", "const char *", "const char *", "const char *",
                  "const char *", "int")
static int
validate_agent_xml(pcmk__output_t *out, va_list args) {
    const char *agent = va_arg(args, const char *);
    const char *device = va_arg(args, const char *);
    const char *output = va_arg(args, const char *);
    const char *error_output = va_arg(args, const char *);
    int rc = va_arg(args, int);

    xmlNode *xml = pcmk__output_create_xml_node(out, PCMK_XE_VALIDATE);

    pcmk__xe_set(xml, PCMK_XA_AGENT, agent);
    pcmk__xe_set_bool(xml, PCMK_XA_VALID, (rc == pcmk_ok));
    pcmk__xe_set(xml, PCMK_XA_DEVICE, device);

    pcmk__output_xml_push_parent(out, xml);
    out->subprocess_output(out, rc, output, error_output);
    pcmk__output_xml_pop_parent(out);

    return rc;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "failed-fencing-list", "default", failed_history },
    { "fencing-list", "default", stonith_history },
    { "full-fencing-list", "default", full_history },
    { "full-fencing-list", "xml", full_history_xml },
    { "last-fenced", "html", last_fenced_html },
    { "last-fenced", "log", last_fenced_text },
    { "last-fenced", "text", last_fenced_text },
    { "last-fenced", "xml", last_fenced_xml },
    { "pending-fencing-list", "default", pending_actions },
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
