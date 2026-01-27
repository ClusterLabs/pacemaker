/*
 * Copyright 2009-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/mainloop.h>
#include <crm/common/output.h>
#include <crm/common/results.h>
#include <crm/stonith-ng.h>         // stonith_t, stonith_history_t, etc.
#include <crm/fencing/internal.h>   // stonith__*

#include <glib.h>
#include <libxml/tree.h>
#include <pacemaker.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

static const int st_opts = st_opt_sync_call|st_opt_allow_self_fencing;

static GMainLoop *mainloop = NULL;

static struct {
    stonith_t *st;
    const char *target;
    const char *action;
    char *name;
    unsigned int timeout;
    unsigned int tolerance;
    int delay;
    pcmk__action_result_t result;
} async_fence_data = { NULL, };

static int
handle_level(stonith_t *st, const char *target, int fence_level, GList *devices,
             bool added)
{
    const char *node = NULL;
    const char *pattern = NULL;

    gchar **name_value = NULL;
    const gchar *name = NULL;
    const gchar *value = NULL;
    int rc = pcmk_rc_ok;

    if (target == NULL) {
        // Not really possible, but makes static analysis happy
        return EINVAL;
    }

    /* Determine if targeting by attribute, node name pattern or node name */
    name_value = g_strsplit(target, "=", 2);

    if (g_strv_length(name_value) == 2) {
        name = name_value[0];
        value = name_value[1];

    } else if (*target == '@') {
        pattern = target + 1;

    } else {
        node = target;
    }

    /* Register or unregister level as appropriate */
    if (added) {
        stonith_key_value_t *kvs = NULL;

        for (GList *iter = devices; iter != NULL; iter = iter->next) {
            kvs = stonith__key_value_add(kvs, NULL, iter->data);
        }

        rc = st->cmds->register_level_full(st, st_opts, node, pattern, name,
                                           value, fence_level, kvs);
        stonith__key_value_freeall(kvs, false, true);
    } else {
        rc = st->cmds->remove_level_full(st, st_opts, node, pattern,
                                         name, value, fence_level);
    }

    g_strfreev(name_value);
    return pcmk_legacy2rc(rc);
}

static stonith_history_t *
reduce_fence_history(stonith_history_t *history)
{
    stonith_history_t *new, *hp, *np;

    if (!history) {
        return history;
    }

    new = history;
    hp = new->next;
    new->next = NULL;

    while (hp) {
        stonith_history_t *hp_next = hp->next;

        hp->next = NULL;

        for (np = new; ; np = np->next) {
            if ((hp->state == st_done) || (hp->state == st_failed)) {
                /* action not in progress */
                if (pcmk__str_eq(hp->target, np->target, pcmk__str_casei)
                    && pcmk__str_eq(hp->action, np->action, pcmk__str_none)
                    && (hp->state == np->state)
                    && ((hp->state == st_done)
                        || pcmk__str_eq(hp->delegate, np->delegate,
                                        pcmk__str_casei))) {
                        /* purge older hp */
                        stonith__history_free(hp);
                        break;
                }
            }

            if (!np->next) {
                np->next = hp;
                break;
            }
        }
        hp = hp_next;
    }

    return new;
}

static void
notify_callback(stonith_t * st, stonith_event_t * e)
{
    if (pcmk__str_eq(async_fence_data.target, e->target, pcmk__str_casei)
        && pcmk__str_eq(async_fence_data.action, e->action, pcmk__str_none)) {

        pcmk__set_result(&async_fence_data.result,
                         stonith__event_exit_status(e),
                         stonith__event_execution_status(e),
                         stonith__event_exit_reason(e));
        g_main_loop_quit(mainloop);
    }
}

static void
fence_callback(stonith_t * stonith, stonith_callback_data_t * data)
{
    pcmk__set_result(&async_fence_data.result, stonith__exit_status(data),
                     stonith__execution_status(data),
                     stonith__exit_reason(data));
    g_main_loop_quit(mainloop);
}

static gboolean
async_fence_helper(gpointer user_data)
{
    stonith_t *st = async_fence_data.st;
    int call_id = 0;
    int rc = stonith__api_connect_retry(st, async_fence_data.name, 10);
    int timeout = 0;

    if (rc != pcmk_rc_ok) {
        g_main_loop_quit(mainloop);
        pcmk__set_result(&async_fence_data.result, CRM_EX_ERROR,
                         PCMK_EXEC_NOT_CONNECTED, pcmk_rc_str(rc));
        return TRUE;
    }

    st->cmds->register_notification(st, PCMK__VALUE_ST_NOTIFY_FENCE,
                                    notify_callback);

    call_id = st->cmds->fence_with_delay(st,
                                         st_opt_allow_self_fencing,
                                         async_fence_data.target,
                                         async_fence_data.action,
                                         pcmk__timeout_ms2s(async_fence_data.timeout),
                                         pcmk__timeout_ms2s(async_fence_data.tolerance),
                                         async_fence_data.delay);

    if (call_id < 0) {
        g_main_loop_quit(mainloop);
        pcmk__set_result(&async_fence_data.result, CRM_EX_ERROR,
                         PCMK_EXEC_ERROR, pcmk_strerror(call_id));
        return TRUE;
    }

    timeout = pcmk__timeout_ms2s(async_fence_data.timeout);
    if (async_fence_data.delay > 0) {
        timeout += async_fence_data.delay;
    }
    st->cmds->register_callback(st, call_id, timeout, st_opt_timeout_updates,
                                NULL, "callback", fence_callback);
    return TRUE;
}

int
pcmk__request_fencing(stonith_t *st, const char *target, const char *action,
                      const char *name, unsigned int timeout,
                      unsigned int tolerance, int delay, char **reason)
{
    crm_trigger_t *trig;
    int rc = pcmk_rc_ok;

    async_fence_data.st = st;
    async_fence_data.name = strdup(name);
    async_fence_data.target = target;
    async_fence_data.action = action;
    async_fence_data.timeout = timeout;
    async_fence_data.tolerance = tolerance;
    async_fence_data.delay = delay;
    pcmk__set_result(&async_fence_data.result, CRM_EX_ERROR, PCMK_EXEC_UNKNOWN,
                     NULL);

    trig = mainloop_add_trigger(G_PRIORITY_HIGH, async_fence_helper, NULL);
    mainloop_set_trigger(trig);

    mainloop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(mainloop);
    g_main_loop_unref(mainloop);

    free(async_fence_data.name);

    if (reason != NULL) {
        // Give the caller ownership of the exit reason
        *reason = async_fence_data.result.exit_reason;
        async_fence_data.result.exit_reason = NULL;
    }
    rc = stonith__result2rc(&async_fence_data.result);
    pcmk__reset_result(&async_fence_data.result);
    return rc;
}

int
pcmk_request_fencing(xmlNodePtr *xml, const char *target, const char *action,
                     const char *name, unsigned int timeout,
                     unsigned int tolerance, int delay, char **reason)
{
    stonith_t *st = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__setup_output_fencing(&out, &st, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    rc = pcmk__request_fencing(st, target, action, name, timeout, tolerance,
                               delay, reason);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);

    st->cmds->disconnect(st);
    stonith__api_free(st);
    return rc;
}

int
pcmk__fence_history(pcmk__output_t *out, stonith_t *st, const char *target,
                    unsigned int timeout, int verbose, bool broadcast,
                    bool cleanup)
{
    stonith_history_t *history = NULL;
    stonith_history_t *latest = NULL;
    int rc = pcmk_rc_ok;
    int opts = 0;

    if (cleanup) {
        out->info(out, "cleaning up fencing-history%s%s",
                  target ? " for node " : "", target ? target : "");
    }

    if (broadcast) {
        out->info(out, "gather fencing-history from all nodes");
    }

    stonith__set_call_options(opts, target, st_opts);

    if (cleanup) {
        stonith__set_call_options(opts, target, st_opt_cleanup);
    }

    if (broadcast) {
        stonith__set_call_options(opts, target, st_opt_broadcast);
    }

    if (pcmk__str_eq(target, "*", pcmk__str_none)) {
        target = NULL;
    }

    rc = st->cmds->history(st, opts, target, &history, pcmk__timeout_ms2s(timeout));

    if (cleanup) {
        // Cleanup doesn't return a history list
        stonith__history_free(history);
        return pcmk_legacy2rc(rc);
    }

    out->begin_list(out, "event", "events", "Fencing history");

    history = stonith__sort_history(history);
    for (stonith_history_t *hp = history; hp != NULL; hp = hp->next) {
        if (hp->state == st_done) {
            latest = hp;
        }

        if (out->is_quiet(out) || !verbose) {
            continue;
        }

        out->message(out, "stonith-event", hp, true, false,
                     stonith__later_succeeded(hp, history),
                     (uint32_t) pcmk_show_failed_detail);
        out->increment_list(out);
    }

    if (latest) {
        if (out->is_quiet(out)) {
            out->message(out, "stonith-event", latest, false, true, NULL,
                         (uint32_t) pcmk_show_failed_detail);
        } else if (!verbose) { // already printed if verbose
            out->message(out, "stonith-event", latest, false, false, NULL,
                         (uint32_t) pcmk_show_failed_detail);
            out->increment_list(out);
        }
    }

    out->end_list(out);

    stonith__history_free(history);
    return pcmk_legacy2rc(rc);
}

int
pcmk_fence_history(xmlNodePtr *xml, const char *target, unsigned int timeout,
                   bool quiet, int verbose, bool broadcast, bool cleanup)
{
    stonith_t *st = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__setup_output_fencing(&out, &st, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    out->quiet = quiet;

    rc = pcmk__fence_history(out, st, target, timeout, verbose, broadcast,
                             cleanup);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);

    st->cmds->disconnect(st);
    stonith__api_free(st);
    return rc;
}

int
pcmk__fence_installed(pcmk__output_t *out, stonith_t *st)
{
    stonith_key_value_t *devices = NULL;
    int rc = pcmk_rc_ok;

    rc = st->cmds->list_agents(st, st_opt_sync_call, NULL, &devices, 0);
    // rc is a negative error code or a positive number of agents
    if (rc < 0) {
        return pcmk_legacy2rc(rc);
    }

    out->begin_list(out, "fence device", "fence devices",
                    "Installed fence devices");
    for (stonith_key_value_t *iter = devices; iter != NULL; iter = iter->next) {
        out->list_item(out, "device", "%s", iter->value);
    }
    out->end_list(out);

    stonith__key_value_freeall(devices, true, true);
    return pcmk_rc_ok;
}

int
pcmk_fence_installed(xmlNodePtr *xml, unsigned int timeout)
{
    stonith_t *st = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__setup_output_fencing(&out, &st, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    rc = pcmk__fence_installed(out, st);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);

    st->cmds->disconnect(st);
    stonith__api_free(st);
    return rc;
}

int
pcmk__fence_last(pcmk__output_t *out, const char *target, bool as_nodeid)
{
    time_t when = 0;

    if (target == NULL) {
        return pcmk_rc_ok;
    }

    if (as_nodeid) {
        when = stonith_api_time(atol(target), NULL, FALSE);
    } else {
        when = stonith_api_time(0, target, FALSE);
    }

    return out->message(out, "last-fenced", target, when);
}

int
pcmk_fence_last(xmlNodePtr *xml, const char *target, bool as_nodeid)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    stonith__register_messages(out);

    rc = pcmk__fence_last(out, target, as_nodeid);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    return rc;
}

int
pcmk__fence_list_targets(pcmk__output_t *out, stonith_t *st,
                         const char *device_id, unsigned int timeout)
{
    GList *targets = NULL;
    char *lists = NULL;
    int rc = pcmk_rc_ok;

    rc = st->cmds->list(st, st_opts, device_id, &lists, pcmk__timeout_ms2s(timeout));
    if (rc != pcmk_rc_ok) {
        return pcmk_legacy2rc(rc);
    }

    targets = stonith__parse_targets(lists);

    out->begin_list(out, "fence target", "fence targets", "Fence Targets");
    while (targets != NULL) {
        out->list_item(out, NULL, "%s", (const char *) targets->data);
        targets = targets->next;
    }
    out->end_list(out);

    free(lists);
    return rc;
}

int
pcmk_fence_list_targets(xmlNodePtr *xml, const char *device_id, unsigned int timeout)
{
    stonith_t *st = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__setup_output_fencing(&out, &st, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    rc = pcmk__fence_list_targets(out, st, device_id, timeout);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);

    st->cmds->disconnect(st);
    stonith__api_free(st);
    return rc;
}

int
pcmk__fence_metadata(pcmk__output_t *out, stonith_t *st, const char *agent,
                     unsigned int timeout)
{
    char *buffer = NULL;
    int rc = st->cmds->metadata(st, st_opt_sync_call, agent, NULL, &buffer,
                                pcmk__timeout_ms2s(timeout));

    if (rc != pcmk_rc_ok) {
        return pcmk_legacy2rc(rc);
    }

    out->output_xml(out, PCMK_XE_METADATA, buffer);
    free(buffer);
    return rc;
}

int
pcmk_fence_metadata(xmlNodePtr *xml, const char *agent, unsigned int timeout)
{
    stonith_t *st = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__setup_output_fencing(&out, &st, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    rc = pcmk__fence_metadata(out, st, agent, timeout);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);

    st->cmds->disconnect(st);
    stonith__api_free(st);
    return rc;
}

int
pcmk__fence_registered(pcmk__output_t *out, stonith_t *st, const char *target,
                       unsigned int timeout)
{
    stonith_key_value_t *devices = NULL;
    int rc = pcmk_rc_ok;

    rc = st->cmds->query(st, st_opts, target, &devices, pcmk__timeout_ms2s(timeout));
    /* query returns a negative error code or a positive number of results. */
    if (rc < 0) {
        return pcmk_legacy2rc(rc);
    }

    out->begin_list(out, "fence device", "fence devices",
                    "Registered fence devices");
    for (stonith_key_value_t *iter = devices; iter != NULL; iter = iter->next) {
        out->list_item(out, "device", "%s", iter->value);
    }
    out->end_list(out);

    stonith__key_value_freeall(devices, true, true);

    /* Return pcmk_rc_ok here, not the number of results.  Callers probably
     * don't care.
     */
    return pcmk_rc_ok;
}

int
pcmk_fence_registered(xmlNodePtr *xml, const char *target, unsigned int timeout)
{
    stonith_t *st = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__setup_output_fencing(&out, &st, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    rc = pcmk__fence_registered(out, st, target, timeout);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);

    st->cmds->disconnect(st);
    stonith__api_free(st);
    return rc;
}

int
pcmk__fence_register_level(stonith_t *st, const char *target, int fence_level,
                           GList *devices)
{
    return handle_level(st, target, fence_level, devices, true);
}

int
pcmk_fence_register_level(xmlNodePtr *xml, const char *target, int fence_level,
                          GList *devices)
{
    stonith_t* st = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__setup_output_fencing(&out, &st, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    rc = pcmk__fence_register_level(st, target, fence_level, devices);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);

    st->cmds->disconnect(st);
    stonith__api_free(st);
    return rc;
}

int
pcmk__fence_unregister_level(stonith_t *st, const char *target, int fence_level)
{
    return handle_level(st, target, fence_level, NULL, false);
}

int
pcmk_fence_unregister_level(xmlNodePtr *xml, const char *target, int fence_level)
{
    stonith_t* st = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__setup_output_fencing(&out, &st, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    rc = pcmk__fence_unregister_level(st, target, fence_level);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);

    st->cmds->disconnect(st);
    stonith__api_free(st);
    return rc;
}

int
pcmk__fence_validate(pcmk__output_t *out, stonith_t *st, const char *agent,
                     const char *id, GHashTable *params, unsigned int timeout)
{
    char *output = NULL;
    char *error_output = NULL;
    int rc;

    rc  = stonith__validate(st, st_opt_sync_call, id, agent, params,
                            pcmk__timeout_ms2s(timeout), &output, &error_output);
    out->message(out, "validate", agent, id, output, error_output, rc);
    return pcmk_legacy2rc(rc);
}

int
pcmk_fence_validate(xmlNodePtr *xml, const char *agent, const char *id,
                    GHashTable *params, unsigned int timeout)
{
    stonith_t *st = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__setup_output_fencing(&out, &st, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    rc = pcmk__fence_validate(out, st, agent, id, params, timeout);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);

    st->cmds->disconnect(st);
    stonith__api_free(st);
    return rc;
}

int
pcmk__get_fencing_history(stonith_t *st, stonith_history_t **stonith_history,
                          enum pcmk__fence_history fence_history)
{
    int rc = pcmk_rc_ok;

    if ((st == NULL) || (st->state == stonith_disconnected)) {
        rc = ENOTCONN;
    } else if (fence_history != pcmk__fence_history_none) {
        rc = st->cmds->history(st, st_opt_sync_call, NULL, stonith_history,
                               120);

        rc = pcmk_legacy2rc(rc);
        if (rc != pcmk_rc_ok) {
            return rc;
        }

        *stonith_history = stonith__sort_history(*stonith_history);
        if (fence_history == pcmk__fence_history_reduced) {
            *stonith_history = reduce_fence_history(*stonith_history);
        }
    }

    return rc;
}
