/*
 * Copyright 2009-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/mainloop.h>
#include <crm/common/results.h>
#include <crm/common/output_internal.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>

#include <glib.h>
#include <libxml/tree.h>
#include <pacemaker.h>
#include <pcmki/pcmki_output.h>
#include <pcmki/pcmki_fence.h>

static const int st_opts = st_opt_sync_call | st_opt_allow_suicide;

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
handle_level(stonith_t *st, char *target, int fence_level,
             stonith_key_value_t *devices, bool added) {
    char *node = NULL;
    char *pattern = NULL;
    char *name = NULL;
    char *value = NULL;
    int rc = pcmk_rc_ok;

    if (target == NULL) {
        // Not really possible, but makes static analysis happy
        return EINVAL;
    }

    /* Determine if targeting by attribute, node name pattern or node name */
    value = strchr(target, '=');
    if (value != NULL)  {
        name = target;
        *value++ = '\0';
    } else if (*target == '@') {
        pattern = target + 1;
    } else {
        node = target;
    }

    /* Register or unregister level as appropriate */
    if (added) {
        rc = st->cmds->register_level_full(st, st_opts, node, pattern,
                                           name, value, fence_level,
                                           devices);
    } else {
        rc = st->cmds->remove_level_full(st, st_opts, node, pattern,
                                         name, value, fence_level);
    }

    return pcmk_legacy2rc(rc);
}

static void
notify_callback(stonith_t * st, stonith_event_t * e)
{
    if (pcmk__str_eq(async_fence_data.target, e->target, pcmk__str_casei)
        && pcmk__str_eq(async_fence_data.action, e->action, pcmk__str_casei)) {

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
    int rc = stonith_api_connect_retry(st, async_fence_data.name, 10);

    if (rc != pcmk_ok) {
        fprintf(stderr, "Could not connect to fencer: %s\n", pcmk_strerror(rc));
        g_main_loop_quit(mainloop);
        pcmk__set_result(&async_fence_data.result, CRM_EX_ERROR,
                         PCMK_EXEC_NOT_CONNECTED, NULL);
        return TRUE;
    }

    st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, notify_callback);

    call_id = st->cmds->fence_with_delay(st,
                                         st_opt_allow_suicide,
                                         async_fence_data.target,
                                         async_fence_data.action,
                                         async_fence_data.timeout/1000,
                                         async_fence_data.tolerance/1000,
                                         async_fence_data.delay);

    if (call_id < 0) {
        g_main_loop_quit(mainloop);
        pcmk__set_result(&async_fence_data.result, CRM_EX_ERROR,
                         PCMK_EXEC_ERROR, pcmk_strerror(call_id));
        return TRUE;
    }

    st->cmds->register_callback(st,
                                call_id,
                                async_fence_data.timeout/1000,
                                st_opt_timeout_updates, NULL, "callback", fence_callback);

    return TRUE;
}

int
pcmk__fence_action(stonith_t *st, const char *target, const char *action,
                   const char *name, unsigned int timeout, unsigned int tolerance,
                   int delay)
{
    crm_trigger_t *trig;

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

    free(async_fence_data.name);

    return stonith__result2rc(&async_fence_data.result);
}

#ifdef BUILD_PUBLIC_LIBPACEMAKER
int
pcmk_fence_action(stonith_t *st, const char *target, const char *action,
                  const char *name, unsigned int timeout, unsigned int tolerance,
                  int delay)
{
    return pcmk__fence_action(st, target, action, name, timeout, tolerance, delay);
}
#endif

int
pcmk__fence_history(pcmk__output_t *out, stonith_t *st, char *target,
                    unsigned int timeout, int verbose, bool broadcast,
                    bool cleanup) {
    stonith_history_t *history = NULL, *hp, *latest = NULL;
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
    rc = st->cmds->history(st, opts,
                           pcmk__str_eq(target, "*", pcmk__str_none)? NULL : target,
                           &history, timeout/1000);

    if (cleanup) {
        // Cleanup doesn't return a history list
        stonith_history_free(history);
        return pcmk_legacy2rc(rc);
    }

    out->begin_list(out, "event", "events", "Fencing history");

    history = stonith__sort_history(history);
    for (hp = history; hp; hp = hp->next) {
        if (hp->state == st_done) {
            latest = hp;
        }

        if (out->is_quiet(out) || !verbose) {
            continue;
        }

        out->message(out, "stonith-event", hp, 1, stonith__later_succeeded(hp, history));
        out->increment_list(out);
    }

    if (latest) {
        if (out->is_quiet(out)) {
            pcmk__formatted_printf(out, "%lld\n", (long long) latest->completed);
        } else if (!verbose) { // already printed if verbose
            out->message(out, "stonith-event", latest, 0, FALSE);
            out->increment_list(out);
        }
    }

    out->end_list(out);

    stonith_history_free(history);
    return pcmk_legacy2rc(rc);
}

#ifdef BUILD_PUBLIC_LIBPACEMAKER
int
pcmk_fence_history(xmlNodePtr *xml, stonith_t *st, char *target, unsigned int timeout,
                   bool quiet, int verbose, bool broadcast, bool cleanup) {
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__out_prologue(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    stonith__register_messages(out);

    out->quiet = quiet;

    rc = pcmk__fence_history(out, st, target, timeout, verbose, broadcast, cleanup);
    pcmk__out_epilogue(out, xml, rc);
    return rc;
}
#endif

int
pcmk__fence_installed(pcmk__output_t *out, stonith_t *st, unsigned int timeout) {
    stonith_key_value_t *devices = NULL;
    int rc = pcmk_rc_ok;

    rc = st->cmds->list_agents(st, st_opt_sync_call, NULL, &devices, timeout/1000);
    /* list_agents returns a negative error code or a positive number of agents. */
    if (rc < 0) {
        return pcmk_legacy2rc(rc);
    }

    out->begin_list(out, "fence device", "fence devices", "Installed fence devices");
    for (stonith_key_value_t *dIter = devices; dIter; dIter = dIter->next) {
        out->list_item(out, "device", "%s", dIter->value);
    }
    out->end_list(out);

    stonith_key_value_freeall(devices, 1, 1);
    return pcmk_rc_ok;
}

#ifdef BUILD_PUBLIC_LIBPACEMAKER
int
pcmk_fence_installed(xmlNodePtr *xml, stonith_t *st, unsigned int timeout) {
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__out_prologue(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    stonith__register_messages(out);

    rc = pcmk__fence_installed(out, st, timeout);
    pcmk__out_epilogue(out, xml, rc);
    return rc;
}
#endif

int
pcmk__fence_last(pcmk__output_t *out, const char *target, bool as_nodeid) {
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

#ifdef BUILD_PUBLIC_LIBPACEMAKER
int
pcmk_fence_last(xmlNodePtr *xml, const char *target, bool as_nodeid) {
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__out_prologue(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    stonith__register_messages(out);

    rc = pcmk__fence_last(out, target, as_nodeid);
    pcmk__out_epilogue(out, xml, rc);
    return rc;
}
#endif

int
pcmk__fence_list_targets(pcmk__output_t *out, stonith_t *st,
                         const char *device_id, unsigned int timeout) {
    GList *targets = NULL;
    char *lists = NULL;
    int rc = pcmk_rc_ok;

    rc = st->cmds->list(st, st_opts, device_id, &lists, timeout/1000);
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

#ifdef BUILD_PUBLIC_LIBPACEMAKER
int
pcmk_fence_list_targets(xmlNodePtr *xml, stonith_t *st, const char *device_id,
                        unsigned int timeout) {
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__out_prologue(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    stonith__register_messages(out);

    rc = pcmk__fence_list_targets(out, st, device_id, timeout);
    pcmk__out_epilogue(out, xml, rc);
    return rc;
}
#endif

int
pcmk__fence_metadata(pcmk__output_t *out, stonith_t *st, char *agent,
                     unsigned int timeout) {
    char *buffer = NULL;
    int rc = st->cmds->metadata(st, st_opt_sync_call, agent, NULL, &buffer,
                                timeout/1000);

    if (rc != pcmk_rc_ok) {
        return pcmk_legacy2rc(rc);
    }

    out->output_xml(out, "metadata", buffer);
    free(buffer);
    return rc;
}

#ifdef BUILD_PUBLIC_LIBPACEMAKER
int
pcmk_fence_metadata(xmlNodePtr *xml, stonith_t *st, char *agent,
                    unsigned int timeout) {
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__out_prologue(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    stonith__register_messages(out);

    rc = pcmk__fence_metadata(out, st, agent, timeout);
    pcmk__out_epilogue(out, xml, rc);
    return rc;
}
#endif

int
pcmk__fence_registered(pcmk__output_t *out, stonith_t *st, char *target,
                       unsigned int timeout) {
    stonith_key_value_t *devices = NULL;
    int rc = pcmk_rc_ok;

    rc = st->cmds->query(st, st_opts, target, &devices, timeout/1000);
    /* query returns a negative error code or a positive number of results. */
    if (rc < 0) {
        return pcmk_legacy2rc(rc);
    }

    out->begin_list(out, "fence device", "fence devices", "Registered fence devices");
    for (stonith_key_value_t *dIter = devices; dIter; dIter = dIter->next) {
        out->list_item(out, "device", "%s", dIter->value);
    }
    out->end_list(out);

    stonith_key_value_freeall(devices, 1, 1);

    /* Return pcmk_rc_ok here, not the number of results.  Callers probably
     * don't care.
     */
    return pcmk_rc_ok;
}

#ifdef BUILD_PUBLIC_LIBPACEMAKER
int
pcmk_fence_registered(xmlNodePtr *xml, stonith_t *st, char *target,
                      unsigned int timeout) {
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__out_prologue(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    stonith__register_messages(out);

    rc = pcmk__fence_registered(out, st, target, timeout);
    pcmk__out_epilogue(out, xml, rc);
    return rc;
}
#endif

int
pcmk__fence_register_level(stonith_t *st, char *target, int fence_level,
                           stonith_key_value_t *devices) {
    return handle_level(st, target, fence_level, devices, true);
}

#ifdef BUILD_PUBLIC_LIBPACEMAKER
int
pcmk_fence_register_level(stonith_t *st, char *target, int fence_level,
                            stonith_key_value_t *devices) {
    return pcmk__fence_register_level(st, target, fence_level, devices);
}
#endif

int
pcmk__fence_unregister_level(stonith_t *st, char *target, int fence_level) {
    return handle_level(st, target, fence_level, NULL, false);
}

#ifdef BUILD_PUBLIC_LIBPACEMAKER
int
pcmk_fence_unregister_level(stonith_t *st, char *target, int fence_level) {
    return pcmk__fence_unregister_level(st, target, fence_level);
}
#endif

int
pcmk__fence_validate(pcmk__output_t *out, stonith_t *st, const char *agent,
                     const char *id, stonith_key_value_t *params,
                     unsigned int timeout) {
    char *output = NULL;
    char *error_output = NULL;
    int rc;

    rc  = st->cmds->validate(st, st_opt_sync_call, id, NULL, agent, params,
                             timeout/1000, &output, &error_output);
    out->message(out, "validate", agent, id, output, error_output, rc);
    return pcmk_legacy2rc(rc);
}

#ifdef BUILD_PUBLIC_LIBPACEMAKER
int
pcmk_fence_validate(xmlNodePtr *xml, stonith_t *st, const char *agent,
                    const char *id, stonith_key_value_t *params,
                    unsigned int timeout) {
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__out_prologue(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    stonith__register_messages(out);

    rc = pcmk__fence_validate(out, st, agent, id, params, timeout);
    pcmk__out_epilogue(out, xml, rc);
    return rc;
}
#endif

stonith_history_t *
pcmk__reduce_fence_history(stonith_history_t *history)
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
                if (pcmk__str_eq(hp->target, np->target, pcmk__str_casei) &&
                    pcmk__str_eq(hp->action, np->action, pcmk__str_casei) &&
                    (hp->state == np->state) &&
                    ((hp->state == st_done) ||
                     pcmk__str_eq(hp->delegate, np->delegate, pcmk__str_casei))) {
                        /* purge older hp */
                        stonith_history_free(hp);
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
