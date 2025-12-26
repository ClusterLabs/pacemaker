/*
 * Copyright 2010-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>                // bool, true, false
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/common/mainloop.h>
#include <crm/services.h>
#include <crm/services_internal.h>
#include <crm/stonith-ng.h>
#include <crm/common/xml.h>
#include "services_private.h"
#include "services_ocf.h"

#if PCMK__ENABLE_LSB
#include "services_lsb.h"
#endif

#if SUPPORT_SYSTEMD
#  include <systemd.h>
#endif

/* TODO: Develop a rollover strategy */

static int operations = 0;
static GHashTable *recurring_actions = NULL;

/* ops waiting to run async because of conflicting active
 * pending ops */
static GList *blocked_ops = NULL;

/* ops currently active (in-flight) */
static GList *inflight_ops = NULL;

static void handle_blocked_ops(void);

/*!
 * \brief Find first service class that can provide a specified agent
 *
 * \param[in] agent  Name of agent to search for
 *
 * \return Service class if found, NULL otherwise
 *
 * \note The priority is LSB then systemd. It would be preferable to put systemd
 *       first, but LSB merely requires a file existence check, while systemd
 *       requires contacting DBus.
 */
const char *
resources_find_service_class(const char *agent)
{
#if PCMK__ENABLE_LSB
    if (services__lsb_agent_exists(agent)) {
        return PCMK_RESOURCE_CLASS_LSB;
    }
#endif

#if SUPPORT_SYSTEMD
    if (systemd_unit_exists(agent)) {
        return PCMK_RESOURCE_CLASS_SYSTEMD;
    }
#endif

    return NULL;
}

static inline void
init_recurring_actions(void)
{
    if (recurring_actions == NULL) {
        recurring_actions = pcmk__strkey_table(NULL, NULL);
    }
}

/*!
 * \internal
 * \brief Check whether op is in-flight systemd op
 *
 * \param[in] op  Operation to check
 *
 * \return TRUE if op is in-flight systemd op
 */
static inline gboolean
inflight_systemd(const svc_action_t *op)
{
    return pcmk__str_eq(op->standard, PCMK_RESOURCE_CLASS_SYSTEMD,
                        pcmk__str_casei)
           && (g_list_find(inflight_ops, op) != NULL);
}

/*!
 * \internal
 * \brief Expand "service" alias to an actual resource class
 *
 * \param[in] rsc       Resource name (for logging only)
 * \param[in] standard  Resource class as configured
 * \param[in] agent     Agent name to look for
 *
 * \return Newly allocated string with actual resource class
 *
 * \note The caller is responsible for calling free() on the result.
 */
static char *
expand_resource_class(const char *rsc, const char *standard, const char *agent)
{
    char *expanded_class = NULL;

#if PCMK__ENABLE_SERVICE
    if (strcasecmp(standard, PCMK_RESOURCE_CLASS_SERVICE) == 0) {
        const char *found_class = resources_find_service_class(agent);

        if (found_class != NULL) {
            pcmk__debug("Found %s agent %s for %s", found_class, agent, rsc);
            expanded_class = pcmk__str_copy(found_class);
        } else {
            const char *default_standard = NULL;

#if PCMK__ENABLE_LSB
            default_standard = PCMK_RESOURCE_CLASS_LSB;
#elif SUPPORT_SYSTEMD
            default_standard = PCMK_RESOURCE_CLASS_SYSTEMD;
#else
#error No standards supported for service alias (configure script bug)
#endif
            pcmk__info("Assuming resource class %s for agent %s for %s",
                       default_standard, agent, rsc);
            expanded_class = pcmk__str_copy(default_standard);
        }
    }
#endif

    if (expanded_class == NULL) {
        expanded_class = pcmk__str_copy(standard);
    }
    return expanded_class;
}

/*!
 * \internal
 * \brief Create a simple svc_action_t instance
 *
 * \return Newly allocated instance (or NULL if not enough memory)
 */
static svc_action_t *
new_action(void)
{
    svc_action_t *op = calloc(1, sizeof(svc_action_t));

    if (op == NULL) {
        return NULL;
    }

    op->opaque = calloc(1, sizeof(svc_action_private_t));
    if (op->opaque == NULL) {
        free(op);
        return NULL;
    }

    // Initialize result
    services__set_result(op, PCMK_OCF_UNKNOWN, PCMK_EXEC_UNKNOWN, NULL);
    return op;
}

static bool
required_argument_missing(uint32_t ra_caps, const char *name,
                          const char *standard, const char *provider,
                          const char *agent, const char *action)
{
    if (pcmk__str_empty(name)) {
        pcmk__info("Cannot create operation without resource name (bug?)");
        return true;
    }

    if (pcmk__str_empty(standard)) {
        pcmk__info("Cannot create operation for %s without resource class "
                   "(bug?)",
                   name);
        return true;
    }

    if (pcmk__is_set(ra_caps, pcmk_ra_cap_provider)
        && pcmk__str_empty(provider)) {
        pcmk__info("Cannot create operation for %s resource %s without "
                   "provider (bug?)",
                   standard, name);
        return true;
    }

    if (pcmk__str_empty(agent)) {
        pcmk__info("Cannot create operation for %s without agent name (bug?)",
                   name);
        return true;
    }

    if (pcmk__str_empty(action)) {
        pcmk__info("Cannot create operation for %s without action name (bug?)",
                   name);
        return true;
    }
    return false;
}

// \return Standard Pacemaker return code (pcmk_rc_ok or ENOMEM)
static int
copy_action_arguments(svc_action_t *op, uint32_t ra_caps, const char *name,
                      const char *standard, const char *provider,
                      const char *agent, const char *action)
{
    op->rsc = strdup(name);
    if (op->rsc == NULL) {
        return ENOMEM;
    }

    op->agent = strdup(agent);
    if (op->agent == NULL) {
        return ENOMEM;
    }

    op->standard = expand_resource_class(name, standard, agent);
    if (op->standard == NULL) {
        return ENOMEM;
    }

    if (pcmk__is_set(ra_caps, pcmk_ra_cap_status)
        && pcmk__str_eq(action, PCMK_ACTION_MONITOR, pcmk__str_casei)) {
        action = PCMK_ACTION_STATUS;
    }
    op->action = strdup(action);
    if (op->action == NULL) {
        return ENOMEM;
    }

    if (pcmk__is_set(ra_caps, pcmk_ra_cap_provider)) {
        op->provider = strdup(provider);
        if (op->provider == NULL) {
            return ENOMEM;
        }
    }
    return pcmk_rc_ok;
}

// Takes ownership of params
svc_action_t *
services__create_resource_action(const char *name, const char *standard,
                        const char *provider, const char *agent,
                        const char *action, guint interval_ms, int timeout,
                        GHashTable *params, enum svc_action_flags flags)
{
    svc_action_t *op = NULL;
    uint32_t ra_caps = pcmk_get_ra_caps(standard);
    int rc = pcmk_rc_ok;

    op = new_action();
    if (op == NULL) {
        pcmk__crit("Cannot prepare action: %s", strerror(ENOMEM));
        if (params != NULL) {
            g_hash_table_destroy(params);
        }
        return NULL;
    }

    op->interval_ms = interval_ms;
    op->timeout = timeout;
    op->flags = flags;
    op->sequence = ++operations;

    // Take ownership of params
    if (pcmk__is_set(ra_caps, pcmk_ra_cap_params)) {
        op->params = params;
    } else if (params != NULL) {
        g_hash_table_destroy(params);
        params = NULL;
    }

    if (required_argument_missing(ra_caps, name, standard, provider, agent,
                                  action)) {
        services__set_result(op, services__generic_error(op),
                             PCMK_EXEC_ERROR_FATAL,
                             "Required agent or action information missing");
        return op;
    }

    op->id = pcmk__op_key(name, action, interval_ms);

    if (copy_action_arguments(op, ra_caps, name, standard, provider, agent,
                              action) != pcmk_rc_ok) {
        pcmk__crit("Cannot prepare %s action for %s: %s", action, name,
                   strerror(ENOMEM));
        services__handle_exec_error(op, ENOMEM);
        return op;
    }

    if (strcasecmp(op->standard, PCMK_RESOURCE_CLASS_OCF) == 0) {
        rc = services__ocf_prepare(op);

#if PCMK__ENABLE_LSB
    } else if (strcasecmp(op->standard, PCMK_RESOURCE_CLASS_LSB) == 0) {
        rc = services__lsb_prepare(op);
#endif
#if SUPPORT_SYSTEMD
    } else if (strcasecmp(op->standard, PCMK_RESOURCE_CLASS_SYSTEMD) == 0) {
        rc = services__systemd_prepare(op);
#endif
    } else {
        pcmk__info("Unknown resource standard: %s", op->standard);
        rc = ENOENT;
    }

    if (rc != pcmk_rc_ok) {
        pcmk__info("Cannot prepare %s operation for %s: %s", action, name,
                   strerror(rc));
        services__handle_exec_error(op, rc);
    }
    return op;
}

svc_action_t *
resources_action_create(const char *name, const char *standard,
                        const char *provider, const char *agent,
                        const char *action, guint interval_ms, int timeout,
                        GHashTable *params, enum svc_action_flags flags)
{
    svc_action_t *op = services__create_resource_action(name, standard,
                            provider, agent, action, interval_ms, timeout,
                            params, flags);
    if (op == NULL || op->rc != 0) {
        services_action_free(op);
        return NULL;
    } else {
        // Preserve public API backward compatibility
        op->rc = PCMK_OCF_OK;
        op->status = PCMK_EXEC_DONE;

        return op;
    }
}

svc_action_t *
services_action_create_generic(const char *exec, const char *args[])
{
    svc_action_t *op = new_action();

    pcmk__mem_assert(op);

    op->opaque->exec = strdup(exec);
    op->opaque->args[0] = strdup(exec);
    if ((op->opaque->exec == NULL) || (op->opaque->args[0] == NULL)) {
        pcmk__crit("Cannot prepare action for '%s': %s", exec,
                   strerror(ENOMEM));
        services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                             strerror(ENOMEM));
        return op;
    }

    if (args == NULL) {
        return op;
    }

    for (int cur_arg = 1; args[cur_arg - 1] != NULL; cur_arg++) {

        if (cur_arg == PCMK__NELEM(op->opaque->args)) {
            pcmk__info("Cannot prepare action for '%s': Too many arguments",
                       exec);
            services__set_result(op, PCMK_OCF_UNKNOWN_ERROR,
                                 PCMK_EXEC_ERROR_HARD, "Too many arguments");
            break;
        }

        op->opaque->args[cur_arg] = strdup(args[cur_arg - 1]);
        if (op->opaque->args[cur_arg] == NULL) {
            pcmk__crit("Cannot prepare action for '%s': %s", exec,
                       strerror(ENOMEM));
            services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                                 strerror(ENOMEM));
            break;
        }
    }

    return op;
}

/*!
 * \brief Create an alert agent action
 *
 * \param[in] id        Alert ID
 * \param[in] exec      Path to alert agent executable
 * \param[in] timeout   Action timeout
 * \param[in] params    Parameters to use with action
 * \param[in] sequence  Action sequence number
 * \param[in] cb_data   Data to pass to callback function
 *
 * \return New action on success, NULL on error
 * \note It is the caller's responsibility to free cb_data.
 *       The caller should not free params explicitly.
 */
svc_action_t *
services_alert_create(const char *id, const char *exec, int timeout,
                      GHashTable *params, int sequence, void *cb_data)
{
    svc_action_t *action = services_action_create_generic(exec, NULL);

    action->id = pcmk__str_copy(id);
    action->standard = pcmk__str_copy(PCMK_RESOURCE_CLASS_ALERT);
    action->timeout = timeout;
    action->params = params;
    action->sequence = sequence;
    action->cb_data = cb_data;
    return action;
}

/*!
 * \brief Set the user and group that an action will execute as
 *
 * \param[in,out] op      Action to modify
 * \param[in]     user    Name of user to execute action as
 * \param[in]     group   Name of group to execute action as
 *
 * \return pcmk_ok on success, -errno otherwise
 *
 * \note This will have no effect unless the process executing the action runs
 *       as root and the action is not a systemd action. We could implement this
 *       for systemd by adding User= and Group= to [Service] in the override
 *       file, but that seems more likely to cause problems than be useful.
 */
int
services_action_user(svc_action_t *op, const char *user)
{
    int rc = pcmk_ok;

    CRM_CHECK((op != NULL) && (user != NULL), return -EINVAL);

    rc = pcmk__lookup_user(user, &(op->opaque->uid), &(op->opaque->gid));
    return pcmk_rc2legacy(rc);
}

/*!
 * \brief Execute an alert agent action
 *
 * \param[in,out] action  Action to execute
 * \param[in]     cb      Function to call when action completes
 *
 * \return TRUE if the library will free action, FALSE otherwise
 *
 * \note If this function returns FALSE, it is the caller's responsibility to
 *       free the action with services_action_free(). However, unless someone
 *       intentionally creates a recurring alert action, this will never return
 *       FALSE.
 */
gboolean
services_alert_async(svc_action_t *action, void (*cb)(svc_action_t *op))
{
    action->synchronous = false;
    action->opaque->callback = cb;
    return services__execute_file(action) == pcmk_rc_ok;
}

#if HAVE_DBUS
/*!
 * \internal
 * \brief Update operation's pending DBus call, unreferencing old one if needed
 *
 * \param[in,out] op       Operation to modify
 * \param[in]     pending  Pending call to set
 */
void
services_set_op_pending(svc_action_t *op, DBusPendingCall *pending)
{
    if (op->opaque->pending && (op->opaque->pending != pending)) {
        if (pending) {
            pcmk__info("Lost pending %s DBus call (%p)", op->id,
                       op->opaque->pending);
        } else {
            pcmk__trace("Done with pending %s DBus call (%p)", op->id,
                        op->opaque->pending);
        }
        dbus_pending_call_unref(op->opaque->pending);
    }
    op->opaque->pending = pending;
    if (pending) {
        pcmk__trace("Updated pending %s DBus call (%p)", op->id, pending);
    } else {
        pcmk__trace("Cleared pending %s DBus call", op->id);
    }
}
#endif

void
services_action_cleanup(svc_action_t * op)
{
    if ((op == NULL) || (op->opaque == NULL)) {
        return;
    }

#if HAVE_DBUS
    if(op->opaque->timerid != 0) {
        pcmk__trace("Removing timer for call %s to %s", op->action, op->rsc);
        g_source_remove(op->opaque->timerid);
        op->opaque->timerid = 0;
    }

    if(op->opaque->pending) {
        if (dbus_pending_call_get_completed(op->opaque->pending)) {
            // This should never be the case
            pcmk__warn("Result of %s op %s was unhandled", op->standard,
                       op->id);
        } else {
            pcmk__debug("Will ignore any result of canceled %s op %s",
                        op->standard, op->id);
        }
        dbus_pending_call_cancel(op->opaque->pending);
        services_set_op_pending(op, NULL);
    }
#endif

    if (op->opaque->stderr_gsource) {
        mainloop_del_fd(op->opaque->stderr_gsource);
        op->opaque->stderr_gsource = NULL;
    }

    if (op->opaque->stdout_gsource) {
        mainloop_del_fd(op->opaque->stdout_gsource);
        op->opaque->stdout_gsource = NULL;
    }
}

/*!
 * \internal
 * \brief Map an actual resource action result to a standard OCF result
 *
 * \param[in] standard     Agent standard (must not be "service")
 * \param[in] action       Action that result is for
 * \param[in] exit_status  Actual agent exit status
 *
 * \return Standard OCF result
 */
enum ocf_exitcode
services_result2ocf(const char *standard, const char *action, int exit_status)
{
    if (pcmk__str_eq(standard, PCMK_RESOURCE_CLASS_OCF, pcmk__str_casei)) {
        return services__ocf2ocf(exit_status);

#if SUPPORT_SYSTEMD
    } else if (pcmk__str_eq(standard, PCMK_RESOURCE_CLASS_SYSTEMD,
                            pcmk__str_casei)) {
        return services__systemd2ocf(exit_status);
#endif

#if PCMK__ENABLE_LSB
    } else if (pcmk__str_eq(standard, PCMK_RESOURCE_CLASS_LSB,
                            pcmk__str_casei)) {
        return services__lsb2ocf(action, exit_status);
#endif

    } else {
        pcmk__warn("Treating result from unknown standard '%s' as OCF",
                   pcmk__s(standard, "unspecified"));
        return services__ocf2ocf(exit_status);
    }
}

void
services_action_free(svc_action_t * op)
{
    unsigned int i;

    if (op == NULL) {
        return;
    }

    /* The operation should be removed from all tracking lists by this point.
     * If it's not, we have a bug somewhere, so bail. That may lead to a
     * memory leak, but it's better than a use-after-free segmentation fault.
     */
    CRM_CHECK(g_list_find(inflight_ops, op) == NULL, return);
    CRM_CHECK(g_list_find(blocked_ops, op) == NULL, return);
    CRM_CHECK((recurring_actions == NULL)
              || (g_hash_table_lookup(recurring_actions, op->id) == NULL),
              return);

    services_action_cleanup(op);

    if (op->opaque->repeat_timer) {
        g_source_remove(op->opaque->repeat_timer);
        op->opaque->repeat_timer = 0;
    }

    free(op->id);
    free(op->opaque->exec);

    for (i = 0; i < PCMK__NELEM(op->opaque->args); i++) {
        free(op->opaque->args[i]);
    }

    free(op->opaque->exit_reason);

#if SUPPORT_SYSTEMD
    free(op->opaque->job_path);
#endif  // SUPPORT_SYSTEMD

    free(op->opaque);
    free(op->rsc);
    free(op->action);

    free(op->standard);
    free(op->agent);
    free(op->provider);

    free(op->stdout_data);
    free(op->stderr_data);

    if (op->params) {
        g_hash_table_destroy(op->params);
        op->params = NULL;
    }

    free(op);
}

gboolean
cancel_recurring_action(svc_action_t * op)
{
    pcmk__info("Cancelling %s operation %s", op->standard, op->id);

    if (recurring_actions) {
        g_hash_table_remove(recurring_actions, op->id);
    }

    if (op->opaque->repeat_timer) {
        g_source_remove(op->opaque->repeat_timer);
        op->opaque->repeat_timer = 0;
    }

    return TRUE;
}

/*!
 * \brief Cancel a recurring action
 *
 * \param[in] name         Name of resource that operation is for
 * \param[in] action       Name of operation to cancel
 * \param[in] interval_ms  Interval of operation to cancel
 *
 * \return TRUE if action was successfully cancelled, FALSE otherwise
 */
gboolean
services_action_cancel(const char *name, const char *action, guint interval_ms)
{
    gboolean cancelled = FALSE;
    char *id = pcmk__op_key(name, action, interval_ms);
    svc_action_t *op = NULL;

    /* We can only cancel a recurring action */
    init_recurring_actions();
    op = g_hash_table_lookup(recurring_actions, id);
    if (op == NULL) {
        goto done;
    }

    // Tell services__finalize_async_op() not to reschedule the operation
    op->cancel = TRUE;

    /* Stop tracking it as a recurring operation, and stop its repeat timer */
    cancel_recurring_action(op);

    /* If the op has a PID, it's an in-flight child process, so kill it.
     *
     * Whether the kill succeeds or fails, the main loop will send the op to
     * async_action_complete() (and thus services__finalize_async_op()) when the
     * process goes away.
     */
    if (op->pid != 0) {
        pcmk__info("Terminating in-flight op %s[%d] early because it was "
                   "cancelled",
                   id, op->pid);
        cancelled = mainloop_child_kill(op->pid);
        if (cancelled == FALSE) {
            pcmk__err("Termination of %s[%d] failed", id, op->pid);
        }
        goto done;
    }

#if HAVE_DBUS
    // In-flight systemd ops don't have a pid
    if (inflight_systemd(op)) {
        inflight_ops = g_list_remove(inflight_ops, op);

        /* This will cause any result that comes in later to be discarded, so we
         * don't call the callback and free the operation twice.
         */
        services_action_cleanup(op);
    }
#endif

    /* The rest of this is essentially equivalent to
     * services__finalize_async_op(), minus the handle_blocked_ops() call.
     */

    // Report operation as cancelled
    services__set_cancelled(op);
    if (op->opaque->callback) {
        op->opaque->callback(op);
    }

    blocked_ops = g_list_remove(blocked_ops, op);
    services_action_free(op);
    cancelled = TRUE;
    // @TODO Initiate handle_blocked_ops() asynchronously

done:
    free(id);
    return cancelled;
}

gboolean
services_action_kick(const char *name, const char *action, guint interval_ms)
{
    svc_action_t * op = NULL;
    char *id = pcmk__op_key(name, action, interval_ms);

    init_recurring_actions();
    op = g_hash_table_lookup(recurring_actions, id);
    free(id);

    if (op == NULL) {
        return FALSE;
    }


    if (op->pid || inflight_systemd(op)) {
        return TRUE;
    } else {
        if (op->opaque->repeat_timer) {
            g_source_remove(op->opaque->repeat_timer);
            op->opaque->repeat_timer = 0;
        }
        recurring_action_timer(op);
        return TRUE;
    }

}

/*!
 * \internal
 * \brief Add a new recurring operation, checking for duplicates
 *
 * \param[in,out] op  Operation to add
 *
 * \return TRUE if duplicate found (and reschedule), FALSE otherwise
 */
static gboolean
handle_duplicate_recurring(svc_action_t *op)
{
    svc_action_t * dup = NULL;

    /* check for duplicates */
    dup = g_hash_table_lookup(recurring_actions, op->id);

    if (dup && (dup != op)) {
        /* update user data */
        if (op->opaque->callback) {
            dup->opaque->callback = op->opaque->callback;
            dup->cb_data = op->cb_data;
            op->cb_data = NULL;
        }
        /* immediately execute the next interval */
        if (dup->pid != 0) {
            if (op->opaque->repeat_timer) {
                g_source_remove(op->opaque->repeat_timer);
                op->opaque->repeat_timer = 0;
            }
            recurring_action_timer(dup);
        }
        /* free the duplicate */
        services_action_free(op);
        return TRUE;
    }

    return FALSE;
}

/*!
 * \internal
 * \brief Execute an action appropriately according to its standard
 *
 * \param[in,out] op  Action to execute
 *
 * \return Standard Pacemaker return code
 * \retval EBUSY          Recurring operation could not be initiated
 * \retval pcmk_rc_error  Synchronous action failed
 * \retval pcmk_rc_ok     Synchronous action succeeded, or asynchronous action
 *                        should not be freed (because it's pending or because
 *                        it failed to execute and was already freed)
 *
 * \note If the return value for an asynchronous action is not pcmk_rc_ok, the
 *       caller is responsible for freeing the action.
 */
static int
execute_action(svc_action_t *op)
{
#if SUPPORT_SYSTEMD
    if (pcmk__str_eq(op->standard, PCMK_RESOURCE_CLASS_SYSTEMD,
                     pcmk__str_casei)) {
        return services__execute_systemd(op);
    }
#endif

    return services__execute_file(op);
}

void
services_add_inflight_op(svc_action_t * op)
{
    if (op == NULL) {
        return;
    }

    pcmk__assert(op->synchronous == FALSE);

    /* keep track of ops that are in-flight to avoid collisions in the same namespace */
    if (op->rsc) {
        inflight_ops = g_list_append(inflight_ops, op);
    }
}

/*!
 * \internal
 * \brief Stop tracking an operation that completed
 *
 * \param[in] op  Operation to stop tracking
 */
void
services_untrack_op(const svc_action_t *op)
{
    /* Op is no longer in-flight or blocked */
    inflight_ops = g_list_remove(inflight_ops, op);
    blocked_ops = g_list_remove(blocked_ops, op);

    /* Op is no longer blocking other ops, so check if any need to run */
    handle_blocked_ops();
}

gboolean
services_action_async_fork_notify(svc_action_t * op,
                                  void (*action_callback) (svc_action_t *),
                                  void (*action_fork_callback) (svc_action_t *))
{
    CRM_CHECK(op != NULL, return TRUE);

    op->synchronous = false;
    if (action_callback != NULL) {
        op->opaque->callback = action_callback;
    }
    if (action_fork_callback != NULL) {
        op->opaque->fork_callback = action_fork_callback;
    }

    if (op->interval_ms > 0) {
        init_recurring_actions();
        if (handle_duplicate_recurring(op)) {
            /* entry rescheduled, dup freed */
            /* exit early */
            return TRUE;
        }
        g_hash_table_replace(recurring_actions, op->id, op);
    }

    if (!pcmk__is_set(op->flags, SVC_ACTION_NON_BLOCKED)
        && (op->rsc != NULL) && is_op_blocked(op->rsc)) {
        blocked_ops = g_list_append(blocked_ops, op);
        return TRUE;
    }

    return execute_action(op) == pcmk_rc_ok;
}

gboolean
services_action_async(svc_action_t * op,
                      void (*action_callback) (svc_action_t *))
{
    return services_action_async_fork_notify(op, action_callback, NULL);
}

static gboolean processing_blocked_ops = FALSE;

gboolean
is_op_blocked(const char *rsc)
{
    GList *gIter = NULL;
    svc_action_t *op = NULL;

    for (gIter = inflight_ops; gIter != NULL; gIter = gIter->next) {
        op = gIter->data;
        if (pcmk__str_eq(op->rsc, rsc, pcmk__str_none)) {
            return TRUE;
        }
    }

    return FALSE;
}

static void
handle_blocked_ops(void)
{
    GList *executed_ops = NULL;
    GList *gIter = NULL;
    svc_action_t *op = NULL;

    if (processing_blocked_ops) {
        /* avoid nested calling of this function */
        return;
    }

    processing_blocked_ops = TRUE;

    /* n^2 operation here, but blocked ops are incredibly rare. this list
     * will be empty 99% of the time. */
    for (gIter = blocked_ops; gIter != NULL; gIter = gIter->next) {
        op = gIter->data;
        if (is_op_blocked(op->rsc)) {
            continue;
        }
        executed_ops = g_list_append(executed_ops, op);
        if (execute_action(op) != pcmk_rc_ok) {
            /* this can cause this function to be called recursively
             * which is why we have processing_blocked_ops static variable */
            services__finalize_async_op(op);
        }
    }

    for (gIter = executed_ops; gIter != NULL; gIter = gIter->next) {
        op = gIter->data;
        blocked_ops = g_list_remove(blocked_ops, op);
    }
    g_list_free(executed_ops);

    processing_blocked_ops = FALSE;
}

/*!
 * \internal
 * \brief Execute a meta-data action appropriately to standard
 *
 * \param[in,out] op  Meta-data action to execute
 *
 * \return Standard Pacemaker return code
 */
static int
execute_metadata_action(svc_action_t *op)
{
    const char *class = op->standard;

    if (op->agent == NULL) {
        pcmk__info("Meta-data requested without specifying agent");
        services__set_result(op, services__generic_error(op),
                             PCMK_EXEC_ERROR_FATAL, "Agent not specified");
        return EINVAL;
    }

    if (class == NULL) {
        pcmk__info("Meta-data requested for agent %s without specifying class",
                   op->agent);
        services__set_result(op, services__generic_error(op),
                             PCMK_EXEC_ERROR_FATAL,
                             "Agent standard not specified");
        return EINVAL;
    }

#if PCMK__ENABLE_SERVICE
    if (!strcmp(class, PCMK_RESOURCE_CLASS_SERVICE)) {
        class = resources_find_service_class(op->agent);
    }
    if (class == NULL) {
        pcmk__info("Meta-data requested for %s, but could not determine class",
                   op->agent);
        services__set_result(op, services__generic_error(op),
                             PCMK_EXEC_ERROR_HARD,
                             "Agent standard could not be determined");
        return EINVAL;
    }
#endif

#if PCMK__ENABLE_LSB
    if (pcmk__str_eq(class, PCMK_RESOURCE_CLASS_LSB, pcmk__str_casei)) {
        return pcmk_legacy2rc(services__get_lsb_metadata(op->agent,
                                                         &op->stdout_data));
    }
#endif

    return execute_action(op);
}

gboolean
services_action_sync(svc_action_t * op)
{
    gboolean rc = TRUE;

    if (op == NULL) {
        pcmk__trace("No operation to execute");
        return FALSE;
    }

    op->synchronous = true;

    if (pcmk__str_eq(op->action, PCMK_ACTION_META_DATA, pcmk__str_casei)) {
        /* Synchronous meta-data operations are handled specially. Since most
         * resource classes don't provide any meta-data, it has to be
         * synthesized from available information about the agent.
         *
         * services_action_async() doesn't treat meta-data actions specially, so
         * it will result in an error for classes that don't support the action.
         */
        rc = (execute_metadata_action(op) == pcmk_rc_ok);
    } else {
        rc = (execute_action(op) == pcmk_rc_ok);
    }
    pcmk__trace(" > " PCMK__OP_FMT ": %s = %d", op->rsc, op->action,
                op->interval_ms, op->opaque->exec, op->rc);
    if (op->stdout_data) {
        pcmk__trace(" >  stdout: %s", op->stdout_data);
    }
    if (op->stderr_data) {
        pcmk__trace(" >  stderr: %s", op->stderr_data);
    }
    return rc;
}

GList *
resources_list_standards(void)
{
    GList *standards = NULL;

    standards = g_list_append(standards, strdup(PCMK_RESOURCE_CLASS_OCF));

#if PCMK__ENABLE_SERVICE
    standards = g_list_append(standards, strdup(PCMK_RESOURCE_CLASS_SERVICE));
#endif

#if PCMK__ENABLE_LSB
    standards = g_list_append(standards, strdup(PCMK_RESOURCE_CLASS_LSB));
#endif

#if SUPPORT_SYSTEMD
    {
        GList *agents = systemd_unit_listall();

        if (agents != NULL) {
            standards = g_list_append(standards,
                                      strdup(PCMK_RESOURCE_CLASS_SYSTEMD));
            g_list_free_full(agents, free);
        }
    }
#endif

    return standards;
}

GList *
resources_list_providers(const char *standard)
{
    if (pcmk__is_set(pcmk_get_ra_caps(standard), pcmk_ra_cap_provider)) {
        return services__list_ocf_providers();
    }

    return NULL;
}

GList *
resources_list_agents(const char *standard, const char *provider)
{
    if ((standard == NULL)
#if PCMK__ENABLE_SERVICE
        || (strcasecmp(standard, PCMK_RESOURCE_CLASS_SERVICE) == 0)
#endif
        ) {

        GList *tmp1;
        GList *tmp2;
        GList *result = NULL;

        if (standard == NULL) {
            tmp1 = result;
            tmp2 = services__list_ocf_agents(NULL);
            if (tmp2) {
                result = g_list_concat(tmp1, tmp2);
            }
        }

#if PCMK__ENABLE_LSB
        result = g_list_concat(result, services__list_lsb_agents());
#endif

#if SUPPORT_SYSTEMD
        tmp1 = result;
        tmp2 = systemd_unit_listall();
        if (tmp2) {
            result = g_list_concat(tmp1, tmp2);
        }
#endif

        return result;

    } else if (strcasecmp(standard, PCMK_RESOURCE_CLASS_OCF) == 0) {
        return services__list_ocf_agents(provider);
#if PCMK__ENABLE_LSB
    } else if (strcasecmp(standard, PCMK_RESOURCE_CLASS_LSB) == 0) {
        return services__list_lsb_agents();
#endif
#if SUPPORT_SYSTEMD
    } else if (strcasecmp(standard, PCMK_RESOURCE_CLASS_SYSTEMD) == 0) {
        return systemd_unit_listall();
#endif
    }

    return NULL;
}

gboolean
resources_agent_exists(const char *standard, const char *provider, const char *agent)
{
    GList *standards = NULL;
    GList *providers = NULL;
    GList *iter = NULL;
    gboolean rc = FALSE;
    gboolean has_providers = FALSE;

    standards = resources_list_standards();
    for (iter = standards; iter != NULL; iter = iter->next) {
        if (pcmk__str_eq(iter->data, standard, pcmk__str_none)) {
            rc = TRUE;
            break;
        }
    }

    if (rc == FALSE) {
        goto done;
    }

    rc = FALSE;

    has_providers = pcmk__is_set(pcmk_get_ra_caps(standard),
                                 pcmk_ra_cap_provider);
    if (has_providers == TRUE && provider != NULL) {
        providers = resources_list_providers(standard);
        for (iter = providers; iter != NULL; iter = iter->next) {
            if (pcmk__str_eq(iter->data, provider, pcmk__str_none)) {
                rc = TRUE;
                break;
            }
        }
    } else if (has_providers == FALSE && provider == NULL) {
        rc = TRUE;
    }

    if (rc == FALSE) {
        goto done;
    }

#if PCMK__ENABLE_SERVICE
    if (pcmk__str_eq(standard, PCMK_RESOURCE_CLASS_SERVICE, pcmk__str_casei)) {
#if PCMK__ENABLE_LSB
        if (services__lsb_agent_exists(agent)) {
            rc = TRUE;
            goto done;
        }
#endif
#if SUPPORT_SYSTEMD
        if (systemd_unit_exists(agent)) {
            rc = TRUE;
            goto done;
        }
#endif
        rc = FALSE;
        goto done;
    }
#endif

    if (pcmk__str_eq(standard, PCMK_RESOURCE_CLASS_OCF, pcmk__str_casei)) {
        rc = services__ocf_agent_exists(provider, agent, NULL);

#if PCMK__ENABLE_LSB
    } else if (pcmk__str_eq(standard, PCMK_RESOURCE_CLASS_LSB, pcmk__str_casei)) {
        rc = services__lsb_agent_exists(agent);
#endif

#if SUPPORT_SYSTEMD
    } else if (pcmk__str_eq(standard, PCMK_RESOURCE_CLASS_SYSTEMD, pcmk__str_casei)) {
        rc = systemd_unit_exists(agent);
#endif

    } else {
        rc = FALSE;
    }

done:
    g_list_free(standards);
    g_list_free(providers);
    return rc;
}

/*!
 * \internal
 * \brief Set the result of an action
 *
 * \param[out] action        Where to set action result
 * \param[in]  agent_status  Exit status to set
 * \param[in]  exec_status   Execution status to set
 * \param[in]  reason        Human-friendly description of event to set
 */
void
services__set_result(svc_action_t *action, int agent_status,
                     enum pcmk_exec_status exec_status, const char *reason)
{
    if (action == NULL) {
        return;
    }

    action->rc = agent_status;
    action->status = exec_status;

    if (!pcmk__str_eq(action->opaque->exit_reason, reason,
                      pcmk__str_none)) {
        free(action->opaque->exit_reason);
        action->opaque->exit_reason = (reason == NULL)? NULL : strdup(reason);
    }
}

/*!
 * \internal
 * \brief Set a \c pcmk__action_result_t based on a \c svc_action_t
 *
 * \param[in]     action  Service action whose result to copy
 * \param[in,out] result  Action result object to set
 */
void
services__copy_result(const svc_action_t *action, pcmk__action_result_t *result)
{
    pcmk__set_result(result, action->rc, action->status,
                     action->opaque->exit_reason);
}

/*!
 * \internal
 * \brief Set the result of an action, with a formatted exit reason
 *
 * \param[out] action        Where to set action result
 * \param[in]  agent_status  Exit status to set
 * \param[in]  exec_status   Execution status to set
 * \param[in]  format        printf-style format for a human-friendly
 *                           description of reason for result
 * \param[in]  ...           arguments for \p format
 */
void
services__format_result(svc_action_t *action, int agent_status,
                        enum pcmk_exec_status exec_status,
                        const char *format, ...)
{
    va_list ap;
    int len = 0;
    char *reason = NULL;

    if (action == NULL) {
        return;
    }

    action->rc = agent_status;
    action->status = exec_status;

    if (format != NULL) {
        va_start(ap, format);
        len = vasprintf(&reason, format, ap);
        pcmk__assert(len > 0);
        va_end(ap);
    }
    free(action->opaque->exit_reason);
    action->opaque->exit_reason = reason;
}

/*!
 * \internal
 * \brief Set the result of an action to cancelled
 *
 * \param[out] action        Where to set action result
 *
 * \note This sets execution status but leaves the exit status unchanged
 */
void
services__set_cancelled(svc_action_t *action)
{
    if (action != NULL) {
        action->status = PCMK_EXEC_CANCELLED;
        free(action->opaque->exit_reason);
        action->opaque->exit_reason = NULL;
    }
}

/*!
 * \internal
 * \brief Get a readable description of what an action is for
 *
 * \param[in] action  Action to check
 *
 * \return Readable name for the kind of \p action
 */
const char *
services__action_kind(const svc_action_t *action)
{
    if ((action == NULL) || (action->standard == NULL)) {
        return "Process";
    } else if (pcmk__str_eq(action->standard, PCMK_RESOURCE_CLASS_STONITH,
                            pcmk__str_none)) {
        return "Fence agent";
    } else if (pcmk__str_eq(action->standard, PCMK_RESOURCE_CLASS_ALERT,
                            pcmk__str_none)) {
        return "Alert agent";
    } else {
        return "Resource agent";
    }
}

/*!
 * \internal
 * \brief Get the exit reason of an action
 *
 * \param[in] action  Action to check
 *
 * \return Action's exit reason (or NULL if none)
 */
const char *
services__exit_reason(const svc_action_t *action)
{
    return action->opaque->exit_reason;
}

/*!
 * \internal
 * \brief Steal stdout from an action
 *
 * \param[in,out] action  Action whose stdout is desired
 *
 * \return Action's stdout (which may be NULL)
 * \note Upon return, \p action will no longer track the output, so it is the
 *       caller's responsibility to free the return value.
 */
char *
services__grab_stdout(svc_action_t *action)
{
    char *output = action->stdout_data;

    action->stdout_data = NULL;
    return output;
}

/*!
 * \internal
 * \brief Steal stderr from an action
 *
 * \param[in,out] action  Action whose stderr is desired
 *
 * \return Action's stderr (which may be NULL)
 * \note Upon return, \p action will no longer track the output, so it is the
 *       caller's responsibility to free the return value.
 */
char *
services__grab_stderr(svc_action_t *action)
{
    char *output = action->stderr_data;

    action->stderr_data = NULL;
    return output;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/services_compat.h>

static GList *
gdl_helper(const char *dir, bool files, bool executable)
{
    GList *list = NULL;
    struct dirent **namelist = NULL;
    int entries = scandir(dir, &namelist, NULL, alphasort);

    if (entries < 0) {
        return NULL;
    }

    for (int i = 0; i < entries; i++) {
        char *buffer = NULL;
        struct stat sb;
        int rc = 0;

        if ('.' == namelist[i]->d_name[0]) {
            continue;
        }

        buffer = pcmk__assert_asprintf("%s/%s", dir, namelist[i]->d_name);
        rc = stat(buffer, &sb);
        free(buffer);

        if (rc != 0) {
            continue;
        }

        if (S_ISDIR(sb.st_mode)) {
            if (files) {
                continue;
            }

        } else if (S_ISREG(sb.st_mode)) {
            if (!files) {
                continue;
            }

            if (executable
                && !pcmk__any_flags_set(sb.st_mode, S_IXUSR|S_IXGRP|S_IXOTH)) {
                continue;
            }
        }

        list = g_list_append(list, pcmk__str_copy(namelist[i]->d_name));
    }

    for (int i = 0; i < entries; i++) {
        free(namelist[i]);
    }
    free(namelist);
    return list;
}

GList *
get_directory_list(const char *root, gboolean files, gboolean executable)
{
    gchar **dir_paths = NULL;
    GList *list = NULL;

    if (pcmk__str_empty(root)) {
        return NULL;
    }

    dir_paths = g_strsplit(root, ":", 0);

    for (const char *const *dir = (const char *const *) dir_paths;
         *dir != NULL; dir++) {

        list = g_list_concat(list, gdl_helper(*dir, files, executable));
    }

    g_strfreev(dir_paths);
    return list;
}

// LCOV_EXCL_STOP
// End deprecated API
