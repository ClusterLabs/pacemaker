/*
 * Copyright (C) 2010-2016 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

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
#include <crm/msg_xml.h>
#include "services_private.h"

#if SUPPORT_UPSTART
#  include <upstart.h>
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

svc_action_t *
services_action_create(const char *name, const char *action, int interval, int timeout)
{
    return resources_action_create(name, PCMK_RESOURCE_CLASS_LSB, NULL, name,
                                   action, interval, timeout, NULL, 0);
}

const char *
resources_find_service_class(const char *agent)
{
    /* Priority is:
     * - lsb
     * - systemd
     * - upstart
     */
    int rc = 0;
    struct stat st;
    char *path = NULL;

#ifdef LSB_ROOT_DIR
    rc = asprintf(&path, "%s/%s", LSB_ROOT_DIR, agent);
    if (rc > 0 && stat(path, &st) == 0) {
        free(path);
        return PCMK_RESOURCE_CLASS_LSB;
    }
    free(path);
#endif

#if SUPPORT_SYSTEMD
    if (systemd_unit_exists(agent)) {
        return PCMK_RESOURCE_CLASS_SYSTEMD;
    }
#endif

#if SUPPORT_UPSTART
    if (upstart_job_exists(agent)) {
        return PCMK_RESOURCE_CLASS_UPSTART;
    }
#endif
    return NULL;
}

/*!
 * \internal
 * \brief Check whether op is in-flight systemd or upstart op
 *
 * \param[in] op  Operation to check
 *
 * \return TRUE if op is in-flight systemd or upstart op
 */
static inline gboolean
inflight_systemd_or_upstart(svc_action_t *op)
{
    return (safe_str_eq(op->standard, PCMK_RESOURCE_CLASS_SYSTEMD)
            || safe_str_eq(op->standard, PCMK_RESOURCE_CLASS_UPSTART))
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

    if (strcasecmp(standard, PCMK_RESOURCE_CLASS_SERVICE) == 0) {
        const char *found_class = resources_find_service_class(agent);

        if (found_class) {
            crm_debug("Found %s agent %s for %s", found_class, agent, rsc);
            expanded_class = strdup(found_class);
        } else {
            crm_info("Assuming resource class lsb for agent %s for %s",
                     agent, rsc);
            expanded_class = strdup(PCMK_RESOURCE_CLASS_LSB);
        }
    } else {
        expanded_class = strdup(standard);
    }
    CRM_ASSERT(expanded_class);
    return expanded_class;
}

svc_action_t *
resources_action_create(const char *name, const char *standard, const char *provider,
                        const char *agent, const char *action, int interval, int timeout,
                        GHashTable * params, enum svc_action_flags flags)
{
    svc_action_t *op = NULL;

    /*
     * Do some up front sanity checks before we go off and
     * build the svc_action_t instance.
     */

    if (crm_strlen_zero(name)) {
        crm_err("Cannot create operation without resource name");
        goto return_error;
    }

    if (crm_strlen_zero(standard)) {
        crm_err("Cannot create operation for %s without resource class", name);
        goto return_error;
    }

    if (!strcasecmp(standard, PCMK_RESOURCE_CLASS_OCF)
        && crm_strlen_zero(provider)) {
        crm_err("Cannot create OCF operation for %s without provider", name);
        goto return_error;
    }

    if (crm_strlen_zero(agent)) {
        crm_err("Cannot create operation for %s without agent name", name);
        goto return_error;
    }

    if (crm_strlen_zero(action)) {
        crm_err("Cannot create operation for %s without operation name", name);
        goto return_error;
    }

    /*
     * Sanity checks passed, proceed!
     */

    op = calloc(1, sizeof(svc_action_t));
    op->opaque = calloc(1, sizeof(svc_action_private_t));
    op->rsc = strdup(name);
    op->interval = interval;
    op->timeout = timeout;
    op->standard = expand_resource_class(name, standard, agent);
    op->agent = strdup(agent);
    op->sequence = ++operations;
    op->flags = flags;
    op->id = generate_op_key(name, action, interval);

    if (safe_str_eq(action, "monitor") && (
#if SUPPORT_HEARTBEAT
        safe_str_eq(op->standard, PCMK_RESOURCE_CLASS_HB) ||
#endif
        safe_str_eq(op->standard, PCMK_RESOURCE_CLASS_LSB))) {
        action = "status";
    }
    op->action = strdup(action);

    if (strcasecmp(op->standard, PCMK_RESOURCE_CLASS_OCF) == 0) {
        op->provider = strdup(provider);
        op->params = params;
        params = NULL;

        if (asprintf(&op->opaque->exec, "%s/resource.d/%s/%s", OCF_ROOT_DIR, provider, agent) == -1) {
            crm_err("Internal error: cannot create agent path");
            goto return_error;
        }
        op->opaque->args[0] = strdup(op->opaque->exec);
        op->opaque->args[1] = strdup(action);

    } else if (strcasecmp(op->standard, PCMK_RESOURCE_CLASS_LSB) == 0) {
        if (op->agent[0] == '/') {
            /* if given an absolute path, use that instead
             * of tacking on the LSB_ROOT_DIR path to the front */
            op->opaque->exec = strdup(op->agent);
        } else if (asprintf(&op->opaque->exec, "%s/%s", LSB_ROOT_DIR, op->agent) == -1) {
            crm_err("Internal error: cannot create agent path");
            goto return_error;
        }
        op->opaque->args[0] = strdup(op->opaque->exec);
        op->opaque->args[1] = strdup(op->action);
        op->opaque->args[2] = NULL;
#if SUPPORT_HEARTBEAT
    } else if (strcasecmp(op->standard, PCMK_RESOURCE_CLASS_HB) == 0) {
        int index;
        int param_num;
        char buf_tmp[20];
        void *value_tmp;

        if (op->agent[0] == '/') {
            /* if given an absolute path, use that instead
             * of tacking on the HB_RA_DIR path to the front */
            op->opaque->exec = strdup(op->agent);
        } else if (asprintf(&op->opaque->exec, "%s/%s", HB_RA_DIR, op->agent) == -1) {
            crm_err("Internal error: cannot create agent path");
            goto return_error;
        }
        op->opaque->args[0] = strdup(op->opaque->exec);

        /* The "heartbeat" agent class only has positional arguments,
         * which we keyed by their decimal position number. */
        param_num = 1;
        for (index = 1; index <= MAX_ARGC - 3; index++ ) {
            snprintf(buf_tmp, sizeof(buf_tmp), "%d", index);
            value_tmp = g_hash_table_lookup(params, buf_tmp);
            if (value_tmp == NULL) {
                /* maybe: strdup("") ??
                 * But the old lrmd did simply continue as well. */
                continue;
            }
            op->opaque->args[param_num++] = strdup(value_tmp);
        }

        /* Add operation code as the last argument, */
        /* and the teminating NULL pointer */
        op->opaque->args[param_num++] = strdup(op->action);
        op->opaque->args[param_num] = NULL;
#endif
#if SUPPORT_SYSTEMD
    } else if (strcasecmp(op->standard, PCMK_RESOURCE_CLASS_SYSTEMD) == 0) {
        op->opaque->exec = strdup("systemd-dbus");
#endif
#if SUPPORT_UPSTART
    } else if (strcasecmp(op->standard, PCMK_RESOURCE_CLASS_UPSTART) == 0) {
        op->opaque->exec = strdup("upstart-dbus");
#endif
#if SUPPORT_NAGIOS
    } else if (strcasecmp(op->standard, PCMK_RESOURCE_CLASS_NAGIOS) == 0) {
        int index = 0;

        if (op->agent[0] == '/') {
            /* if given an absolute path, use that instead
             * of tacking on the NAGIOS_PLUGIN_DIR path to the front */
            op->opaque->exec = strdup(op->agent);

        } else if (asprintf(&op->opaque->exec, "%s/%s", NAGIOS_PLUGIN_DIR, op->agent) == -1) {
            crm_err("Internal error: cannot create agent path");
            goto return_error;
        }

        op->opaque->args[0] = strdup(op->opaque->exec);
        index = 1;

        if (safe_str_eq(op->action, "monitor") && op->interval == 0) {
            /* Invoke --version for a nagios probe */
            op->opaque->args[index] = strdup("--version");
            index++;

        } else if (params) {
            GHashTableIter iter;
            char *key = NULL;
            char *value = NULL;
            static int args_size = sizeof(op->opaque->args) / sizeof(char *);

            g_hash_table_iter_init(&iter, params);

            while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value) &&
                   index <= args_size - 3) {
                int len = 3;
                char *long_opt = NULL;

                if (safe_str_eq(key, XML_ATTR_CRM_VERSION) || strstr(key, CRM_META "_")) {
                    continue;
                }

                len += strlen(key);
                long_opt = calloc(1, len);
                sprintf(long_opt, "--%s", key);
                long_opt[len - 1] = 0;

                op->opaque->args[index] = long_opt;
                op->opaque->args[index + 1] = strdup(value);
                index += 2;
            }
        }
        op->opaque->args[index] = NULL;
#endif
    } else {
        crm_err("Unknown resource standard: %s", op->standard);
        services_action_free(op);
        op = NULL;
    }

    if(params) {
        g_hash_table_destroy(params);
    }
    return op;

  return_error:
    if(params) {
        g_hash_table_destroy(params);
    }
    services_action_free(op);

    return NULL;
}

svc_action_t *
services_action_create_generic(const char *exec, const char *args[])
{
    svc_action_t *op;
    unsigned int cur_arg;

    op = calloc(1, sizeof(*op));
    op->opaque = calloc(1, sizeof(svc_action_private_t));

    op->opaque->exec = strdup(exec);
    op->opaque->args[0] = strdup(exec);

    for (cur_arg = 1; args && args[cur_arg - 1]; cur_arg++) {
        op->opaque->args[cur_arg] = strdup(args[cur_arg - 1]);

        if (cur_arg == DIMOF(op->opaque->args) - 1) {
            crm_err("svc_action_t args list not long enough for '%s' execution request.", exec);
            break;
        }
    }

    return op;
}

#if SUPPORT_DBUS
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
            crm_info("Lost pending %s DBus call (%p)", op->id, op->opaque->pending);
        } else {
            crm_trace("Done with pending %s DBus call (%p)", op->id, op->opaque->pending);
        }
        dbus_pending_call_unref(op->opaque->pending);
    }
    op->opaque->pending = pending;
    if (pending) {
        crm_trace("Updated pending %s DBus call (%p)", op->id, pending);
    } else {
        crm_trace("Cleared pending %s DBus call", op->id);
    }
}
#endif

void
services_action_cleanup(svc_action_t * op)
{
    if(op->opaque == NULL) {
        return;
    }

#if SUPPORT_DBUS
    if(op->opaque->timerid != 0) {
        crm_trace("Removing timer for call %s to %s", op->action, op->rsc);
        g_source_remove(op->opaque->timerid);
        op->opaque->timerid = 0;
    }

    if(op->opaque->pending) {
        crm_trace("Cleaning up pending dbus call %p %s for %s", op->opaque->pending, op->action, op->rsc);
        if(dbus_pending_call_get_completed(op->opaque->pending)) {
            crm_warn("Pending dbus call %s for %s did not complete", op->action, op->rsc);
        }
        dbus_pending_call_cancel(op->opaque->pending);
        dbus_pending_call_unref(op->opaque->pending);
        op->opaque->pending = NULL;
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

    for (i = 0; i < DIMOF(op->opaque->args); i++) {
        free(op->opaque->args[i]);
    }

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
    crm_info("Cancelling %s operation %s", op->standard, op->id);

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
 * \param[in] name      Name of resource that operation is for
 * \param[in] action    Name of operation to cancel
 * \param[in] interval  Interval of operation to cancel
 *
 * \return TRUE if action was successfully cancelled, FALSE otherwise
 */
gboolean
services_action_cancel(const char *name, const char *action, int interval)
{
    gboolean cancelled = FALSE;
    char *id = generate_op_key(name, action, interval);
    svc_action_t *op = g_hash_table_lookup(recurring_actions, id);

    /* We can only cancel a recurring action */
    if (op == NULL) {
        goto done;
    }

    /* Tell operation_finalize() not to reschedule the operation */
    op->cancel = TRUE;

    /* Stop tracking it as a recurring operation, and stop its timer */
    cancel_recurring_action(op);

    /* If the op has a PID, it's an in-flight child process, so kill it.
     *
     * Whether the kill succeeds or fails, the main loop will send the op to
     * operation_finished() (and thus operation_finalize()) when the process
     * goes away.
     */
    if (op->pid != 0) {
        crm_info("Terminating in-flight op %s (pid %d) early because it was cancelled",
                 id, op->pid);
        cancelled = mainloop_child_kill(op->pid);
        if (cancelled == FALSE) {
            crm_err("Termination of %s (pid %d) failed", id, op->pid);
        }
        goto done;
    }

    /* In-flight systemd and upstart ops don't have a pid. The relevant handlers
     * will call operation_finalize() when the operation completes.
     * @TODO: Can we request early termination, maybe using
     * dbus_pending_call_cancel()?
     */
    if (inflight_systemd_or_upstart(op)) {
        crm_info("Will cancel %s op %s when in-flight instance completes",
                 op->standard, op->id);
        cancelled = FALSE;
        goto done;
    }

    /* Otherwise, operation is not in-flight, just report as cancelled */
    op->status = PCMK_LRM_OP_CANCELLED;
    if (op->opaque->callback) {
        op->opaque->callback(op);
    }

    blocked_ops = g_list_remove(blocked_ops, op);
    services_action_free(op);
    cancelled = TRUE;

done:
    free(id);
    return cancelled;
}

gboolean
services_action_kick(const char *name, const char *action, int interval /* ms */)
{
    svc_action_t * op = NULL;
    char *id = generate_op_key(name, action, interval);

    op = g_hash_table_lookup(recurring_actions, id);
    free(id);

    if (op == NULL) {
        return FALSE;
    }


    if (op->pid || inflight_systemd_or_upstart(op)) {
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

/* add new recurring operation, check for duplicates. 
 * - if duplicate found, return TRUE, immediately reschedule op.
 * - if no dup, return FALSE, inserve into recurring op list.*/
static gboolean
handle_duplicate_recurring(svc_action_t * op, void (*action_callback) (svc_action_t *))
{
    svc_action_t * dup = NULL;

    if (recurring_actions == NULL) {
        recurring_actions = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
        return FALSE;
    }

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
        /* free the dup.  */
        services_action_free(op);
        return TRUE;
    }

    return FALSE;
}

inline static gboolean
action_exec_helper(svc_action_t * op)
{
    /* Whether a/synchronous must be decided (op->synchronous) beforehand. */
    if (op->standard
        && (strcasecmp(op->standard, PCMK_RESOURCE_CLASS_UPSTART) == 0)) {
#if SUPPORT_UPSTART
        return upstart_job_exec(op);
#endif
    } else if (op->standard && strcasecmp(op->standard,
                                          PCMK_RESOURCE_CLASS_SYSTEMD) == 0) {
#if SUPPORT_SYSTEMD
        return systemd_unit_exec(op);
#endif
    } else {
        return services_os_action_execute(op);
    }
    /* The 'op' has probably been freed if the execution functions return TRUE
       for the asynchronous 'op'. */
    /* Avoid using the 'op' in here. */

    return FALSE;
}

void
services_add_inflight_op(svc_action_t * op)
{
    if (op == NULL) {
        return;
    }

    CRM_ASSERT(op->synchronous == FALSE);

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
services_untrack_op(svc_action_t *op)
{
    /* Op is no longer in-flight or blocked */
    inflight_ops = g_list_remove(inflight_ops, op);
    blocked_ops = g_list_remove(blocked_ops, op);

    /* Op is no longer blocking other ops, so check if any need to run */
    handle_blocked_ops();
}

gboolean
services_action_async(svc_action_t * op, void (*action_callback) (svc_action_t *))
{
    op->synchronous = false;
    if (action_callback) {
        op->opaque->callback = action_callback;
    }

    if (op->interval > 0) {
        if (handle_duplicate_recurring(op, action_callback) == TRUE) {
            /* entry rescheduled, dup freed */
            /* exit early */
            return TRUE;
        }
        g_hash_table_replace(recurring_actions, op->id, op);
    }

    if (op->rsc && is_op_blocked(op->rsc)) {
        blocked_ops = g_list_append(blocked_ops, op);
        return TRUE;
    }

    return action_exec_helper(op);
}


static gboolean processing_blocked_ops = FALSE;

gboolean
is_op_blocked(const char *rsc)
{
    GList *gIter = NULL;
    svc_action_t *op = NULL;

    for (gIter = inflight_ops; gIter != NULL; gIter = gIter->next) {
        op = gIter->data;
        if (safe_str_eq(op->rsc, rsc)) {
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
    gboolean res = FALSE;

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
        res = action_exec_helper(op);
        if (res == FALSE) {
            op->status = PCMK_LRM_OP_ERROR;
            /* this can cause this function to be called recursively
             * which is why we have processing_blocked_ops static variable */
            operation_finalize(op);
        }
    }

    for (gIter = executed_ops; gIter != NULL; gIter = gIter->next) {
        op = gIter->data;
        blocked_ops = g_list_remove(blocked_ops, op);
    }
    g_list_free(executed_ops);

    processing_blocked_ops = FALSE;
}

gboolean
services_action_sync(svc_action_t * op)
{
    gboolean rc = TRUE;

    if (op == NULL) {
        crm_trace("No operation to execute");
        return FALSE;
    }

    op->synchronous = true;
    rc = action_exec_helper(op);
    crm_trace(" > %s_%s_%d: %s = %d", op->rsc, op->action, op->interval, op->opaque->exec, op->rc);
    if (op->stdout_data) {
        crm_trace(" >  stdout: %s", op->stdout_data);
    }
    if (op->stderr_data) {
        crm_trace(" >  stderr: %s", op->stderr_data);
    }
    return rc;
}

GList *
get_directory_list(const char *root, gboolean files, gboolean executable)
{
    return services_os_get_directory_list(root, files, executable);
}

GList *
services_list(void)
{
    return resources_list_agents(PCMK_RESOURCE_CLASS_LSB, NULL);
}

#if SUPPORT_HEARTBEAT
static GList *
resources_os_list_hb_agents(void)
{
    return services_os_get_directory_list(HB_RA_DIR, TRUE, TRUE);
}
#endif

GList *
resources_list_standards(void)
{
    GList *standards = NULL;
    GList *agents = NULL;

    standards = g_list_append(standards, strdup(PCMK_RESOURCE_CLASS_OCF));
    standards = g_list_append(standards, strdup(PCMK_RESOURCE_CLASS_LSB));
    standards = g_list_append(standards, strdup(PCMK_RESOURCE_CLASS_SERVICE));

#if SUPPORT_SYSTEMD
    agents = systemd_unit_listall();
    if (agents) {
        standards = g_list_append(standards,
                                  strdup(PCMK_RESOURCE_CLASS_SYSTEMD));
        g_list_free_full(agents, free);
    }
#endif

#if SUPPORT_UPSTART
    agents = upstart_job_listall();
    if (agents) {
        standards = g_list_append(standards,
                                  strdup(PCMK_RESOURCE_CLASS_UPSTART));
        g_list_free_full(agents, free);
    }
#endif

#if SUPPORT_NAGIOS
    agents = resources_os_list_nagios_agents();
    if (agents) {
        standards = g_list_append(standards,
                                  strdup(PCMK_RESOURCE_CLASS_NAGIOS));
        g_list_free_full(agents, free);
    }
#endif

#if SUPPORT_HEARTBEAT
    standards = g_list_append(standards, strdup(PCMK_RESOURCE_CLASS_HB));
#endif

    return standards;
}

GList *
resources_list_providers(const char *standard)
{
    if (strcasecmp(standard, PCMK_RESOURCE_CLASS_OCF) == 0) {
        return resources_os_list_ocf_providers();
    }

    return NULL;
}

GList *
resources_list_agents(const char *standard, const char *provider)
{
    if ((standard == NULL)
        || (strcasecmp(standard, PCMK_RESOURCE_CLASS_SERVICE) == 0)) {

        GList *tmp1;
        GList *tmp2;
        GList *result = resources_os_list_lsb_agents();

        if (standard == NULL) {
            tmp1 = result;
            tmp2 = resources_os_list_ocf_agents(NULL);
            if (tmp2) {
                result = g_list_concat(tmp1, tmp2);
            }
        }
#if SUPPORT_SYSTEMD
        tmp1 = result;
        tmp2 = systemd_unit_listall();
        if (tmp2) {
            result = g_list_concat(tmp1, tmp2);
        }
#endif

#if SUPPORT_UPSTART
        tmp1 = result;
        tmp2 = upstart_job_listall();
        if (tmp2) {
            result = g_list_concat(tmp1, tmp2);
        }
#endif

        return result;

    } else if (strcasecmp(standard, PCMK_RESOURCE_CLASS_OCF) == 0) {
        return resources_os_list_ocf_agents(provider);
    } else if (strcasecmp(standard, PCMK_RESOURCE_CLASS_LSB) == 0) {
        return resources_os_list_lsb_agents();
#if SUPPORT_HEARTBEAT
    } else if (strcasecmp(standard, PCMK_RESOURCE_CLASS_HB) == 0) {
        return resources_os_list_hb_agents();
#endif
#if SUPPORT_SYSTEMD
    } else if (strcasecmp(standard, PCMK_RESOURCE_CLASS_SYSTEMD) == 0) {
        return systemd_unit_listall();
#endif
#if SUPPORT_UPSTART
    } else if (strcasecmp(standard, PCMK_RESOURCE_CLASS_UPSTART) == 0) {
        return upstart_job_listall();
#endif
#if SUPPORT_NAGIOS
    } else if (strcasecmp(standard, PCMK_RESOURCE_CLASS_NAGIOS) == 0) {
        return resources_os_list_nagios_agents();
#endif
    }

    return NULL;
}
