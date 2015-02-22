/*
 * Copyright (C) 2010 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
GHashTable *recurring_actions = NULL;

svc_action_t *
services_action_create(const char *name, const char *action, int interval, int timeout)
{
    return resources_action_create(name, "lsb", NULL, name, action, interval, timeout, NULL);
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
        return "lsb";
    }
    free(path);
#endif

#if SUPPORT_SYSTEMD
    if (systemd_unit_exists(agent)) {
        return "systemd";
    }
#endif

#if SUPPORT_UPSTART
    if (upstart_job_exists(agent)) {
        return "upstart";
    }
#endif
    return NULL;
}


svc_action_t *
resources_action_create(const char *name, const char *standard, const char *provider,
                        const char *agent, const char *action, int interval, int timeout,
                        GHashTable * params)
{
    svc_action_t *op = NULL;

    /*
     * Do some up front sanity checks before we go off and
     * build the svc_action_t instance.
     */

    if (crm_strlen_zero(name)) {
        crm_err("A service or resource action must have a name.");
        goto return_error;
    }

    if (crm_strlen_zero(standard)) {
        crm_err("A service action must have a valid standard.");
        goto return_error;
    }

    if (!strcasecmp(standard, "ocf") && crm_strlen_zero(provider)) {
        crm_err("An OCF resource action must have a provider.");
        goto return_error;
    }

    if (crm_strlen_zero(agent)) {
        crm_err("A service or resource action must have an agent.");
        goto return_error;
    }

    if (crm_strlen_zero(action)) {
        crm_err("A service or resource action must specify an action.");
        goto return_error;
    }

    if (safe_str_eq(action, "monitor") && (
#if SUPPORT_HEARTBEAT
        safe_str_eq(standard, "heartbeat") ||
#endif
        safe_str_eq(standard, "lsb") || safe_str_eq(standard, "service"))) {
        action = "status";
    }

    /*
     * Sanity checks passed, proceed!
     */

    op = calloc(1, sizeof(svc_action_t));
    op->opaque = calloc(1, sizeof(svc_action_private_t));
    op->rsc = strdup(name);
    op->action = strdup(action);
    op->interval = interval;
    op->timeout = timeout;
    op->standard = strdup(standard);
    op->agent = strdup(agent);
    op->sequence = ++operations;
    if (asprintf(&op->id, "%s_%s_%d", name, action, interval) == -1) {
        goto return_error;
    }

    if (strcasecmp(op->standard, "service") == 0) {
        const char *expanded = resources_find_service_class(op->agent);

        if(expanded) {
            crm_debug("Found a %s agent for %s/%s", expanded, op->rsc, op->agent);
            free(op->standard);
            op->standard = strdup(expanded);

        } else {
            crm_info("Cannot determine the standard for %s (%s)", op->rsc, op->agent);
            free(op->standard);
            op->standard = strdup("lsb");
        }
        CRM_ASSERT(op->standard);
    }

    if (strcasecmp(op->standard, "ocf") == 0) {
        op->provider = strdup(provider);
        op->params = params;
        params = NULL;

        if (asprintf(&op->opaque->exec, "%s/resource.d/%s/%s", OCF_ROOT_DIR, provider, agent) == -1) {
            crm_err("Internal error: cannot create agent path");
            goto return_error;
        }
        op->opaque->args[0] = strdup(op->opaque->exec);
        op->opaque->args[1] = strdup(action);

    } else if (strcasecmp(op->standard, "lsb") == 0) {
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
    } else if (strcasecmp(op->standard, "heartbeat") == 0) {
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
    } else if (strcasecmp(op->standard, "systemd") == 0) {
        op->opaque->exec = strdup("systemd-dbus");
#endif
#if SUPPORT_UPSTART
    } else if (strcasecmp(op->standard, "upstart") == 0) {
        op->opaque->exec = strdup("upstart-dbus");
#endif
    } else if (strcasecmp(op->standard, "service") == 0) {
        op->opaque->exec = strdup(SERVICE_SCRIPT);
        op->opaque->args[0] = strdup(SERVICE_SCRIPT);
        op->opaque->args[1] = strdup(agent);
        op->opaque->args[2] = strdup(action);

#if SUPPORT_NAGIOS
    } else if (strcasecmp(op->standard, "nagios") == 0) {
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

void
services_action_cleanup(svc_action_t * op)
{
#if SUPPORT_DBUS
    if(op->opaque == NULL) {
        return;
    }

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

    if (op->opaque->stderr_gsource) {
        mainloop_del_fd(op->opaque->stderr_gsource);
        op->opaque->stderr_gsource = NULL;
    }

    if (op->opaque->stdout_gsource) {
        mainloop_del_fd(op->opaque->stdout_gsource);
        op->opaque->stdout_gsource = NULL;
    }
#endif
}

void
services_action_free(svc_action_t * op)
{
    unsigned int i;

    if (op == NULL) {
        return;
    }

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
    crm_info("Cancelling operation %s", op->id);

    if (recurring_actions) {
        g_hash_table_remove(recurring_actions, op->id);
    }

    if (op->opaque->repeat_timer) {
        g_source_remove(op->opaque->repeat_timer);
        op->opaque->repeat_timer = 0;
    }

    return TRUE;
}

gboolean
services_action_cancel(const char *name, const char *action, int interval)
{
    svc_action_t *op = NULL;
    char id[512];

    snprintf(id, sizeof(id), "%s_%s_%d", name, action, interval);

    if (!(op = g_hash_table_lookup(recurring_actions, id))) {
        return FALSE;
    }

    /* Always kill the recurring timer */
    cancel_recurring_action(op);

    if (op->pid == 0) {
        op->status = PCMK_LRM_OP_CANCELLED;
        if (op->opaque->callback) {
            op->opaque->callback(op);
        }
        services_action_free(op);

    } else {
        crm_info("Cancelling in-flight op: performing early termination of %s (pid=%d)", id, op->pid);
        op->cancel = 1;
        if (mainloop_child_kill(op->pid) == FALSE) {
            /* even though the early termination failed,
             * the op will be marked as cancelled once it completes. */
            crm_err("Termination of %s (pid=%d) failed", id, op->pid);
            return FALSE;
        }
    }

    return TRUE;
}

gboolean
services_action_kick(const char *name, const char *action, int interval /* ms */)
{
    svc_action_t * op = NULL;
    char *id = NULL;

    if (asprintf(&id, "%s_%s_%d", name, action, interval) == -1) {
        return FALSE;
    }

    op = g_hash_table_lookup(recurring_actions, id);
    free(id);

    if (op == NULL) {
        return FALSE;
    }

    if (op->pid) {
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
            return TRUE;
        }
        g_hash_table_replace(recurring_actions, op->id, op);
    }
    if (op->standard && strcasecmp(op->standard, "upstart") == 0) {
#if SUPPORT_UPSTART
        return upstart_job_exec(op, FALSE);
#endif
    }
    if (op->standard && strcasecmp(op->standard, "systemd") == 0) {
#if SUPPORT_SYSTEMD
        return systemd_unit_exec(op);
#endif
    }
    return services_os_action_execute(op, FALSE);
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
    if (op->standard && strcasecmp(op->standard, "upstart") == 0) {
#if SUPPORT_UPSTART
        rc = upstart_job_exec(op, TRUE);
#endif
    } else if (op->standard && strcasecmp(op->standard, "systemd") == 0) {
#if SUPPORT_SYSTEMD
        rc = systemd_unit_exec(op);
#endif
    } else {
        rc = services_os_action_execute(op, TRUE);
    }
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
    return resources_list_agents("lsb", NULL);
}

static GList *
resources_os_list_hb_agents(void)
{
    return services_os_get_directory_list(HB_RA_DIR, TRUE, TRUE);
}

GList *
resources_list_standards(void)
{
    GList *standards = NULL;
    GList *agents = NULL;

    standards = g_list_append(standards, strdup("ocf"));
    standards = g_list_append(standards, strdup("lsb"));
    standards = g_list_append(standards, strdup("service"));

#if SUPPORT_SYSTEMD
    agents = systemd_unit_listall();
#else
    agents = NULL;
#endif

    if (agents) {
        standards = g_list_append(standards, strdup("systemd"));
        g_list_free_full(agents, free);
    }
#if SUPPORT_UPSTART
    agents = upstart_job_listall();
#else
    agents = NULL;
#endif

    if (agents) {
        standards = g_list_append(standards, strdup("upstart"));
        g_list_free_full(agents, free);
    }
#if SUPPORT_NAGIOS
    agents = resources_os_list_nagios_agents();
    if (agents) {
        standards = g_list_append(standards, strdup("nagios"));
        g_list_free_full(agents, free);
    }
#endif

#if SUPPORT_HEARTBEAT
    standards = g_list_append(standards, strdup("heartbeat"));
#endif

    return standards;
}

GList *
resources_list_providers(const char *standard)
{
    if (strcasecmp(standard, "ocf") == 0) {
        return resources_os_list_ocf_providers();
    }

    return NULL;
}

GList *
resources_list_agents(const char *standard, const char *provider)
{
    if (standard == NULL || strcasecmp(standard, "service") == 0) {
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

    } else if (strcasecmp(standard, "ocf") == 0) {
        return resources_os_list_ocf_agents(provider);
    } else if (strcasecmp(standard, "lsb") == 0) {
        return resources_os_list_lsb_agents();
#if SUPPORT_HEARTBEAT
    } else if (strcasecmp(standard, "heartbeat") == 0) {
        return resources_os_list_hb_agents();
#endif
#if SUPPORT_SYSTEMD
    } else if (strcasecmp(standard, "systemd") == 0) {
        return systemd_unit_listall();
#endif
#if SUPPORT_UPSTART
    } else if (strcasecmp(standard, "upstart") == 0) {
        return upstart_job_listall();
#endif
#if SUPPORT_NAGIOS
    } else if (strcasecmp(standard, "nagios") == 0) {
        return resources_os_list_nagios_agents();
#endif
    }

    return NULL;
}
