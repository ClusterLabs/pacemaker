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
#define _GNU_SOURCE
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
#include "services_private.h"

#if SUPPORT_UPSTART
#include <upstart.h>
#endif

#if SUPPORT_SYSTEMD
#include <systemd.h>
#endif

/* TODO: Develop a rollover strategy */

static int operations = 0;
GHashTable *recurring_actions = NULL;

svc_action_t *
services_action_create(const char *name, const char *action, int interval,
                       int timeout)
{
    return resources_action_create(name, "lsb", NULL, name, action, interval, timeout, NULL);
}

svc_action_t *resources_action_create(
    const char *name, const char *standard, const char *provider, const char *agent,
    const char *action, int interval, int timeout, GHashTable *params)
{
    svc_action_t *op;

    /*
     * Do some up front sanity checks before we go off and
     * build the svc_action_t instance.
     */

    if (crm_strlen_zero(name)) {
        crm_err("A service or resource action must have a name.");
        return NULL;
    }

    if (crm_strlen_zero(standard)) {
        crm_err("A service action must have a valid standard.");
        return NULL;
    }

    if (!strcasecmp(standard, "ocf") && crm_strlen_zero(provider)) {
        crm_err("An OCF resource action must have a provider.");
        return NULL;
    }

    if (crm_strlen_zero(agent)) {
        crm_err("A service or resource action must have an agent.");
        return NULL;
    }

    if (crm_strlen_zero(action)) {
        crm_err("A service or resource action must specify an action.");
        return NULL;
    }

    if (safe_str_eq(action, "monitor") && (safe_str_eq(standard, "lsb") || safe_str_eq(standard, "service"))) {
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

    if(strcasecmp(op->standard, "service") == 0) {
        /* Work it out and then fall into the if-else block below.
         * Priority is:
         * - lsb
         * - systemd
         * - upstart
         */
        int rc = 0;
        struct stat st;
        char *path = NULL;

#ifdef LSB_ROOT_DIR
        rc = asprintf(&path, "%s/%s", LSB_ROOT_DIR, op->agent);
        if(rc > 0 && stat(path, &st) == 0) {
            crm_debug("Found an lsb agent for %s/% the", op->rsc, op->agent);
            free(path);
            free(op->standard);
            op->standard = strdup("lsb");
            goto expanded;
        }
        free(path);
#endif

#if SUPPORT_SYSTEMD
        if(systemd_unit_exists(op->agent)) {
            crm_debug("Found a systemd agent for %s/%s", op->rsc, op->agent);
            free(op->standard);
            op->standard = strdup("systemd");
            goto expanded;
        }
#endif

#if SUPPORT_UPSTART
        if(upstart_job_exists(op->agent)) {
            crm_debug("Found an upstart agent for %s/%s", op->rsc, op->agent);
            free(op->standard);
            op->standard = strdup("upstart");
            goto expanded;
        }
#endif

        crm_info("Cannot determine the standard for %s (%s)", op->rsc, op->agent);
    }

  expanded:
    if(strcasecmp(op->standard, "ocf") == 0) {
        op->provider = strdup(provider);
        op->params = params;

        if (asprintf(&op->opaque->exec, "%s/resource.d/%s/%s",
                     OCF_ROOT_DIR, provider, agent) == -1) {
            goto return_error;
        }
        op->opaque->args[0] = strdup(op->opaque->exec);
        op->opaque->args[1] = strdup(action);

    } else if(strcasecmp(op->standard, "lsb") == 0) {
        if (op->agent[0] == '/') {
             /* if given an absolute path, use that instead
             * of tacking on the LSB_ROOT_DIR path to the front */
            op->opaque->exec = strdup(op->agent);
        } else if (asprintf(&op->opaque->exec, "%s/%s", LSB_ROOT_DIR, op->agent) == -1) {
            goto return_error;
        }
        op->opaque->args[0] = strdup(op->opaque->exec);
        op->opaque->args[1] = strdup(op->action);
        op->opaque->args[2] = NULL;

#if SUPPORT_SYSTEMD
    } else if(strcasecmp(op->standard, "systemd") == 0) {
        op->opaque->exec = strdup("systemd-dbus");
#endif
#if SUPPORT_UPSTART
    } else if(strcasecmp(op->standard, "upstart") == 0) {
        op->opaque->exec = strdup("upstart-dbus");
#endif
    } else if(strcasecmp(op->standard, "service") == 0) {
        op->opaque->exec = strdup(SERVICE_SCRIPT);
        op->opaque->args[0] = strdup(SERVICE_SCRIPT);
        op->opaque->args[1] = strdup(agent);
        op->opaque->args[2] = strdup(action);

    } else {
        crm_err("Unknown resource standard: %s", op->standard);
        services_action_free(op);
        op = NULL;
    }

    return op;

return_error:
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
services_action_free(svc_action_t *op)
{
    unsigned int i;

    if (op == NULL) {
        return;
    }

    if (op->opaque->stderr_gsource) {
        mainloop_del_fd(op->opaque->stderr_gsource);
        op->opaque->stderr_gsource = NULL;
    }

    if (op->opaque->stdout_gsource) {
        mainloop_del_fd(op->opaque->stdout_gsource);
        op->opaque->stdout_gsource = NULL;
    }

    free(op->id);
    free(op->opaque->exec);

    for (i = 0; i < DIMOF(op->opaque->args); i++) {
        free(op->opaque->args[i]);
    }

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
cancel_recurring_action(svc_action_t *op)
{
    if (op->pid) {
        return FALSE;
    }

    crm_info("Cancelling operation %s", op->id);

    if (recurring_actions) {
        g_hash_table_remove(recurring_actions, op->id);
    }

    if (op->opaque->repeat_timer) {
        g_source_remove(op->opaque->repeat_timer);
    }

    return TRUE;
}

gboolean
services_action_cancel(const char *name, const char *action, int interval)
{
    svc_action_t* op = NULL;
    char id[512];

    snprintf(id, sizeof(id), "%s_%s_%d", name, action, interval);

    if (!(op = g_hash_table_lookup(recurring_actions, id))) {
        return FALSE;
    }

    if (cancel_recurring_action(op)) {
        op->status = PCMK_LRM_OP_CANCELLED;
        if (op->opaque->callback) {
            op->opaque->callback(op);
        }
        services_action_free(op);
    } else {
        crm_info("Cancelling op: %s will occur once operation completes", id);
        op->cancel = 1;
    }

    return TRUE;
}

gboolean
services_action_async(svc_action_t* op, void (*action_callback)(svc_action_t *))
{
    if (action_callback) {
        op->opaque->callback = action_callback;
    }

    if (recurring_actions == NULL) {
        recurring_actions = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                  NULL, NULL);
    }

    if (op->interval > 0) {
        g_hash_table_replace(recurring_actions, op->id, op);
    }

#if SUPPORT_UPSTART
    if(strcasecmp(op->standard, "upstart") == 0) {
	return upstart_job_exec(op, FALSE);
    }
#endif
#if SUPPORT_SYSTEMD
    if(strcasecmp(op->standard, "systemd") == 0) {
	return systemd_unit_exec(op, FALSE);
    }
#endif
    return services_os_action_execute(op, FALSE);
}

gboolean
services_action_sync(svc_action_t* op)
{
    gboolean rc = TRUE;

    if(strcasecmp(op->standard, "upstart") == 0) {
#if SUPPORT_UPSTART
	rc = upstart_job_exec(op, TRUE);
#endif
    } else if(strcasecmp(op->standard, "systemd") == 0) {
#if SUPPORT_SYSTEMD
	rc = systemd_unit_exec(op, TRUE);
#endif
    } else {
        rc = services_os_action_execute(op, TRUE);
    }
    crm_trace(" > %s_%s_%d: %s = %d", op->rsc, op->action, op->interval,
             op->opaque->exec, op->rc);
    if (op->stdout_data) {
        crm_trace(" >  stdout: %s", op->stdout_data);
    }
    if (op->stderr_data) {
        crm_trace(" >  stderr: %s", op->stderr_data);
    }
    return rc;
}

GList *
get_directory_list(const char *root, gboolean files)
{
    return services_os_get_directory_list(root, files);
}

GList *
services_list(void)
{
    return resources_list_agents("lsb", NULL);
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

    if(agents) {
        standards = g_list_append(standards, strdup("systemd"));
        g_list_free_full(agents, free);
    }

#if SUPPORT_UPSTART
    agents = upstart_job_listall();
#else
    agents = NULL;
#endif

    if(agents) {
        standards = g_list_append(standards, strdup("upstart"));
        g_list_free_full(agents, free);
    }

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

        if(standard == NULL) {
            tmp1 = result;
            tmp2 = resources_os_list_ocf_agents(NULL);
            if(tmp2) {
                result = g_list_concat(tmp1, tmp2);
            }
        }

#if SUPPORT_SYSTEMD
        tmp1 = result;
        tmp2 = systemd_unit_listall();
        if(tmp2) {
            result = g_list_concat(tmp1, tmp2);
        }
#endif

#if SUPPORT_UPSTART
        tmp1 = result;
        tmp2 = upstart_job_listall();
        if(tmp2) {
            result = g_list_concat(tmp1, tmp2);
        }
#endif

        return result;

    } else if (strcasecmp(standard, "ocf") == 0) {
        return resources_os_list_ocf_agents(provider);
    } else if (strcasecmp(standard, "lsb") == 0) {
        return resources_os_list_lsb_agents();
#if SUPPORT_SYSTEMD
    } else if (strcasecmp(standard, "systemd") == 0) {
        return systemd_unit_listall();
#endif
#if SUPPORT_UPSTART
    } else if (strcasecmp(standard, "upstart") == 0) {
        return upstart_job_listall();
#endif
    }

    return NULL;
}
