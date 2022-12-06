/*
 * Copyright 2012-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/services.h>
#include <crm/services_internal.h>

#include "services_private.h"
#include "services_ocf.h"

GList *
resources_os_list_ocf_providers(void)
{
    return get_directory_list(OCF_RA_PATH, FALSE, TRUE);
}

static GList *
services_os_get_directory_list_provider(const char *root, const char *provider,
                                        gboolean files, gboolean executable)
{
    GList *result = NULL;
    char *dirs = strdup(root);
    char *dir = NULL;
    char buffer[PATH_MAX];

    if (pcmk__str_empty(dirs)) {
        free(dirs);
        return result;
    }

    for (dir = strtok(dirs, ":"); dir != NULL; dir = strtok(NULL, ":")) {
        GList *tmp = NULL;

        sprintf(buffer, "%s/%s", dir, provider);
        tmp = services_os_get_single_directory_list(buffer, files, executable);

        if (tmp) {
            result = g_list_concat(result, tmp);
        }
    }

    free(dirs);

    return result;
}

GList *
resources_os_list_ocf_agents(const char *provider)
{
    GList *gIter = NULL;
    GList *result = NULL;
    GList *providers = NULL;

    if (provider) {
        return services_os_get_directory_list_provider(OCF_RA_PATH, provider,
                                                       TRUE, TRUE);
    }

    providers = resources_os_list_ocf_providers();
    for (gIter = providers; gIter != NULL; gIter = gIter->next) {
        GList *tmp1 = result;
        GList *tmp2 = resources_os_list_ocf_agents(gIter->data);

        if (tmp2) {
            result = g_list_concat(tmp1, tmp2);
        }
    }
    g_list_free_full(providers, free);
    return result;
}

gboolean
services__ocf_agent_exists(const char *provider, const char *agent)
{
    gboolean rc = FALSE;
    struct stat st;
    char *dirs = strdup(OCF_RA_PATH);
    char *dir = NULL;
    char *buf = NULL;

    if (provider == NULL || agent == NULL || pcmk__str_empty(dirs)) {
        free(dirs);
        return rc;
    }

    for (dir = strtok(dirs, ":"); dir != NULL; dir = strtok(NULL, ":")) {
        buf = crm_strdup_printf("%s/%s/%s", dir, provider, agent);
        if (stat(buf, &st) == 0) {
            free(buf);
            rc = TRUE;
            break;
        }

        free(buf);
    }

    free(dirs);

    return rc;
}

/*!
 * \internal
 * \brief Prepare an OCF action
 *
 * \param[in,out] op  Action to prepare
 *
 * \return Standard Pacemaker return code
 */
int
services__ocf_prepare(svc_action_t *op)
{
    char *dirs = strdup(OCF_RA_PATH);
    struct stat st;

    if (dirs == NULL) {
        return ENOMEM;
    }

    // Look for agent on path
    for (char *dir = strtok(dirs, ":"); dir != NULL; dir = strtok(NULL, ":")) {
        char *buf = crm_strdup_printf("%s/%s/%s", dir, op->provider, op->agent);

        if (stat(buf, &st) == 0) {
            op->opaque->exec = buf;
            break;
        }
        free(buf);
    }
    free(dirs);

    if (op->opaque->exec == NULL) {
        return ENOENT;
    }

    op->opaque->args[0] = strdup(op->opaque->exec);
    op->opaque->args[1] = strdup(op->action);
    if ((op->opaque->args[0] == NULL) || (op->opaque->args[1] == NULL)) {
        return ENOMEM;
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Map an actual OCF result to a standard OCF result
 *
 * \param[in] exit_status  Actual OCF agent exit status
 *
 * \return Standard OCF result
 */
enum ocf_exitcode
services__ocf2ocf(int exit_status)
{
    switch (exit_status) {
        case PCMK_OCF_DEGRADED:
        case PCMK_OCF_DEGRADED_PROMOTED:
            break;
        default:
            if ((exit_status < 0) || (exit_status > PCMK_OCF_FAILED_PROMOTED)) {
                exit_status = PCMK_OCF_UNKNOWN_ERROR;
            }
            break;
    }
    return (enum ocf_exitcode) exit_status;
}
