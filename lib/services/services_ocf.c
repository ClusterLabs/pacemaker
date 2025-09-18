/*
 * Copyright 2012-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>                // true, false
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
    GList *list = NULL;
    gchar **dirs = g_strsplit(PCMK__OCF_RA_PATH, ":", 0);

    for (gchar **dir = dirs; *dir != NULL; dir++) {
        list = g_list_concat(list, services__list_dir(*dir, false, true));
    }

    g_strfreev(dirs);
    return list;
}

/*!
 * \internal
 * \brief List the agents from the given OCF provider
 *
 * For each directory along \c PCMK__OCF_RA_PATH (a colon-delimited list), this
 * function looks for a subdirectory called \p provider. It then finds the top-
 * level executable files inside that subdirectory, excluding those beginning
 * with \c '.', and adds them to the list.
 *
 * \param[in] provider  OCF provider
 *
 * \return Newly allocated list of OCF agents as newly allocated strings
 *
 * \note The caller is responsible for freeing the return value using
 *       <tt>g_list_free_full(list, free)</tt>.
 */
static GList *
list_provider_agents(const char *provider)
{
    gchar **dirs = NULL;
    GList *list = NULL;

    dirs = g_strsplit(PCMK__OCF_RA_PATH, ":", 0);

    for (gchar **dir = dirs; *dir != NULL; dir++) {
        char *buf = pcmk__assert_asprintf("%s/%s", *dir, provider);

        list = g_list_concat(list, services__list_dir(buf, true, true));
        free(buf);
    }

    g_strfreev(dirs);
    return list;
}

GList *
resources_os_list_ocf_agents(const char *provider)
{
    GList *list = NULL;
    GList *providers = NULL;

    if (provider != NULL) {
        return list_provider_agents(provider);
    }

    providers = resources_os_list_ocf_providers();
    for (const GList *iter = providers; iter != NULL; iter = iter->next) {
        provider = (const char *) iter->data;
        list = g_list_concat(list, resources_os_list_ocf_agents(provider));
    }

    g_list_free_full(providers, free);
    return list;
}

gboolean
services__ocf_agent_exists(const char *provider, const char *agent)
{
    gboolean rc = FALSE;
    struct stat st;
    char *dirs = strdup(PCMK__OCF_RA_PATH);
    char *dir = NULL;
    char *buf = NULL;

    if (provider == NULL || agent == NULL || pcmk__str_empty(dirs)) {
        free(dirs);
        return rc;
    }

    for (dir = strtok(dirs, ":"); dir != NULL; dir = strtok(NULL, ":")) {
        buf = pcmk__assert_asprintf("%s/%s/%s", dir, provider, agent);
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
    char *dirs = strdup(PCMK__OCF_RA_PATH);
    struct stat st;

    if (dirs == NULL) {
        return ENOMEM;
    }

    // Look for agent on path
    for (char *dir = strtok(dirs, ":"); dir != NULL; dir = strtok(NULL, ":")) {
        char *buf = pcmk__assert_asprintf("%s/%s/%s", dir, op->provider,
                                          op->agent);

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
