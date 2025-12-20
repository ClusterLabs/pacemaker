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

/*!
 * \internal
 * \brief List the OCF providers from \c PCMK__OCF_RA_PATH
 *
 * For each directory along \c PCMK__OCF_RA_PATH (a colon-delimited list), this
 * function adds all top-level subdirectories to the list, excluding those
 * beginning with \c '.'.
 *
 * \return Newly allocated list of OCF providers as newly allocated strings
 *
 * \note The caller is responsible for freeing the return value using
 *       <tt>g_list_free_full(list, free)</tt>.
 */
GList *
services__list_ocf_providers(void)
{
    GList *list = NULL;
    gchar **dirs = g_strsplit(PCMK__OCF_RA_PATH, ":", 0);

    // NULL dirs should be impossible if PCMK__OCF_RA_PATH is defined correctly
    CRM_CHECK(dirs != NULL, return NULL);

    for (const char *const *dir = (const char *const *) dirs; *dir != NULL;
         dir++) {

        list = g_list_concat(list, services__list_dir(*dir, false));
    }

    g_strfreev(dirs);
    return list;
}

/*!
 * \internal
 * \brief List the agents from the given OCF provider or from all OCF providers
 *
 * If \p provider is not \c NULL, for each directory along \c PCMK__OCF_RA_PATH
 * (a colon-delimited list), this function looks for a subdirectory called
 * \p provider. It then finds the top-level executable files inside that
 * subdirectory, excluding those beginning with \c '.', and adds them to the
 * list.
 *
 * If \p provider is \c NULL, this function does the above for each provider and
 * concatenates the results.
 *
 * \param[in] provider  OCF provider (\c NULL to list agents from all providers)
 *
 * \return Newly allocated list of OCF agents as newly allocated strings
 *
 * \note The caller is responsible for freeing the return value using
 *       <tt>g_list_free_full(list, free)</tt>.
 */
GList *
services__list_ocf_agents(const char *provider)
{
    GList *list = NULL;
    gchar **dirs = NULL;

    if (provider == NULL) {
        // Make a recursive call for each provider and concatenate the results
        GList *providers = services__list_ocf_providers();

        for (const GList *iter = providers; iter != NULL; iter = iter->next) {
            provider = (const char *) iter->data;
            list = g_list_concat(list, services__list_ocf_agents(provider));
        }
        g_list_free_full(providers, free);
        return list;
    }

    dirs = g_strsplit(PCMK__OCF_RA_PATH, ":", 0);

    // NULL dirs should be impossible if PCMK__OCF_RA_PATH is defined correctly
    CRM_CHECK(dirs != NULL, return NULL);

    for (const char *const *dir = (const char *const *) dirs; *dir != NULL;
         dir++) {

        char *buf = pcmk__assert_asprintf("%s/%s", *dir, provider);

        list = g_list_concat(list, services__list_dir(buf, true));
        free(buf);
    }

    g_strfreev(dirs);
    return list;
}

/*!
 * \internal
 * \brief Check whether the given OCF agent from the given provider exists
 *
 * For each directory along \c PCMK__OCF_RA_PATH (a colon-delimited list), this
 * function looks for a file called \p agent in a subdirectory called
 * \p provider. It returns \c true if such a file is found.
 *
 * \param[in]  provider  OCF provider
 * \param[in]  agent     OCF agent
 * \param[out] path      If not \c NULL, where to store full path to agent if
 *                       found; unchanged if agent is not found
 *
 * \return \c true if the agent is found or \c false otherwise
 *
 * \note The caller is responsible for freeing \p *path on success using
 *       \c free().
 */
bool
services__ocf_agent_exists(const char *provider, const char *agent, char **path)
{
    bool found = false;
    gchar **dirs = NULL;

    pcmk__assert((path == NULL) || (*path == NULL));

    if ((provider == NULL) || (agent == NULL)) {
        return false;
    }

    dirs = g_strsplit(PCMK__OCF_RA_PATH, ":", 0);

    // NULL dirs should be impossible if PCMK__OCF_RA_PATH is defined correctly
    CRM_CHECK(dirs != NULL, return NULL);

    for (const char *const *dir = (const char *const *) dirs;
         !found && (*dir != NULL); dir++) {

        char *buf = pcmk__assert_asprintf("%s/%s/%s", *dir, provider, agent);
        struct stat sb;

        if (stat(buf, &sb) == 0) {
            found = true;

            if (path != NULL) {
                *path = buf;
                buf = NULL;
            }
        }
        free(buf);
    }

    g_strfreev(dirs);
    return found;
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
    if (!services__ocf_agent_exists(op->provider, op->agent,
                                    &(op->opaque->exec))) {
        return ENOENT;
    }

    op->opaque->args[0] = pcmk__str_copy(op->opaque->exec);
    op->opaque->args[1] = pcmk__str_copy(op->action);
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
