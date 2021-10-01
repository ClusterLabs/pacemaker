/*
 * Copyright 2012-2021 the Pacemaker project contributors
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
