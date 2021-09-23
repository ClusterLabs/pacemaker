/*
 * Copyright 2010-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
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
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <grp.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "crm/crm.h"
#include <crm/msg_xml.h>
#include "crm/common/mainloop.h"
#include "crm/services.h"

#include "services_private.h"
#include "services_nagios.h"

/*!
 * \internal
 * \brief Prepare a Nagios action
 *
 * \param[in] op  Action to prepare
 *
 * \return Standard Pacemaker return code
 */
int
services__nagios_prepare(svc_action_t *op)
{
    op->opaque->exec = pcmk__full_path(op->agent, NAGIOS_PLUGIN_DIR);
    op->opaque->args[0] = strdup(op->opaque->exec);
    if (op->opaque->args[0] == NULL) {
        return ENOMEM;
    }

    if (pcmk__str_eq(op->action, "monitor", pcmk__str_casei)
        && (op->interval_ms == 0)) {

        // Invoke --version for a nagios probe
        op->opaque->args[1] = strdup("--version");
        if (op->opaque->args[1] == NULL) {
            return ENOMEM;
        }

    } else if (op->params != NULL) {
        GHashTableIter iter;
        char *key = NULL;
        char *value = NULL;
        int index = 1; // 0 is already set to executable name

        g_hash_table_iter_init(&iter, op->params);

        while (g_hash_table_iter_next(&iter, (gpointer *) & key,
                                      (gpointer *) & value)) {

            if (index > (PCMK__NELEM(op->opaque->args) - 2)) {
                return E2BIG;
            }

            if (pcmk__str_eq(key, XML_ATTR_CRM_VERSION, pcmk__str_casei)
                || strstr(key, CRM_META "_")) {
                continue;
            }

            op->opaque->args[index++] = crm_strdup_printf("--%s", key);
            op->opaque->args[index++] = strdup(value);
            if (op->opaque->args[index - 1] == NULL) {
                return ENOMEM;
            }
        }
    }

    // Nagios actions don't need to keep the parameters
    if (op->params != NULL) {
        g_hash_table_destroy(op->params);
        op->params = NULL;
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Map a Nagios result to a standard OCF result
 *
 * \param[in] exit_status  Nagios exit status
 *
 * \return Standard OCF result
 */
enum ocf_exitcode
services__nagios2ocf(int exit_status)
{
    switch (exit_status) {
        case NAGIOS_STATE_OK:
            return PCMK_OCF_OK;

        case NAGIOS_INSUFFICIENT_PRIV:
            return PCMK_OCF_INSUFFICIENT_PRIV;

        case NAGIOS_NOT_INSTALLED:
            return PCMK_OCF_NOT_INSTALLED;

        case NAGIOS_STATE_WARNING:
            return PCMK_OCF_DEGRADED;

        case NAGIOS_STATE_CRITICAL:
        case NAGIOS_STATE_UNKNOWN:
        case NAGIOS_STATE_DEPENDENT:
        default:
            return PCMK_OCF_UNKNOWN_ERROR;
    }
}

static inline char *
nagios_metadata_name(const char *plugin)
{
    return crm_strdup_printf(NAGIOS_METADATA_DIR "/%s.xml", plugin);
}

GList *
services__list_nagios_agents(void)
{
    GList *plugin_list = NULL;
    GList *result = NULL;

    plugin_list = services_os_get_directory_list(NAGIOS_PLUGIN_DIR, TRUE, TRUE);

    // Return only the plugins that have metadata
    for (GList *gIter = plugin_list; gIter != NULL; gIter = gIter->next) {
        struct stat st;
        const char *plugin = gIter->data;
        char *metadata = nagios_metadata_name(plugin);

        if (stat(metadata, &st) == 0) {
            result = g_list_append(result, strdup(plugin));
        }
        free(metadata);
    }
    g_list_free_full(plugin_list, free);
    return result;
}

gboolean
services__nagios_agent_exists(const char *name)
{
    char *buf = NULL;
    gboolean rc = FALSE;
    struct stat st;

    if (name == NULL) {
        return rc;
    }

    buf = crm_strdup_printf(NAGIOS_PLUGIN_DIR "/%s", name);
    if (stat(buf, &st) == 0) {
        rc = TRUE;
    }

    free(buf);
    return rc;
}

int
services__get_nagios_metadata(const char *type, char **output)
{
    int rc = pcmk_ok;
    FILE *file_strm = NULL;
    int start = 0, length = 0, read_len = 0;
    char *metadata_file = nagios_metadata_name(type);

    file_strm = fopen(metadata_file, "r");
    if (file_strm == NULL) {
        crm_err("Metadata file %s does not exist", metadata_file);
        free(metadata_file);
        return -EIO;
    }

    /* see how big the file is */
    start = ftell(file_strm);
    fseek(file_strm, 0L, SEEK_END);
    length = ftell(file_strm);
    fseek(file_strm, 0L, start);

    CRM_ASSERT(length >= 0);
    CRM_ASSERT(start == ftell(file_strm));

    if (length <= 0) {
        crm_info("%s was not valid", metadata_file);
        free(*output);
        *output = NULL;
        rc = -EIO;

    } else {
        crm_trace("Reading %d bytes from file", length);
        *output = calloc(1, (length + 1));
        read_len = fread(*output, 1, length, file_strm);
        if (read_len != length) {
            crm_err("Calculated and read bytes differ: %d vs. %d",
                    length, read_len);
            free(*output);
            *output = NULL;
            rc = -EIO;
        }
    }

    fclose(file_strm);
    free(metadata_file);
    return rc;
}
