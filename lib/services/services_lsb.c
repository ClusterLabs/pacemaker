/*
 * Copyright 2010-2024 the Pacemaker project contributors
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

#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/services.h>
#include "services_private.h"
#include "services_lsb.h"

// @TODO Use XML string constants and maybe a real XML object
#define lsb_metadata_template  \
    "<?xml version='1.0'?>\n"                                           \
    "<resource-agent " PCMK_XA_NAME "='%s' "                            \
                       PCMK_XA_VERSION                                  \
                           "='" PCMK_DEFAULT_AGENT_VERSION "'>\n"       \
    "  <" PCMK_XE_VERSION ">1.0</" PCMK_XE_VERSION ">\n"                \
    "  <longdesc lang='en'>\n"                                          \
    "%s"                                                                \
    "  </longdesc>\n"                                                   \
    "  <shortdesc lang='en'>%s</shortdesc>\n"                           \
    "  <" PCMK_XE_PARAMETERS "/>\n"                                     \
    "  <actions>\n"                                                     \
    "    <action name='meta-data'    timeout='5' />\n"                  \
    "    <action name='start'        timeout='15' />\n"                 \
    "    <action name='stop'         timeout='15' />\n"                 \
    "    <action name='status'       timeout='15' />\n"                 \
    "    <action name='restart'      timeout='15' />\n"                 \
    "    <action name='force-reload' timeout='15' />\n"                 \
    "    <action name='monitor'      timeout='15' interval='15' />\n"   \
    "  </actions>\n"                                                    \
    "  <special tag='LSB'>\n"                                           \
    "    <Provides>%s</Provides>\n"                                     \
    "    <Required-Start>%s</Required-Start>\n"                         \
    "    <Required-Stop>%s</Required-Stop>\n"                           \
    "    <Should-Start>%s</Should-Start>\n"                             \
    "    <Should-Stop>%s</Should-Stop>\n"                               \
    "    <Default-Start>%s</Default-Start>\n"                           \
    "    <Default-Stop>%s</Default-Stop>\n"                             \
    "  </special>\n"                                                    \
    "</resource-agent>\n"

/* See "Comment Conventions for Init Scripts" in the LSB core specification at:
 * http://refspecs.linuxfoundation.org/lsb.shtml
 */
#define LSB_INITSCRIPT_INFOBEGIN_TAG    "### BEGIN INIT INFO"
#define LSB_INITSCRIPT_INFOEND_TAG      "### END INIT INFO"
#define PROVIDES                        "# Provides:"
#define REQUIRED_START                  "# Required-Start:"
#define REQUIRED_STOP                   "# Required-Stop:"
#define SHOULD_START                    "# Should-Start:"
#define SHOULD_STOP                     "# Should-Stop:"
#define DEFAULT_START                   "# Default-Start:"
#define DEFAULT_STOP                    "# Default-Stop:"
#define SHORT_DESC                      "# Short-Description:"
#define DESCRIPTION                     "# Description:"

#define lsb_meta_helper_free_value(m)           \
    do {                                        \
        if ((m) != NULL) {                      \
            xmlFree(m);                         \
            (m) = NULL;                         \
        }                                       \
    } while(0)

/*!
 * \internal
 * \brief Grab an LSB header value
 *
 * \param[in]     line    Line read from LSB init script
 * \param[in,out] value   If not set, will be set to XML-safe copy of value
 * \param[in]     prefix  Set value if line starts with this pattern
 *
 * \return TRUE if value was set, FALSE otherwise
 */
static inline gboolean
lsb_meta_helper_get_value(const char *line, char **value, const char *prefix)
{
    if (!*value && pcmk__starts_with(line, prefix)) {
        *value = (char *)xmlEncodeEntitiesReentrant(NULL, BAD_CAST line+strlen(prefix));
        return TRUE;
    }
    return FALSE;
}

int
services__get_lsb_metadata(const char *type, char **output)
{
    char ra_pathname[PATH_MAX] = { 0, };
    FILE *fp = NULL;
    char buffer[1024] = { 0, };
    char *provides = NULL;
    char *required_start = NULL;
    char *required_stop = NULL;
    char *should_start = NULL;
    char *should_stop = NULL;
    char *default_start = NULL;
    char *default_stop = NULL;
    char *short_desc = NULL;
    char *long_desc = NULL;
    bool in_header = FALSE;

    if (type[0] == '/') {
        snprintf(ra_pathname, sizeof(ra_pathname), "%s", type);
    } else {
        snprintf(ra_pathname, sizeof(ra_pathname), "%s/%s",
                 PCMK__LSB_INIT_DIR, type);
    }

    crm_trace("Looking into %s", ra_pathname);
    fp = fopen(ra_pathname, "r");
    if (fp == NULL) {
        return -errno;
    }

    /* Enter into the LSB-compliant comment block */
    while (fgets(buffer, sizeof(buffer), fp)) {

        // Ignore lines up to and including the block delimiter
        if (pcmk__starts_with(buffer, LSB_INITSCRIPT_INFOBEGIN_TAG)) {
            in_header = TRUE;
            continue;
        }
        if (!in_header) {
            continue;
        }

        /* Assume each of the following eight arguments contain one line */
        if (lsb_meta_helper_get_value(buffer, &provides, PROVIDES)) {
            continue;
        }
        if (lsb_meta_helper_get_value(buffer, &required_start,
                                      REQUIRED_START)) {
            continue;
        }
        if (lsb_meta_helper_get_value(buffer, &required_stop, REQUIRED_STOP)) {
            continue;
        }
        if (lsb_meta_helper_get_value(buffer, &should_start, SHOULD_START)) {
            continue;
        }
        if (lsb_meta_helper_get_value(buffer, &should_stop, SHOULD_STOP)) {
            continue;
        }
        if (lsb_meta_helper_get_value(buffer, &default_start, DEFAULT_START)) {
            continue;
        }
        if (lsb_meta_helper_get_value(buffer, &default_stop, DEFAULT_STOP)) {
            continue;
        }
        if (lsb_meta_helper_get_value(buffer, &short_desc, SHORT_DESC)) {
            continue;
        }

        /* Long description may cross multiple lines */
        if ((long_desc == NULL)  // Haven't already found long description
            && pcmk__starts_with(buffer, DESCRIPTION)) {
            bool processed_line = TRUE;
            GString *desc = g_string_sized_new(2048);

            // Get remainder of description line itself
            g_string_append(desc, buffer + sizeof(DESCRIPTION) - 1);

            // Read any continuation lines of the description
            buffer[0] = '\0';
            while (fgets(buffer, sizeof(buffer), fp)) {
                if (pcmk__starts_with(buffer, "#  ")
                    || pcmk__starts_with(buffer, "#\t")) {
                    /* '#' followed by a tab or more than one space indicates a
                     * continuation of the long description.
                     */
                    g_string_append(desc, buffer + 1);
                } else {
                    /* This line is not part of the long description,
                     * so continue with normal processing.
                     */
                    processed_line = FALSE;
                    break;
                }
            }

            // Make long description safe to use in XML
            long_desc =
                (char *) xmlEncodeEntitiesReentrant(NULL,
                                                    (pcmkXmlStr) desc->str);
            g_string_free(desc, TRUE);

            if (processed_line) {
                // We grabbed the line into the long description
                continue;
            }
        }

        // Stop if we leave the header block
        if (pcmk__starts_with(buffer, LSB_INITSCRIPT_INFOEND_TAG)) {
            break;
        }
        if (buffer[0] != '#') {
            break;
        }
    }
    fclose(fp);

    *output = crm_strdup_printf(lsb_metadata_template, type,
                                pcmk__s(long_desc, type),
                                pcmk__s(short_desc, type),
                                pcmk__s(provides, ""),
                                pcmk__s(required_start, ""),
                                pcmk__s(required_stop, ""),
                                pcmk__s(should_start, ""),
                                pcmk__s(should_stop, ""),
                                pcmk__s(default_start, ""),
                                pcmk__s(default_stop, ""));

    lsb_meta_helper_free_value(long_desc);
    lsb_meta_helper_free_value(short_desc);
    lsb_meta_helper_free_value(provides);
    lsb_meta_helper_free_value(required_start);
    lsb_meta_helper_free_value(required_stop);
    lsb_meta_helper_free_value(should_start);
    lsb_meta_helper_free_value(should_stop);
    lsb_meta_helper_free_value(default_start);
    lsb_meta_helper_free_value(default_stop);

    crm_trace("Created fake metadata: %zu", strlen(*output));
    return pcmk_ok;
}

GList *
services__list_lsb_agents(void)
{
    return services_os_get_directory_list(PCMK__LSB_INIT_DIR, TRUE, TRUE);
}

bool
services__lsb_agent_exists(const char *agent)
{
    bool rc = FALSE;
    struct stat st;
    char *path = pcmk__full_path(agent, PCMK__LSB_INIT_DIR);

    rc = (stat(path, &st) == 0);
    free(path);
    return rc;
}

/*!
 * \internal
 * \brief Prepare an LSB action
 *
 * \param[in,out] op  Action to prepare
 *
 * \return Standard Pacemaker return code
 */
int
services__lsb_prepare(svc_action_t *op)
{
    op->opaque->exec = pcmk__full_path(op->agent, PCMK__LSB_INIT_DIR);
    op->opaque->args[0] = strdup(op->opaque->exec);
    op->opaque->args[1] = strdup(op->action);
    if ((op->opaque->args[0] == NULL) || (op->opaque->args[1] == NULL)) {
        return ENOMEM;
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Map an LSB result to a standard OCF result
 *
 * \param[in] action       Action that result is for
 * \param[in] exit_status  LSB agent exit status
 *
 * \return Standard OCF result
 */
enum ocf_exitcode
services__lsb2ocf(const char *action, int exit_status)
{
    // For non-status actions, LSB and OCF share error codes <= 7
    if (!pcmk__str_any_of(action, PCMK_ACTION_STATUS, PCMK_ACTION_MONITOR,
                          NULL)) {
        if ((exit_status < 0) || (exit_status > PCMK_LSB_NOT_RUNNING)) {
            return PCMK_OCF_UNKNOWN_ERROR;
        }
        return (enum ocf_exitcode) exit_status;
    }

    // LSB status actions have their own codes
    switch (exit_status) {
        case PCMK_LSB_STATUS_OK:
            return PCMK_OCF_OK;

        case PCMK_LSB_STATUS_NOT_INSTALLED:
            return PCMK_OCF_NOT_INSTALLED;

        case PCMK_LSB_STATUS_INSUFFICIENT_PRIV:
            return PCMK_OCF_INSUFFICIENT_PRIV;

        case PCMK_LSB_STATUS_VAR_PID:
        case PCMK_LSB_STATUS_VAR_LOCK:
        case PCMK_LSB_STATUS_NOT_RUNNING:
            return PCMK_OCF_NOT_RUNNING;

        default:
            return PCMK_OCF_UNKNOWN_ERROR;
    }
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/services_compat.h>

svc_action_t *
services_action_create(const char *name, const char *action,
                       guint interval_ms, int timeout)
{
    return resources_action_create(name, PCMK_RESOURCE_CLASS_LSB, NULL, name,
                                   action, interval_ms, timeout, NULL, 0);
}

GList *
services_list(void)
{
    return resources_list_agents(PCMK_RESOURCE_CLASS_LSB, NULL);
}

// LCOV_EXCL_STOP
// End deprecated API
