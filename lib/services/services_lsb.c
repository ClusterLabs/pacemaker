/*
 * Copyright 2010-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#include <glib.h>               // g_str_has_prefix()

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/services.h>
#include "services_private.h"
#include "services_lsb.h"

// @TODO Use XML string constants and maybe a real XML object
#define lsb_metadata_template  \
    "<?xml " PCMK_XA_VERSION "='1.0'?>\n"                                     \
    "<" PCMK_XE_RESOURCE_AGENT " "                                            \
        PCMK_XA_NAME "='%s' "                                                 \
        PCMK_XA_VERSION "='" PCMK_DEFAULT_AGENT_VERSION "'>\n"                \
    "  <" PCMK_XE_VERSION ">1.1</" PCMK_XE_VERSION ">\n"                      \
    "  <" PCMK_XE_LONGDESC " " PCMK_XA_LANG "='" PCMK__VALUE_EN "'>\n"        \
        "%s"                                                                  \
    "  </" PCMK_XE_LONGDESC ">\n"                                             \
    "  <" PCMK_XE_SHORTDESC " " PCMK_XA_LANG "='" PCMK__VALUE_EN "'>"         \
        "%s"                                                                  \
      "</" PCMK_XE_SHORTDESC ">\n"                                            \
    "  <" PCMK_XE_PARAMETERS "/>\n"                                           \
    "  <" PCMK_XE_ACTIONS ">\n"                                               \
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "='" PCMK_ACTION_META_DATA "'"    \
                           " " PCMK_META_TIMEOUT "='5s' />\n"                 \
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "='" PCMK_ACTION_START "'"        \
                           " " PCMK_META_TIMEOUT "='15s' />\n"                \
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "='" PCMK_ACTION_STOP "'"         \
                           " " PCMK_META_TIMEOUT "='15s' />\n"                \
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "='" PCMK_ACTION_STATUS "'"       \
                           " " PCMK_META_TIMEOUT "='15s' />\n"                \
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "='restart'"                      \
                           " " PCMK_META_TIMEOUT "='15s' />\n"                \
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "='force-reload'"                 \
                           " " PCMK_META_TIMEOUT "='15s' />\n"                \
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "'"      \
                           " " PCMK_META_TIMEOUT "='15s'"                     \
                           " " PCMK_META_INTERVAL "='15s' />\n"               \
    "  </" PCMK_XE_ACTIONS ">\n"                                              \
    "  <" PCMK_XE_SPECIAL " " PCMK_XA_TAG "='LSB'>\n"                         \
    "    <Provides>%s</Provides>\n"                                           \
    "    <Required-Start>%s</Required-Start>\n"                               \
    "    <Required-Stop>%s</Required-Stop>\n"                                 \
    "    <Should-Start>%s</Should-Start>\n"                                   \
    "    <Should-Stop>%s</Should-Stop>\n"                                     \
    "    <Default-Start>%s</Default-Start>\n"                                 \
    "    <Default-Stop>%s</Default-Stop>\n"                                   \
    "  </" PCMK_XE_SPECIAL ">\n"                                              \
    "</" PCMK_XE_RESOURCE_AGENT ">\n"

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
lsb_meta_helper_get_value(const char *line, gchar **value, const char *prefix)
{
    if ((*value == NULL) && g_str_has_prefix(line, prefix)) {
        *value = pcmk__xml_escape(line + strlen(prefix), pcmk__xml_escape_text);
        return TRUE;
    }
    return FALSE;
}

int
services__get_lsb_metadata(const char *type, char **output)
{
    char *ra_pathname = NULL;
    FILE *fp = NULL;
    char buffer[1024] = { 0, };
    gchar *provides = NULL;
    gchar *required_start = NULL;
    gchar *required_stop = NULL;
    gchar *should_start = NULL;
    gchar *should_stop = NULL;
    gchar *default_start = NULL;
    gchar *default_stop = NULL;
    gchar *short_desc = NULL;
    gchar *long_desc = NULL;
    bool in_header = FALSE;

    if (type[0] == '/') {
        ra_pathname = pcmk__str_copy(type);
    } else {
        ra_pathname = pcmk__assert_asprintf(PCMK__LSB_INIT_DIR "/%s", type);
    }

    pcmk__trace("Looking into %s", ra_pathname);
    fp = fopen(ra_pathname, "r");
    free(ra_pathname);

    if (fp == NULL) {
        return -errno;
    }

    /* Enter into the LSB-compliant comment block */
    while (fgets(buffer, sizeof(buffer), fp)) {

        // Ignore lines up to and including the block delimiter
        if (g_str_has_prefix(buffer, LSB_INITSCRIPT_INFOBEGIN_TAG)) {
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
            && g_str_has_prefix(buffer, DESCRIPTION)) {
            bool processed_line = TRUE;
            GString *desc = g_string_sized_new(2048);

            // Get remainder of description line itself
            g_string_append(desc, buffer + sizeof(DESCRIPTION) - 1);

            // Read any continuation lines of the description
            buffer[0] = '\0';
            while (fgets(buffer, sizeof(buffer), fp)) {
                if (g_str_has_prefix(buffer, "#  ")
                    || g_str_has_prefix(buffer, "#\t")) {
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
            long_desc = pcmk__xml_escape(desc->str, pcmk__xml_escape_text);
            g_string_free(desc, TRUE);

            if (processed_line) {
                // We grabbed the line into the long description
                continue;
            }
        }

        // Stop if we leave the header block
        if (g_str_has_prefix(buffer, LSB_INITSCRIPT_INFOEND_TAG)) {
            break;
        }
        if (buffer[0] != '#') {
            break;
        }
    }
    fclose(fp);

    *output = pcmk__assert_asprintf(lsb_metadata_template, type,
                                    pcmk__s(long_desc, type),
                                    pcmk__s(short_desc, type),
                                    pcmk__s(provides, ""),
                                    pcmk__s(required_start, ""),
                                    pcmk__s(required_stop, ""),
                                    pcmk__s(should_start, ""),
                                    pcmk__s(should_stop, ""),
                                    pcmk__s(default_start, ""),
                                    pcmk__s(default_stop, ""));

    g_free(long_desc);
    g_free(short_desc);
    g_free(provides);
    g_free(required_start);
    g_free(required_stop);
    g_free(should_start);
    g_free(should_stop);
    g_free(default_start);
    g_free(default_stop);
    return pcmk_ok;
}

GList *
services__list_lsb_agents(void)
{
    return services__list_dir(PCMK__LSB_INIT_DIR, true);
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
