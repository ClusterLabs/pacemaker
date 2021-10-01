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

#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/services.h>
#include "services_private.h"
#include "services_lsb.h"

#define lsb_metadata_template  \
    "<?xml version='1.0'?>\n"                                           \
    "<!DOCTYPE resource-agent SYSTEM 'ra-api-1.dtd'>\n"                 \
    "<resource-agent name='%s' version='" PCMK_DEFAULT_AGENT_VERSION "'>\n" \
    "  <version>1.0</version>\n"                                        \
    "  <longdesc lang='en'>\n"                                          \
    "%s"                                                                \
    "  </longdesc>\n"                                                   \
    "  <shortdesc lang='en'>%s</shortdesc>\n"                           \
    "  <parameters>\n"                                                  \
    "  </parameters>\n"                                                 \
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
#define LSB_INITSCRIPT_INFOBEGIN_TAG "### BEGIN INIT INFO"
#define LSB_INITSCRIPT_INFOEND_TAG "### END INIT INFO"
#define PROVIDES    "# Provides:"
#define REQ_START   "# Required-Start:"
#define REQ_STOP    "# Required-Stop:"
#define SHLD_START  "# Should-Start:"
#define SHLD_STOP   "# Should-Stop:"
#define DFLT_START  "# Default-Start:"
#define DFLT_STOP   "# Default-Stop:"
#define SHORT_DSCR  "# Short-Description:"
#define DESCRIPTION "# Description:"

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

#define DESC_MAX 2048

int
services__get_lsb_metadata(const char *type, char **output)
{
    char ra_pathname[PATH_MAX] = { 0, };
    FILE *fp = NULL;
    char buffer[1024] = { 0, };
    char *provides = NULL;
    char *req_start = NULL;
    char *req_stop = NULL;
    char *shld_start = NULL;
    char *shld_stop = NULL;
    char *dflt_start = NULL;
    char *dflt_stop = NULL;
    char *s_dscrpt = NULL;
    char *xml_l_dscrpt = NULL;
    int offset = 0;
    bool in_header = FALSE;
    char description[DESC_MAX] = { 0, };

    if (type[0] == '/') {
        snprintf(ra_pathname, sizeof(ra_pathname), "%s", type);
    } else {
        snprintf(ra_pathname, sizeof(ra_pathname), "%s/%s",
                 LSB_ROOT_DIR, type);
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
        if (lsb_meta_helper_get_value(buffer, &req_start, REQ_START)) {
            continue;
        }
        if (lsb_meta_helper_get_value(buffer, &req_stop, REQ_STOP)) {
            continue;
        }
        if (lsb_meta_helper_get_value(buffer, &shld_start, SHLD_START)) {
            continue;
        }
        if (lsb_meta_helper_get_value(buffer, &shld_stop, SHLD_STOP)) {
            continue;
        }
        if (lsb_meta_helper_get_value(buffer, &dflt_start, DFLT_START)) {
            continue;
        }
        if (lsb_meta_helper_get_value(buffer, &dflt_stop, DFLT_STOP)) {
            continue;
        }
        if (lsb_meta_helper_get_value(buffer, &s_dscrpt, SHORT_DSCR)) {
            continue;
        }

        /* Long description may cross multiple lines */
        if ((offset == 0) // haven't already found long description
            && pcmk__starts_with(buffer, DESCRIPTION)) {
            bool processed_line = TRUE;

            // Get remainder of description line itself
            offset += snprintf(description, DESC_MAX, "%s",
                               buffer + strlen(DESCRIPTION));

            // Read any continuation lines of the description
            buffer[0] = '\0';
            while (fgets(buffer, sizeof(buffer), fp)) {
                if (pcmk__starts_with(buffer, "#  ")
                    || pcmk__starts_with(buffer, "#\t")) {
                    /* '#' followed by a tab or more than one space indicates a
                     * continuation of the long description.
                     */
                    offset += snprintf(description + offset, DESC_MAX - offset,
                                       "%s", buffer + 1);
                } else {
                    /* This line is not part of the long description,
                     * so continue with normal processing.
                     */
                    processed_line = FALSE;
                    break;
                }
            }

            // Make long description safe to use in XML
            xml_l_dscrpt = (char *)xmlEncodeEntitiesReentrant(NULL, BAD_CAST(description));

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
                                (xml_l_dscrpt? xml_l_dscrpt : type),
                                (s_dscrpt? s_dscrpt : type),
                                (provides? provides : ""),
                                (req_start? req_start : ""),
                                (req_stop? req_stop : ""),
                                (shld_start? shld_start : ""),
                                (shld_stop? shld_stop : ""),
                                (dflt_start? dflt_start : ""),
                                (dflt_stop? dflt_stop : ""));

    lsb_meta_helper_free_value(xml_l_dscrpt);
    lsb_meta_helper_free_value(s_dscrpt);
    lsb_meta_helper_free_value(provides);
    lsb_meta_helper_free_value(req_start);
    lsb_meta_helper_free_value(req_stop);
    lsb_meta_helper_free_value(shld_start);
    lsb_meta_helper_free_value(shld_stop);
    lsb_meta_helper_free_value(dflt_start);
    lsb_meta_helper_free_value(dflt_stop);

    crm_trace("Created fake metadata: %llu",
              (unsigned long long) strlen(*output));
    return pcmk_ok;
}

GList *
services__list_lsb_agents(void)
{
    return services_os_get_directory_list(LSB_ROOT_DIR, TRUE, TRUE);
}

bool
services__lsb_agent_exists(const char *agent)
{
    bool rc = FALSE;
    struct stat st;
    char *path = pcmk__full_path(agent, LSB_ROOT_DIR);

    rc = (stat(path, &st) == 0);
    free(path);
    return rc;
}

/*!
 * \internal
 * \brief Prepare an LSB action
 *
 * \param[in] op  Action to prepare
 *
 * \return Standard Pacemaker return code
 */
int
services__lsb_prepare(svc_action_t *op)
{
    op->opaque->exec = pcmk__full_path(op->agent, LSB_ROOT_DIR);
    op->opaque->args[0] = strdup(op->opaque->exec);
    op->opaque->args[1] = strdup(op->action);
    if ((op->opaque->args[0] == NULL) || (op->opaque->args[1] == NULL)) {
        return ENOMEM;
    }
    return pcmk_rc_ok;
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
