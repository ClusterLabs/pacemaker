/*
 * Copyright 2004-2021 the Pacemaker project contributors
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
#include <glib.h>
#include <dirent.h>

#include <crm/crm.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>

#include "fencing_private.h"

#define RH_STONITH_PREFIX "fence_"

/*!
 * \internal
 * \brief Add available RHCS-compatible agents to a list
 *
 * \param[in,out]  List to add to
 *
 * \return Number of agents added
 */
int
stonith__list_rhcs_agents(stonith_key_value_t **devices)
{
    // Essentially: ls -1 @sbin_dir@/fence_*

    int count = 0, i;
    struct dirent **namelist;
    const int file_num = scandir(PCMK__FENCE_BINDIR, &namelist, 0, alphasort);

#if _POSIX_C_SOURCE < 200809L && !(defined(O_SEARCH) || defined(O_PATH))
    char buffer[FILENAME_MAX + 1];
#elif defined(O_SEARCH)
    const int dirfd = open(PCMK__FENCE_BINDIR, O_SEARCH);
#else
    const int dirfd = open(PCMK__FENCE_BINDIR, O_PATH);
#endif

    for (i = 0; i < file_num; i++) {
        struct stat prop;

        if (pcmk__starts_with(namelist[i]->d_name, RH_STONITH_PREFIX)) {
#if _POSIX_C_SOURCE < 200809L && !(defined(O_SEARCH) || defined(O_PATH))
            snprintf(buffer, sizeof(buffer), "%s/%s", PCMK__FENCE_BINDIR,
                     namelist[i]->d_name);
            if (stat(buffer, &prop) == 0 && S_ISREG(prop.st_mode)) {
#else
            if (dirfd == -1) {
                if (i == 0) {
                    crm_notice("Problem with listing %s directory"
                               CRM_XS "errno=%d", RH_STONITH_PREFIX, errno);
                }
                free(namelist[i]);
                continue;
            }
            /* note: we can possibly prevent following symlinks here,
                     which may be a good idea, but fall on the nose when
                     these agents are moved elsewhere & linked back */
            if (fstatat(dirfd, namelist[i]->d_name, &prop, 0) == 0
                    && S_ISREG(prop.st_mode)) {
#endif
                *devices = stonith_key_value_add(*devices, NULL,
                                                 namelist[i]->d_name);
                count++;
            }
        }
        free(namelist[i]);
    }
    if (file_num > 0) {
        free(namelist);
    }
#if _POSIX_C_SOURCE >= 200809L || defined(O_SEARCH) || defined(O_PATH)
    if (dirfd >= 0) {
        close(dirfd);
    }
#endif
    return count;
}

static void
stonith_rhcs_parameter_not_required(xmlNode *metadata, const char *parameter)
{
    char *xpath = NULL;
    xmlXPathObject *xpathObj = NULL;

    CRM_CHECK(metadata != NULL, return);
    CRM_CHECK(parameter != NULL, return);

    xpath = crm_strdup_printf("//parameter[@name='%s']", parameter);
    /* Fudge metadata so that the parameter isn't required in config
     * Pacemaker handles and adds it */
    xpathObj = xpath_search(metadata, xpath);
    if (numXpathResults(xpathObj) > 0) {
        xmlNode *tmp = getXpathResult(xpathObj, 0);

        crm_xml_add(tmp, "required", "0");
    }
    freeXpathObject(xpathObj);
    free(xpath);
}

/*!
 * \brief Execute RHCS-compatible agent's meta-data action
 *
 * \param[in]  agent    Agent to execute
 * \param[in]  timeout  Action timeout
 * \param[out] metadata Where to store output xmlNode (or NULL to ignore)
 *
 * \todo timeout is currently ignored; shouldn't we use it?
 */
static int
stonith__rhcs_get_metadata(const char *agent, int timeout, xmlNode **metadata)
{
    xmlNode *xml = NULL;
    xmlNode *actions = NULL;
    xmlXPathObject *xpathObj = NULL;
    pcmk__action_result_t *result = NULL;
    stonith_action_t *action = stonith_action_create(agent, "metadata", NULL, 0,
                                                     5, NULL, NULL, NULL);
    int rc = stonith__execute(action);

    if (rc < 0) {
        crm_warn("Could not execute metadata action for %s: %s "
                 CRM_XS " rc=%d", agent, pcmk_strerror(rc), rc);
        stonith__destroy_action(action);
        return rc;
    }

    result = stonith__action_result(action);

    if (result->execution_status != PCMK_EXEC_DONE) {
        crm_warn("Could not execute metadata action for %s: %s",
                 agent, pcmk_exec_status_str(result->execution_status));
        stonith__destroy_action(action);
        return pcmk_rc2legacy(stonith__result2rc(result));
    }

    if (result->exit_status != CRM_EX_OK) {
        crm_warn("Metadata action for %s returned error code %d",
                 agent, result->exit_status);
        stonith__destroy_action(action);
        return pcmk_rc2legacy(stonith__result2rc(result));
    }

    if (result->action_stdout == NULL) {
        crm_warn("Metadata action for %s returned no data", agent);
        stonith__destroy_action(action);
        return -ENODATA;
    }

    xml = string2xml(result->action_stdout);
    stonith__destroy_action(action);

    if (xml == NULL) {
        crm_warn("Metadata for %s is invalid", agent);
        return -pcmk_err_schema_validation;
    }

    xpathObj = xpath_search(xml, "//actions");
    if (numXpathResults(xpathObj) > 0) {
        actions = getXpathResult(xpathObj, 0);
    }
    freeXpathObject(xpathObj);

    // Add start and stop (implemented by pacemaker, not agent) to meta-data
    xpathObj = xpath_search(xml, "//action[@name='stop']");
    if (numXpathResults(xpathObj) <= 0) {
        xmlNode *tmp = NULL;

        tmp = create_xml_node(actions, "action");
        crm_xml_add(tmp, "name", "stop");
        crm_xml_add(tmp, "timeout", CRM_DEFAULT_OP_TIMEOUT_S);

        tmp = create_xml_node(actions, "action");
        crm_xml_add(tmp, "name", "start");
        crm_xml_add(tmp, "timeout", CRM_DEFAULT_OP_TIMEOUT_S);
    }
    freeXpathObject(xpathObj);

    // Fudge metadata so parameters are not required in config (pacemaker adds them)
    stonith_rhcs_parameter_not_required(xml, "action");
    stonith_rhcs_parameter_not_required(xml, "plug");
    stonith_rhcs_parameter_not_required(xml, "port");

    if (metadata) {
        *metadata = xml;

    } else {
        free_xml(xml);
    }

    return pcmk_ok;
}

/*!
 * \brief Execute RHCS-compatible agent's meta-data action
 *
 * \param[in]  agent    Agent to execute
 * \param[in]  timeout  Action timeout
 * \param[out] output   Where to store action output (or NULL to ignore)
 *
 * \todo timeout is currently ignored; shouldn't we use it?
 */
int
stonith__rhcs_metadata(const char *agent, int timeout, char **output)
{
    char *buffer = NULL;
    xmlNode *xml = NULL;

    int rc = stonith__rhcs_get_metadata(agent, timeout, &xml);

    if (rc != pcmk_ok) {
        free_xml(xml);
        return rc;
    }

    buffer = dump_xml_formatted_with_text(xml);
    free_xml(xml);
    if (buffer == NULL) {
        return -pcmk_err_schema_validation;
    }
    if (output) {
        *output = buffer;
    } else {
        free(buffer);
    }
    return pcmk_ok;
}

bool
stonith__agent_is_rhcs(const char *agent)
{
    struct stat prop;
    char *buffer = crm_strdup_printf(PCMK__FENCE_BINDIR "/%s", agent);
    int rc = stat(buffer, &prop);

    free(buffer);
    return (rc >= 0) && S_ISREG(prop.st_mode);
}

int
stonith__rhcs_validate(stonith_t *st, int call_options, const char *target,
                       const char *agent, GHashTable *params,
                       const char * host_arg, int timeout,
                       char **output, char **error_output)
{
    int rc = pcmk_ok;
    int remaining_timeout = timeout;
    xmlNode *metadata = NULL;
    stonith_action_t *action = NULL;

    if (host_arg == NULL) {
        time_t start_time = time(NULL);

        rc = stonith__rhcs_get_metadata(agent, remaining_timeout, &metadata);

        if (rc == pcmk_ok) {
            uint32_t device_flags = 0;

            stonith__device_parameter_flags(&device_flags, agent, metadata);
            if (pcmk_is_set(device_flags, st_device_supports_parameter_port)) {
                host_arg = "port";

            } else if (pcmk_is_set(device_flags,
                                   st_device_supports_parameter_plug)) {
                host_arg = "plug";
            }
        }

        free_xml(metadata);

        remaining_timeout -= time(NULL) - start_time;

        if (rc == -ETIME || remaining_timeout <= 0 ) {
            return -ETIME;
        }

    } else if (pcmk__str_eq(host_arg, "none", pcmk__str_casei)) {
        host_arg = NULL;
    }

    action = stonith_action_create(agent, "validate-all",
                                   target, 0, remaining_timeout, params,
                                   NULL, host_arg);

    rc = stonith__execute(action);
    if (rc == pcmk_ok) {
        pcmk__action_result_t *result = stonith__action_result(action);

        rc = pcmk_rc2legacy(stonith__result2rc(result));

        // Take ownership of output so stonith__destroy_action() doesn't free it
        if (output != NULL) {
            *output = result->action_stdout;
            result->action_stdout = NULL;
        }
        if (error_output != NULL) {
            *error_output = result->action_stderr;
            result->action_stderr = NULL;
        }
    }
    stonith__destroy_action(action);
    return rc;
}
