/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <glib.h>
#include <libxml/xpath.h>           // xmlXPathObject, etc.

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>

#include "fencing_private.h"

/*!
 * \internal
 * \brief \c scandir() filter for RHCS fence agents
 *
 * \param[in] entry  Directory entry
 *
 * \retval 1 if \p entry is a regular file whose name begins with \c "fence_"
 * \retval 0 otherwise
 */
static int
rhcs_agent_filter(const struct dirent *entry)
{
    char *buf = NULL;
    struct stat sb;
    int rc = 0;

    if (!pcmk__starts_with(entry->d_name, "fence_")) {
        goto done;
    }

    // glibc doesn't enforce PATH_MAX, so don't limit buf size
    buf = crm_strdup_printf(PCMK__FENCE_BINDIR "/%s", entry->d_name);
    if ((stat(buf, &sb) != 0) || !S_ISREG(sb.st_mode)) {
        goto done;
    }

    rc = 1;

done:
    free(buf);
    return rc;
}

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
    struct dirent **namelist = NULL;
    const int file_num = scandir(PCMK__FENCE_BINDIR, &namelist,
                                 rhcs_agent_filter, alphasort);

    if (file_num < 0) {
        int rc = errno;

        crm_err("Could not list " PCMK__FENCE_BINDIR ": %s", pcmk_rc_str(rc));
        free(namelist);
        return 0;
    }

    for (int i = 0; i < file_num; i++) {
        *devices = stonith_key_value_add(*devices, NULL, namelist[i]->d_name);
        free(namelist[i]);
    }
    free(namelist);
    return file_num;
}

static void
stonith_rhcs_parameter_not_required(xmlNode *metadata, const char *parameter)
{
    char *xpath = NULL;
    xmlXPathObject *xpathObj = NULL;

    CRM_CHECK(metadata != NULL, return);
    CRM_CHECK(parameter != NULL, return);

    xpath = crm_strdup_printf("//" PCMK_XE_PARAMETER "[@" PCMK_XA_NAME "='%s']",
                              parameter);
    /* Fudge metadata so that the parameter isn't required in config
     * Pacemaker handles and adds it */
    xpathObj = pcmk__xpath_search(metadata->doc, xpath);
    if (pcmk__xpath_num_results(xpathObj) > 0) {
        xmlNode *tmp = pcmk__xpath_result(xpathObj, 0);

        if (tmp != NULL) {
            pcmk__xe_set(tmp, "required", "0");
        }
    }
    xmlXPathFreeObject(xpathObj);
    free(xpath);
}

/*!
 * \brief Execute RHCS-compatible agent's metadata action
 *
 * \param[in]  agent        Agent to execute
 * \param[in]  timeout_sec  Action timeout
 * \param[out] metadata     Where to store output xmlNode (or NULL to ignore)
 */
static int
stonith__rhcs_get_metadata(const char *agent, int timeout_sec,
                           xmlNode **metadata)
{
    xmlNode *xml = NULL;
    xmlNode *actions = NULL;
    xmlXPathObject *xpathObj = NULL;
    stonith_action_t *action = stonith__action_create(agent,
                                                      PCMK_ACTION_METADATA,
                                                      NULL, 0, timeout_sec,
                                                      NULL, NULL, NULL);
    int rc = stonith__execute(action);
    pcmk__action_result_t *result = stonith__action_result(action);

    if (result == NULL) {
        if (rc < 0) {
            crm_warn("Could not execute metadata action for %s: %s "
                     QB_XS " rc=%d", agent, pcmk_strerror(rc), rc);
        }
        stonith__destroy_action(action);
        return rc;
    }

    if (result->execution_status != PCMK_EXEC_DONE) {
        crm_warn("Could not execute metadata action for %s: %s",
                 agent, pcmk_exec_status_str(result->execution_status));
        rc = pcmk_rc2legacy(stonith__result2rc(result));
        stonith__destroy_action(action);
        return rc;
    }

    if (!pcmk__result_ok(result)) {
        crm_warn("Metadata action for %s returned error code %d",
                 agent, result->exit_status);
        rc = pcmk_rc2legacy(stonith__result2rc(result));
        stonith__destroy_action(action);
        return rc;
    }

    if (result->action_stdout == NULL) {
        crm_warn("Metadata action for %s returned no data", agent);
        stonith__destroy_action(action);
        return -ENODATA;
    }

    xml = pcmk__xml_parse(result->action_stdout);
    stonith__destroy_action(action);

    if (xml == NULL) {
        crm_warn("Metadata for %s is invalid", agent);
        return -pcmk_err_schema_validation;
    }

    xpathObj = pcmk__xpath_search(xml->doc, "//" PCMK_XE_ACTIONS);
    if (pcmk__xpath_num_results(xpathObj) > 0) {
        actions = pcmk__xpath_result(xpathObj, 0);
    }
    xmlXPathFreeObject(xpathObj);

    // Add start and stop (implemented by pacemaker, not agent) to meta-data
    xpathObj = pcmk__xpath_search(xml->doc,
                                  "//" PCMK_XE_ACTION
                                  "[@" PCMK_XA_NAME "='" PCMK_ACTION_STOP "']");
    if (pcmk__xpath_num_results(xpathObj) == 0) {
        xmlNode *tmp = NULL;
        const char *timeout_str = NULL;

        timeout_str = pcmk__readable_interval(PCMK_DEFAULT_ACTION_TIMEOUT_MS);

        tmp = pcmk__xe_create(actions, PCMK_XE_ACTION);
        pcmk__xe_set(tmp, PCMK_XA_NAME, PCMK_ACTION_STOP);
        pcmk__xe_set(tmp, PCMK_META_TIMEOUT, timeout_str);

        tmp = pcmk__xe_create(actions, PCMK_XE_ACTION);
        pcmk__xe_set(tmp, PCMK_XA_NAME, PCMK_ACTION_START);
        pcmk__xe_set(tmp, PCMK_META_TIMEOUT, timeout_str);
    }
    xmlXPathFreeObject(xpathObj);

    // Fudge metadata so parameters are not required in config (pacemaker adds them)
    stonith_rhcs_parameter_not_required(xml, STONITH_ATTR_ACTION_OP);
    stonith_rhcs_parameter_not_required(xml, "plug");
    stonith_rhcs_parameter_not_required(xml, "port");

    if (metadata) {
        *metadata = xml;

    } else {
        pcmk__xml_free(xml);
    }

    return pcmk_ok;
}

/*!
 * \brief Retrieve metadata for RHCS-compatible fence agent
 *
 * \param[in]  agent        Agent to execute
 * \param[in]  timeout_sec  Action timeout
 * \param[out] output       Where to store action output (or NULL to ignore)
 */
int
stonith__rhcs_metadata(const char *agent, int timeout_sec, char **output)
{
    GString *buffer = NULL;
    xmlNode *xml = NULL;

    int rc = stonith__rhcs_get_metadata(agent, timeout_sec, &xml);

    if (rc != pcmk_ok) {
        goto done;
    }

    buffer = g_string_sized_new(1024);
    pcmk__xml_string(xml, pcmk__xml_fmt_pretty|pcmk__xml_fmt_text, buffer, 0);

    if (pcmk__str_empty(buffer->str)) {
        rc = -pcmk_err_schema_validation;
        goto done;
    }

    if (output != NULL) {
        pcmk__str_update(output, buffer->str);
    }

done:
    if (buffer != NULL) {
        g_string_free(buffer, TRUE);
    }
    pcmk__xml_free(xml);
    return rc;
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
    pcmk__action_result_t *result = NULL;

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

        pcmk__xml_free(metadata);

        remaining_timeout -= time(NULL) - start_time;

        if (rc == -ETIME || remaining_timeout <= 0 ) {
            return -ETIME;
        }

    } else if (pcmk__str_eq(host_arg, PCMK_VALUE_NONE, pcmk__str_casei)) {
        host_arg = NULL;
    }

    action = stonith__action_create(agent, PCMK_ACTION_VALIDATE_ALL, target, 0,
                                    remaining_timeout, params, NULL, host_arg);

    rc = stonith__execute(action);
    result = stonith__action_result(action);

    if (result != NULL) {
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
