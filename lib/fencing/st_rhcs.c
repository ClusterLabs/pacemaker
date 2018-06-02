/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
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

    int count = 0;
    struct dirent **namelist;
    int file_num = scandir(RH_STONITH_DIR, &namelist, 0, alphasort);

    if (file_num > 0) {
        struct stat prop;
        char buffer[FILENAME_MAX + 1];

        while (file_num--) {
            if ('.' == namelist[file_num]->d_name[0]) {
                free(namelist[file_num]);
                continue;

            } else if (!crm_starts_with(namelist[file_num]->d_name,
                                        RH_STONITH_PREFIX)) {
                free(namelist[file_num]);
                continue;
            }

            snprintf(buffer, FILENAME_MAX, "%s/%s", RH_STONITH_DIR,
                     namelist[file_num]->d_name);
            if (stat(buffer, &prop) == 0 && S_ISREG(prop.st_mode)) {
                *devices = stonith_key_value_add(*devices, NULL,
                                                 namelist[file_num]->d_name);
                count++;
            }

            free(namelist[file_num]);
        }
        free(namelist);
    }
    return count;
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
    int rc = 0;
    char *buffer = NULL;
    xmlNode *xml = NULL;
    xmlNode *actions = NULL;
    xmlXPathObject *xpathObj = NULL;
    stonith_action_t *action = stonith_action_create(agent, "metadata", NULL, 0,
                                                     5, NULL, NULL);
    int exec_rc = stonith_action_execute(action, &rc, &buffer);

    if ((exec_rc < 0) || (rc != 0) || (buffer == NULL)) {
        crm_warn("Could not obtain metadata for %s", agent);
        crm_debug("Query failed: %d %d: %s", exec_rc, rc, crm_str(buffer));
        free(buffer);
        return -EINVAL;
    }

    xml = string2xml(buffer);
    if (xml == NULL) {
        crm_warn("Metadata for %s is invalid", agent);
        free(buffer);
        return -EINVAL;
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

    // Fudge metadata so port isn't required in config (pacemaker adds it)
    xpathObj = xpath_search(xml, "//parameter[@name='port']");
    if (numXpathResults(xpathObj) > 0) {
        xmlNode *tmp = getXpathResult(xpathObj, 0);

        crm_xml_add(tmp, "required", "0");
    }
    freeXpathObject(xpathObj);

    free(buffer);
    buffer = dump_xml_formatted_with_text(xml);
    free_xml(xml);
    if (buffer == NULL) {
        return -EINVAL;
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
    char *buffer = crm_strdup_printf(RH_STONITH_DIR "/%s", agent);
    int rc = stat(buffer, &prop);

    free(buffer);
    return (rc >= 0) && S_ISREG(prop.st_mode);
}
