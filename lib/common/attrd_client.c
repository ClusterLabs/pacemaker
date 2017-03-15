/*
 * Copyright (C) 2011-2017 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */


#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <crm_internal.h>

#include <stdio.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/attrd.h>

int
attrd_update_delegate(crm_ipc_t *ipc, char command, const char *host,
                      const char *name, const char *value, const char *section,
                      const char *set, const char *dampen,
                      const char *user_name, int options)
{
    int rc = -ENOTCONN;
    int max = 5;
    const char *task = NULL;
    const char *name_as = NULL;
    const char *display_host = (host ? host : "localhost");
    const char *display_command = NULL; /* for commands without name/value */
    xmlNode *update = create_xml_node(NULL, __FUNCTION__);

    static gboolean connected = TRUE;
    static crm_ipc_t *local_ipc = NULL;
    static enum crm_ipc_flags flags = crm_ipc_flags_none;

    if (ipc == NULL && local_ipc == NULL) {
        local_ipc = crm_ipc_new(T_ATTRD, 0);
        flags |= crm_ipc_client_response;
        connected = FALSE;
    }

    if (ipc == NULL) {
        ipc = local_ipc;
    }

    /* remap common aliases */
    if (safe_str_eq(section, "reboot")) {
        section = XML_CIB_TAG_STATUS;

    } else if (safe_str_eq(section, "forever")) {
        section = XML_CIB_TAG_NODES;
    }

    crm_xml_add(update, F_TYPE, T_ATTRD);
    crm_xml_add(update, F_ORIG, crm_system_name?crm_system_name:"unknown");

    if (name == NULL && command == 'U') {
        command = 'R';
    }

    switch (command) {
        case 'u':
            task = ATTRD_OP_UPDATE;
            name_as = F_ATTRD_REGEX;
            break;
        case 'D':
        case 'U':
        case 'v':
            task = ATTRD_OP_UPDATE;
            name_as = F_ATTRD_ATTRIBUTE;
            break;
        case 'R':
            task = ATTRD_OP_REFRESH;
            display_command = "refresh";
            break;
        case 'B':
            task = ATTRD_OP_UPDATE_BOTH;
            name_as = F_ATTRD_ATTRIBUTE;
            break;
        case 'Y':
            task = ATTRD_OP_UPDATE_DELAY;
            name_as = F_ATTRD_ATTRIBUTE;
            break;
        case 'Q':
            task = ATTRD_OP_QUERY;
            name_as = F_ATTRD_ATTRIBUTE;
            break;
        case 'C':
            task = ATTRD_OP_PEER_REMOVE;
            display_command = "purge";
            break;
        case 'c':
            task = ATTRD_OP_CLEAR_FAILURE;
            name_as = F_ATTRD_ATTRIBUTE;
            section = XML_CIB_TAG_STATUS;
            value = NULL;
            break;
    }

    if (name_as != NULL) {
        if ((name == NULL) && (command != 'c')) {
            rc = -EINVAL;
            goto done;
        }
        crm_xml_add(update, name_as, name);
    }

    crm_xml_add(update, F_ATTRD_TASK, task);
    crm_xml_add(update, F_ATTRD_VALUE, value);
    crm_xml_add(update, F_ATTRD_DAMPEN, dampen);
    crm_xml_add(update, F_ATTRD_SECTION, section);
    crm_xml_add(update, F_ATTRD_HOST, host);
    crm_xml_add(update, F_ATTRD_SET, set);
    crm_xml_add_int(update, F_ATTRD_IS_REMOTE, is_set(options, attrd_opt_remote));
    crm_xml_add_int(update, F_ATTRD_IS_PRIVATE, is_set(options, attrd_opt_private));
#if ENABLE_ACL
    if (user_name) {
        crm_xml_add(update, F_ATTRD_USER, user_name);
    }
#endif

    while (max > 0) {
        if (connected == FALSE) {
            crm_info("Connecting to cluster... %d retries remaining", max);
            connected = crm_ipc_connect(ipc);
        }

        if (connected) {
            rc = crm_ipc_send(ipc, update, flags, 0, NULL);
        } else {
            crm_perror(LOG_INFO, "Connection to cluster attribute manager failed");
        }

        if (ipc != local_ipc) {
            break;

        } else if (rc > 0) {
            break;

        } else if (rc == -EAGAIN || rc == -EALREADY) {
            sleep(5 - max);
            max--;

        } else {
            crm_ipc_close(ipc);
            connected = FALSE;
            sleep(5 - max);
            max--;
        }
    }

done:
    free_xml(update);
    if (rc > 0) {
        rc = pcmk_ok;
    }

    if (command == 'c') {
        crm_debug("Asked attrd to clear failure of %s on %s: %s (%d)",
                  (name? name : "all resources"),
                  (host? host : "all nodes"), pcmk_strerror(rc), rc);
    } else if (display_command) {
        crm_debug("Asked attrd to %s %s: %s (%d)",
                  display_command, display_host, pcmk_strerror(rc), rc);
    } else {
        crm_debug("Asked attrd to update %s=%s for %s: %s (%d)",
                  name, value, display_host, pcmk_strerror(rc), rc);
    }
    return rc;
}
