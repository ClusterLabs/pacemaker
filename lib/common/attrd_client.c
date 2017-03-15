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

/*!
 * \internal
 * \brief Create a generic attrd operation
 *
 * \param[in] user_name  If not NULL, ACL user to set for operation
 *
 * \return XML of attrd operation
 */
static xmlNode *
create_attrd_op(const char *user_name)
{
    xmlNode *attrd_op = create_xml_node(NULL, __FUNCTION__);

    crm_xml_add(attrd_op, F_TYPE, T_ATTRD);
    crm_xml_add(attrd_op, F_ORIG, (crm_system_name? crm_system_name: "unknown"));
#if ENABLE_ACL
    crm_xml_add(attrd_op, F_ATTRD_USER, user_name);
#endif

    return attrd_op;
}

/*!
 * \internal
 * \brief Send an operation to attrd via IPC
 *
 * \param[in] ipc       Connection to attrd (or NULL to use a local connection)
 * \param[in] attrd_op  XML of attrd operation to send
 *
 * \return pcmk_ok on success, -errno otherwise
 */
static int
send_attrd_op(crm_ipc_t *ipc, xmlNode *attrd_op)
{
    int rc = -ENOTCONN;
    int max = 5;

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

    while (max > 0) {
        if (connected == FALSE) {
            crm_info("Connecting to cluster... %d retries remaining", max);
            connected = crm_ipc_connect(ipc);
        }

        if (connected) {
            rc = crm_ipc_send(ipc, attrd_op, flags, 0, NULL);
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

    if (rc > 0) {
        rc = pcmk_ok;
    }
    return rc;
}

/*!
 * \brief Send a request to attrd
 *
 * \param[in] ipc      Connection to attrd (or NULL to use a local connection)
 * \param[in] command  A character indicating the type of attrd request:
 *                     U or v: update attribute (or refresh if name is NULL)
 *                     u: update attributes matching regular expression in name
 *                     D: delete attribute (value must be NULL)
 *                     R: refresh
 *                     B: update both attribute and its dampening
 *                     Y: update attribute dampening only
 *                     Q: query attribute
 *                     C: remove peer specified by host
 * \param[in] host     Affect only this host (or NULL for all hosts)
 * \param[in] name     Name of attribute to affect
 * \param[in] value    Attribute value to set
 * \param[in] section  Status or nodes
 * \param[in] set      ID of attribute set to use (or NULL to choose first)
 * \param[in] dampen   Attribute dampening to use with B/Y, and U/v if creating
 * \param[in] user_name ACL user to pass to attrd
 * \param[in] options  Bitmask that may include:
 *                     attrd_opt_remote: host is a Pacemaker Remote node
 *                     attrd_opt_private: attribute is private (not kept in CIB)
 *
 * \return pcmk_ok if request was successfully submitted to attrd, else -errno
 */
int
attrd_update_delegate(crm_ipc_t *ipc, char command, const char *host,
                      const char *name, const char *value, const char *section,
                      const char *set, const char *dampen,
                      const char *user_name, int options)
{
    int rc = pcmk_ok;
    const char *task = NULL;
    const char *name_as = NULL;
    const char *display_host = (host ? host : "localhost");
    const char *display_command = NULL; /* for commands without name/value */
    xmlNode *update = create_attrd_op(user_name);

    /* remap common aliases */
    if (safe_str_eq(section, "reboot")) {
        section = XML_CIB_TAG_STATUS;

    } else if (safe_str_eq(section, "forever")) {
        section = XML_CIB_TAG_NODES;
    }

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
    }

    if (name_as != NULL) {
        if (name == NULL) {
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

    rc = send_attrd_op(ipc, update);

done:
    free_xml(update);

    if (display_command) {
        crm_debug("Asked attrd to %s %s: %s (%d)",
                  display_command, display_host, pcmk_strerror(rc), rc);
    } else {
        crm_debug("Asked attrd to update %s=%s for %s: %s (%d)",
                  name, value, display_host, pcmk_strerror(rc), rc);
    }
    return rc;
}

/*!
 * \brief Send a request to attrd to clear resource failure
 *
 * \param[in] ipc       Connection to attrd (or NULL to use a local connection)
 * \param[in] host      Affect only this host (or NULL for all hosts)
 * \param[in] name      Name of resource to clear
 * \param[in] user_name ACL user to pass to attrd
 * \param[in] options   attrd_opt_remote if host is a Pacemaker Remote node
 *
 * \return pcmk_ok if request was successfully submitted to attrd, else -errno
 */
int
attrd_clear_delegate(crm_ipc_t *ipc, const char *host, const char *resource,
                     const char *user_name, int options)
{
    int rc = pcmk_ok;
    xmlNode *clear_op = create_attrd_op(user_name);

    crm_xml_add(clear_op, F_ATTRD_TASK, ATTRD_OP_CLEAR_FAILURE);
    crm_xml_add(clear_op, F_ATTRD_HOST, host);
    crm_xml_add(clear_op, F_ATTRD_RESOURCE, resource);
    crm_xml_add_int(clear_op, F_ATTRD_IS_REMOTE, is_set(options, attrd_opt_remote));

    rc = send_attrd_op(ipc, clear_op);
    free_xml(clear_op);

    crm_debug("Asked attrd to clear failure of %s on %s: %s (%d)",
              (resource? resource : "all resources"),
              (host? host : "all nodes"), pcmk_strerror(rc), rc);
    return rc;
}
