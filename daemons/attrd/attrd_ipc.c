/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <crm/cluster.h>
#include <crm/cluster/internal.h>
#include <crm/msg_xml.h>
#include <crm/common/acl_internal.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/logging.h>
#include <crm/common/results.h>
#include <crm/common/strings_internal.h>
#include <crm/common/util.h>

#include "pacemaker-attrd.h"

static qb_ipcs_service_t *ipcs = NULL;

/*!
 * \internal
 * \brief Build the XML reply to a client query
 *
 * param[in] attr Name of requested attribute
 * param[in] host Name of requested host (or NULL for all hosts)
 *
 * \return New XML reply
 * \note Caller is responsible for freeing the resulting XML
 */
static xmlNode *build_query_reply(const char *attr, const char *host)
{
    xmlNode *reply = create_xml_node(NULL, __func__);
    attribute_t *a;

    if (reply == NULL) {
        return NULL;
    }
    crm_xml_add(reply, F_TYPE, T_ATTRD);
    crm_xml_add(reply, F_SUBTYPE, PCMK__ATTRD_CMD_QUERY);
    crm_xml_add(reply, PCMK__XA_ATTR_VERSION, ATTRD_PROTOCOL_VERSION);

    /* If desired attribute exists, add its value(s) to the reply */
    a = g_hash_table_lookup(attributes, attr);
    if (a) {
        attribute_value_t *v;
        xmlNode *host_value;

        crm_xml_add(reply, PCMK__XA_ATTR_NAME, attr);

        /* Allow caller to use "localhost" to refer to local node */
        if (pcmk__str_eq(host, "localhost", pcmk__str_casei)) {
            host = attrd_cluster->uname;
            crm_trace("Mapped localhost to %s", host);
        }

        /* If a specific node was requested, add its value */
        if (host) {
            v = g_hash_table_lookup(a->values, host);
            host_value = create_xml_node(reply, XML_CIB_TAG_NODE);
            if (host_value == NULL) {
                free_xml(reply);
                return NULL;
            }
            pcmk__xe_add_node(host_value, host, 0);
            crm_xml_add(host_value, PCMK__XA_ATTR_VALUE,
                        (v? v->current : NULL));

        /* Otherwise, add all nodes' values */
        } else {
            GHashTableIter iter;

            g_hash_table_iter_init(&iter, a->values);
            while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &v)) {
                host_value = create_xml_node(reply, XML_CIB_TAG_NODE);
                if (host_value == NULL) {
                    free_xml(reply);
                    return NULL;
                }
                pcmk__xe_add_node(host_value, v->nodename, 0);
                crm_xml_add(host_value, PCMK__XA_ATTR_VALUE, v->current);
            }
        }
    }
    return reply;
}

xmlNode *
attrd_client_clear_failure(pcmk__request_t *request)
{
    xmlNode *xml = request->xml;
    const char *rsc, *op, *interval_spec;

    attrd_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags);

    if (minimum_protocol_version >= 2) {
        /* Propagate to all peers (including ourselves).
         * This ends up at attrd_peer_message().
         */
        attrd_send_message(NULL, xml);
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
        return NULL;
    }

    rsc = crm_element_value(xml, PCMK__XA_ATTR_RESOURCE);
    op = crm_element_value(xml, PCMK__XA_ATTR_OPERATION);
    interval_spec = crm_element_value(xml, PCMK__XA_ATTR_INTERVAL);

    /* Map this to an update */
    crm_xml_add(xml, PCMK__XA_TASK, PCMK__ATTRD_CMD_UPDATE);

    /* Add regular expression matching desired attributes */

    if (rsc) {
        char *pattern;

        if (op == NULL) {
            pattern = crm_strdup_printf(ATTRD_RE_CLEAR_ONE, rsc);

        } else {
            guint interval_ms = crm_parse_interval_spec(interval_spec);

            pattern = crm_strdup_printf(ATTRD_RE_CLEAR_OP,
                                        rsc, op, interval_ms);
        }

        crm_xml_add(xml, PCMK__XA_ATTR_PATTERN, pattern);
        free(pattern);

    } else {
        crm_xml_add(xml, PCMK__XA_ATTR_PATTERN, ATTRD_RE_CLEAR_ALL);
    }

    /* Make sure attribute and value are not set, so we delete via regex */
    if (crm_element_value(xml, PCMK__XA_ATTR_NAME)) {
        crm_xml_replace(xml, PCMK__XA_ATTR_NAME, NULL);
    }
    if (crm_element_value(xml, PCMK__XA_ATTR_VALUE)) {
        crm_xml_replace(xml, PCMK__XA_ATTR_VALUE, NULL);
    }

    return attrd_client_update(request);
}

xmlNode *
attrd_client_peer_remove(pcmk__request_t *request)
{
    xmlNode *xml = request->xml;

    // Host and ID are not used in combination, rather host has precedence
    const char *host = crm_element_value(xml, PCMK__XA_ATTR_NODE_NAME);
    char *host_alloc = NULL;

    attrd_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags);

    if (host == NULL) {
        int nodeid = 0;

        crm_element_value_int(xml, PCMK__XA_ATTR_NODE_ID, &nodeid);
        if (nodeid > 0) {
            crm_node_t *node = pcmk__search_cluster_node_cache(nodeid, NULL);
            char *host_alloc = NULL;

            if (node && node->uname) {
                // Use cached name if available
                host = node->uname;
            } else {
                // Otherwise ask cluster layer
                host_alloc = get_node_name(nodeid);
                host = host_alloc;
            }
            pcmk__xe_add_node(xml, host, 0);
        }
    }

    if (host) {
        crm_info("Client %s is requesting all values for %s be removed",
                 pcmk__client_name(request->ipc_client), host);
        attrd_send_message(NULL, xml); /* ends up at attrd_peer_message() */
        free(host_alloc);
    } else {
        crm_info("Ignoring request by client %s to remove all peer values without specifying peer",
                 pcmk__client_name(request->ipc_client));
    }

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    return NULL;
}

xmlNode *
attrd_client_query(pcmk__request_t *request)
{
    xmlNode *query = request->xml;
    xmlNode *reply = NULL;
    const char *attr = NULL;

    crm_debug("Query arrived from %s", pcmk__client_name(request->ipc_client));

    /* Request must specify attribute name to query */
    attr = crm_element_value(query, PCMK__XA_ATTR_NAME);
    if (attr == NULL) {
        pcmk__format_result(&request->result, CRM_EX_ERROR, PCMK_EXEC_ERROR,
                            "Ignoring malformed query from %s (no attribute name given)",
                            pcmk__client_name(request->ipc_client));
        return NULL;
    }

    /* Build the XML reply */
    reply = build_query_reply(attr, crm_element_value(query,
                                                      PCMK__XA_ATTR_NODE_NAME));
    if (reply == NULL) {
        pcmk__format_result(&request->result, CRM_EX_ERROR, PCMK_EXEC_ERROR,
                            "Could not respond to query from %s: could not create XML reply",
                            pcmk__client_name(request->ipc_client));
        return NULL;
    } else {
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    }

    request->ipc_client->request_id = 0;
    return reply;
}

xmlNode *
attrd_client_refresh(pcmk__request_t *request)
{
    crm_info("Updating all attributes");

    attrd_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags);
    attrd_write_attributes(true, true);

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    return NULL;
}

static void
handle_missing_host(xmlNode *xml)
{
    const char *host = crm_element_value(xml, PCMK__XA_ATTR_NODE_NAME);

    if (host == NULL) {
        crm_trace("Inferring host");
        pcmk__xe_add_node(xml, attrd_cluster->uname, attrd_cluster->nodeid);
    }
}

static int
handle_value_expansion(const char **value, xmlNode *xml, const char *op,
                       const char *attr)
{
    attribute_t *a = g_hash_table_lookup(attributes, attr);

    if (a == NULL && pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE_DELAY, pcmk__str_none)) {
        return EINVAL;
    }

    if (*value && attrd_value_needs_expansion(*value)) {
        int int_value;
        attribute_value_t *v = NULL;

        if (a) {
            const char *host = crm_element_value(xml, PCMK__XA_ATTR_NODE_NAME);
            v = g_hash_table_lookup(a->values, host);
        }

        int_value = attrd_expand_value(*value, (v? v->current : NULL));

        crm_info("Expanded %s=%s to %d", attr, *value, int_value);
        crm_xml_add_int(xml, PCMK__XA_ATTR_VALUE, int_value);

        /* Replacing the value frees the previous memory, so re-query it */
        *value = crm_element_value(xml, PCMK__XA_ATTR_VALUE);
    }

    return pcmk_rc_ok;
}

xmlNode *
attrd_client_update(pcmk__request_t *request)
{
    xmlNode *xml = request->xml;
    const char *attr, *value, *regex;

    /* If the message has children, that means it is a message from a newer
     * client that supports sending multiple operations at a time.  There are
     * two ways we can handle that.
     */
    if (xml_has_children(xml)) {
        if (minimum_protocol_version >= 4) {
            /* First, if all peers support a certain protocol version, we can
             * just broadcast the big message and they'll handle it.  However,
             * we also need to apply all the transformations in this function
             * to the children since they don't happen anywhere else.
             */
            for (xmlNode *child = first_named_child(xml, XML_ATTR_OP); child != NULL;
                 child = crm_next_same_xml(child)) {
                attr = crm_element_value(child, PCMK__XA_ATTR_NAME);
                value = crm_element_value(child, PCMK__XA_ATTR_VALUE);

                handle_missing_host(child);

                if (handle_value_expansion(&value, child, request->op, attr) == EINVAL) {
                    pcmk__format_result(&request->result, CRM_EX_NOSUCH, PCMK_EXEC_ERROR,
                                        "Attribute %s does not exist", attr);
                    return NULL;
                }
            }

            attrd_send_message(NULL, xml);
            pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);

        } else {
            /* Second, if they do not support that protocol version, split it
             * up into individual messages and call attrd_client_update on
             * each one.
             */
            for (xmlNode *child = first_named_child(xml, XML_ATTR_OP); child != NULL;
                 child = crm_next_same_xml(child)) {
                request->xml = child;
                /* Calling pcmk__set_result is handled by one of these calls to
                 * attrd_client_update, so no need to do it again here.
                 */
                attrd_client_update(request);
            }
        }

        return NULL;
    }

    attr = crm_element_value(xml, PCMK__XA_ATTR_NAME);
    value = crm_element_value(xml, PCMK__XA_ATTR_VALUE);
    regex = crm_element_value(xml, PCMK__XA_ATTR_PATTERN);

    /* If a regex was specified, broadcast a message for each match */
    if ((attr == NULL) && regex) {
        GHashTableIter aIter;
        regex_t *r_patt = calloc(1, sizeof(regex_t));

        crm_debug("Setting %s to %s", regex, value);
        if (regcomp(r_patt, regex, REG_EXTENDED|REG_NOSUB)) {
            pcmk__format_result(&request->result, CRM_EX_ERROR, PCMK_EXEC_ERROR,
                                "Bad regex '%s' for update from client %s", regex,
                                pcmk__client_name(request->ipc_client));

        } else {
            g_hash_table_iter_init(&aIter, attributes);
            while (g_hash_table_iter_next(&aIter, (gpointer *) & attr, NULL)) {
                int status = regexec(r_patt, attr, 0, NULL, 0);

                if (status == 0) {
                    crm_trace("Matched %s with %s", attr, regex);
                    crm_xml_add(xml, PCMK__XA_ATTR_NAME, attr);
                    attrd_send_message(NULL, xml);
                }
            }

            pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
        }

        regfree(r_patt);
        free(r_patt);
        return NULL;

    } else if (attr == NULL) {
        crm_err("Update request did not specify attribute or regular expression");
        pcmk__format_result(&request->result, CRM_EX_ERROR, PCMK_EXEC_ERROR,
                            "Client %s update request did not specify attribute or regular expression",
                            pcmk__client_name(request->ipc_client));
        return NULL;
    }

    handle_missing_host(xml);

    if (handle_value_expansion(&value, xml, request->op, attr) == EINVAL) {
        pcmk__format_result(&request->result, CRM_EX_NOSUCH, PCMK_EXEC_ERROR,
                            "Attribute %s does not exist", attr);
        return NULL;
    }

    crm_debug("Broadcasting %s[%s]=%s%s", attr, crm_element_value(xml, PCMK__XA_ATTR_NODE_NAME),
              value, (attrd_election_won()? " (writer)" : ""));

    attrd_send_message(NULL, xml); /* ends up at attrd_peer_message() */
    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    return NULL;
}

/*!
 * \internal
 * \brief Accept a new client IPC connection
 *
 * \param[in,out] c    New connection
 * \param[in]     uid  Client user id
 * \param[in]     gid  Client group id
 *
 * \return pcmk_ok on success, -errno otherwise
 */
static int32_t
attrd_ipc_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    crm_trace("New client connection %p", c);
    if (attrd_shutting_down()) {
        crm_info("Ignoring new connection from pid %d during shutdown",
                 pcmk__client_pid(c));
        return -EPERM;
    }

    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -EIO;
    }
    return pcmk_ok;
}

/*!
 * \internal
 * \brief Destroy a client IPC connection
 *
 * \param[in] c  Connection to destroy
 *
 * \return FALSE (i.e. do not re-run this callback)
 */
static int32_t
attrd_ipc_closed(qb_ipcs_connection_t *c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        crm_trace("Ignoring request to clean up unknown connection %p", c);
    } else {
        crm_trace("Cleaning up closed client connection %p", c);
        pcmk__free_client(client);
    }
    return FALSE;
}

/*!
 * \internal
 * \brief Destroy a client IPC connection
 *
 * \param[in,out] c  Connection to destroy
 *
 * \note We handle a destroyed connection the same as a closed one,
 *       but we need a separate handler because the return type is different.
 */
static void
attrd_ipc_destroy(qb_ipcs_connection_t *c)
{
    crm_trace("Destroying client connection %p", c);
    attrd_ipc_closed(c);
}

static int32_t
attrd_ipc_dispatch(qb_ipcs_connection_t * c, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    pcmk__client_t *client = pcmk__find_client(c);
    xmlNode *xml = NULL;

    // Sanity-check, and parse XML from IPC data
    CRM_CHECK((c != NULL) && (client != NULL), return 0);
    if (data == NULL) {
        crm_debug("No IPC data from PID %d", pcmk__client_pid(c));
        return 0;
    }

    xml = pcmk__client_data2xml(client, data, &id, &flags);

    if (xml == NULL) {
        crm_debug("Unrecognizable IPC data from PID %d", pcmk__client_pid(c));
        pcmk__ipc_send_ack(client, id, flags, "ack", NULL, CRM_EX_PROTOCOL);
        return 0;

    } else {
        pcmk__request_t request = {
            .ipc_client     = client,
            .ipc_id         = id,
            .ipc_flags      = flags,
            .peer           = NULL,
            .xml            = xml,
            .call_options   = 0,
            .result         = PCMK__UNKNOWN_RESULT,
        };

        CRM_ASSERT(client->user != NULL);
        pcmk__update_acl_user(xml, PCMK__XA_ATTR_USER, client->user);

        request.op = crm_element_value_copy(request.xml, PCMK__XA_TASK);
        CRM_CHECK(request.op != NULL, return 0);

        attrd_handle_request(&request);
        pcmk__reset_request(&request);
    }

    free_xml(xml);
    return 0;
}

static struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = attrd_ipc_accept,
    .connection_created = NULL,
    .msg_process = attrd_ipc_dispatch,
    .connection_closed = attrd_ipc_closed,
    .connection_destroyed = attrd_ipc_destroy
};

void
attrd_ipc_fini(void)
{
    if (ipcs != NULL) {
        pcmk__drop_all_clients(ipcs);
        qb_ipcs_destroy(ipcs);
        ipcs = NULL;
    }
}

/*!
 * \internal
 * \brief Set up attrd IPC communication
 */
void
attrd_init_ipc(void)
{
    pcmk__serve_attrd_ipc(&ipcs, &ipc_callbacks);
}
