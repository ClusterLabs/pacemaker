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

#define attrd_send_ack(client, id, flags) \
    pcmk__ipc_send_ack((client), (id), (flags), "ack", ATTRD_PROTOCOL_VERSION, CRM_EX_INDETERMINATE)

extern int minimum_protocol_version;
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
            crm_xml_add(host_value, PCMK__XA_ATTR_NODE_NAME, host);
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
                crm_xml_add(host_value, PCMK__XA_ATTR_NODE_NAME, v->nodename);
                crm_xml_add(host_value, PCMK__XA_ATTR_VALUE, v->current);
            }
        }
    }
    return reply;
}

/*!
 * \internal
 * \brief Respond to client clear-failure request
 *
 * \param[in] xml         Request XML
 */
void
attrd_client_clear_failure(xmlNode *xml)
{
    const char *rsc, *op, *interval_spec;

    if (minimum_protocol_version >= 2) {
        /* Propagate to all peers (including ourselves).
         * This ends up at attrd_peer_message().
         */
        send_attrd_message(NULL, xml);
        return;
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

    attrd_client_update(xml);
}

/*!
 * \internal
 * \brief Respond to a client peer-remove request (i.e. propagate to all peers)
 *
 * \param[in] client_name Name of client that made request (for log messages)
 * \param[in] xml         Root of request XML
 *
 * \return void
 */
void
attrd_client_peer_remove(pcmk__client_t *client, xmlNode *xml)
{
    // Host and ID are not used in combination, rather host has precedence
    const char *host = crm_element_value(xml, PCMK__XA_ATTR_NODE_NAME);
    char *host_alloc = NULL;

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
            crm_xml_add(xml, PCMK__XA_ATTR_NODE_NAME, host);
        }
    }

    if (host) {
        crm_info("Client %s is requesting all values for %s be removed",
                 pcmk__client_name(client), host);
        send_attrd_message(NULL, xml); /* ends up at attrd_peer_message() */
        free(host_alloc);
    } else {
        crm_info("Ignoring request by client %s to remove all peer values without specifying peer",
                 pcmk__client_name(client));
    }
}

/*!
 * \internal
 * \brief Respond to a client query
 *
 * \param[in] client Who queried us
 * \param[in] query  Root of query XML
 *
 * \return void
 */
void
attrd_client_query(pcmk__client_t *client, uint32_t id, uint32_t flags,
                   xmlNode *query)
{
    const char *attr;
    const char *origin = crm_element_value(query, F_ORIG);
    xmlNode *reply;

    if (origin == NULL) {
        origin = "unknown client";
    }
    crm_debug("Query arrived from %s", origin);

    /* Request must specify attribute name to query */
    attr = crm_element_value(query, PCMK__XA_ATTR_NAME);
    if (attr == NULL) {
        crm_warn("Ignoring malformed query from %s (no attribute name given)",
                 origin);
        return;
    }

    /* Build the XML reply */
    reply = build_query_reply(attr, crm_element_value(query,
                                                      PCMK__XA_ATTR_NODE_NAME));
    if (reply == NULL) {
        crm_err("Could not respond to query from %s: could not create XML reply",
                 origin);
        return;
    }
    crm_log_xml_trace(reply, "Reply");

    /* Send the reply to the client */
    client->request_id = 0;
    {
        int rc = pcmk__ipc_send_xml(client, id, reply, flags);

        if (rc != pcmk_rc_ok) {
            crm_err("Could not respond to query from %s: %s " CRM_XS " rc=%d",
                    origin, pcmk_rc_str(rc), rc);
        }
    }
    free_xml(reply);
}

/*!
 * \internal
 * \brief Respond to a client refresh request (i.e. write out all attributes)
 *
 * \return void
 */
void
attrd_client_refresh(void)
{
    crm_info("Updating all attributes");
    attrd_write_attributes(true, true);
}

/*!
 * \internal
 * \brief Respond to a client update request
 *
 * \param[in] xml         Root of request XML
 *
 * \return void
 */
void
attrd_client_update(xmlNode *xml)
{
    attribute_t *a = NULL;
    char *host;
    const char *attr, *value, *regex;

    /* If the message has children, that means it is a message from a newer
     * client that supports sending multiple operations at a time.  There are
     * two ways we can handle that.
     */
    if (xml_has_children(xml)) {
        if (minimum_protocol_version >= 4) {
            /* First, if all peers support a certain protocol version, we can
             * just broadcast the big message and they'll handle it.
             */
            send_attrd_message(NULL, xml);
        } else {
            /* Second, if they do not support that protocol version, split it
             * up into individual messages and call attrd_client_update on
             * each one.
             */
            for (xmlNode *child = first_named_child(xml, XML_ATTR_OP); child != NULL;
                 child = crm_next_same_xml(child)) {
                attrd_client_update(child);
            }
        }

        return;
    }

    host = crm_element_value_copy(xml, PCMK__XA_ATTR_NODE_NAME);
    attr = crm_element_value(xml, PCMK__XA_ATTR_NAME);
    value = crm_element_value(xml, PCMK__XA_ATTR_VALUE);
    regex = crm_element_value(xml, PCMK__XA_ATTR_PATTERN);

    /* If a regex was specified, broadcast a message for each match */
    if ((attr == NULL) && regex) {
        GHashTableIter aIter;
        regex_t *r_patt = calloc(1, sizeof(regex_t));

        crm_debug("Setting %s to %s", regex, value);
        if (regcomp(r_patt, regex, REG_EXTENDED|REG_NOSUB)) {
            crm_err("Bad regex '%s' for update", regex);

        } else {
            g_hash_table_iter_init(&aIter, attributes);
            while (g_hash_table_iter_next(&aIter, (gpointer *) & attr, NULL)) {
                int status = regexec(r_patt, attr, 0, NULL, 0);

                if (status == 0) {
                    crm_trace("Matched %s with %s", attr, regex);
                    crm_xml_add(xml, PCMK__XA_ATTR_NAME, attr);
                    send_attrd_message(NULL, xml);
                }
            }
        }

        free(host);
        regfree(r_patt);
        free(r_patt);
        return;

    } else if (attr == NULL) {
        crm_err("Update request did not specify attribute or regular expression");
        free(host);
        return;
    }

    if (host == NULL) {
        crm_trace("Inferring host");
        host = strdup(attrd_cluster->uname);
        crm_xml_add(xml, PCMK__XA_ATTR_NODE_NAME, host);
        crm_xml_add_int(xml, PCMK__XA_ATTR_NODE_ID, attrd_cluster->nodeid);
    }

    a = g_hash_table_lookup(attributes, attr);

    /* If value was specified using ++ or += notation, expand to real value */
    if (value) {
        if (attrd_value_needs_expansion(value)) {
            int int_value;
            attribute_value_t *v = NULL;

            if (a) {
                v = g_hash_table_lookup(a->values, host);
            }
            int_value = attrd_expand_value(value, (v? v->current : NULL));

            crm_info("Expanded %s=%s to %d", attr, value, int_value);
            crm_xml_add_int(xml, PCMK__XA_ATTR_VALUE, int_value);

            /* Replacing the value frees the previous memory, so re-query it */
            value = crm_element_value(xml, PCMK__XA_ATTR_VALUE);
        }
    }

    crm_debug("Broadcasting %s[%s]=%s%s", attr, host, value,
              (attrd_election_won()? " (writer)" : ""));

    free(host);

    send_attrd_message(NULL, xml); /* ends up at attrd_peer_message() */
}

/*!
 * \internal
 * \brief Accept a new client IPC connection
 *
 * \param[in] c    New connection
 * \param[in] uid  Client user id
 * \param[in] gid  Client group id
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
 * \param[in] c  Connection to destroy
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
    const char *op;

    // Sanity-check, and parse XML from IPC data
    CRM_CHECK((c != NULL) && (client != NULL), return 0);
    if (data == NULL) {
        crm_debug("No IPC data from PID %d", pcmk__client_pid(c));
        return 0;
    }
    xml = pcmk__client_data2xml(client, data, &id, &flags);
    if (xml == NULL) {
        crm_debug("Unrecognizable IPC data from PID %d", pcmk__client_pid(c));
        return 0;
    }

    CRM_ASSERT(client->user != NULL);
    pcmk__update_acl_user(xml, PCMK__XA_ATTR_USER, client->user);

    op = crm_element_value(xml, PCMK__XA_TASK);

    if (client->name == NULL) {
        const char *value = crm_element_value(xml, F_ORIG);
        client->name = crm_strdup_printf("%s.%d", value?value:"unknown", client->pid);
    }

    if (pcmk__str_eq(op, PCMK__ATTRD_CMD_PEER_REMOVE, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_peer_remove(client, xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_CLEAR_FAILURE, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_clear_failure(xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_update(xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE_BOTH, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_update(xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE_DELAY, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_update(xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_REFRESH, pcmk__str_casei)) {
        attrd_send_ack(client, id, flags);
        attrd_client_refresh();

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_QUERY, pcmk__str_casei)) {
        /* queries will get reply, so no ack is necessary */
        attrd_client_query(client, id, flags, xml);

    } else {
        crm_info("Ignoring request from client %s with unknown operation %s",
                 pcmk__client_name(client), op);
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
