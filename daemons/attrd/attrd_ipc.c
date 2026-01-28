/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>   // PRIu32
#include <sys/types.h>

#include <crm/cluster.h>
#include <crm/cluster/internal.h>
#include <crm/common/logging.h>
#include <crm/common/results.h>
#include <crm/common/util.h>
#include <crm/common/xml.h>

#include "pacemaker-attrd.h"

static qb_ipcs_service_t *ipcs = NULL;

/*!
 * \internal
 * \brief Build the XML reply to a client query
 *
 * \param[in] attr Name of requested attribute
 * \param[in] host Name of requested host (or NULL for all hosts)
 *
 * \return New XML reply
 * \note Caller is responsible for freeing the resulting XML
 */
static xmlNode *build_query_reply(const char *attr, const char *host)
{
    xmlNode *reply = pcmk__xe_create(NULL, __func__);
    attribute_t *a;

    pcmk__xe_set(reply, PCMK__XA_T, PCMK__VALUE_ATTRD);
    pcmk__xe_set(reply, PCMK__XA_SUBT, PCMK__ATTRD_CMD_QUERY);
    pcmk__xe_set(reply, PCMK__XA_ATTR_VERSION, ATTRD_PROTOCOL_VERSION);

    /* If desired attribute exists, add its value(s) to the reply */
    a = g_hash_table_lookup(attributes, attr);
    if (a) {
        attribute_value_t *v;
        xmlNode *host_value;

        pcmk__xe_set(reply, PCMK__XA_ATTR_NAME, attr);

        /* Allow caller to use "localhost" to refer to local node */
        if (pcmk__str_eq(host, "localhost", pcmk__str_casei)) {
            host = attrd_cluster->priv->node_name;
            pcmk__trace("Mapped localhost to %s", host);
        }

        /* If a specific node was requested, add its value */
        if (host) {
            v = g_hash_table_lookup(a->values, host);
            host_value = pcmk__xe_create(reply, PCMK_XE_NODE);
            pcmk__xe_set(host_value, PCMK__XA_ATTR_HOST, host);
            pcmk__xe_set(host_value, PCMK__XA_ATTR_VALUE,
                         ((v != NULL)? v->current : NULL));

        /* Otherwise, add all nodes' values */
        } else {
            GHashTableIter iter;

            g_hash_table_iter_init(&iter, a->values);
            while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &v)) {
                host_value = pcmk__xe_create(reply, PCMK_XE_NODE);
                pcmk__xe_set(host_value, PCMK__XA_ATTR_HOST, v->nodename);
                pcmk__xe_set(host_value, PCMK__XA_ATTR_VALUE, v->current);
            }
        }
    }
    return reply;
}

void
attrd_client_clear_failure(pcmk__request_t *request)
{
    xmlNode *xml = request->xml;
    const char *rsc, *op, *interval_spec;

    if (minimum_protocol_version >= 2) {
        /* Propagate to all peers (including ourselves).
         * This ends up at attrd_peer_message().
         */
        attrd_send_message(NULL, xml, false);
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
        return;
    }

    rsc = pcmk__xe_get(xml, PCMK__XA_ATTR_RESOURCE);
    op = pcmk__xe_get(xml, PCMK__XA_ATTR_CLEAR_OPERATION);
    interval_spec = pcmk__xe_get(xml, PCMK__XA_ATTR_CLEAR_INTERVAL);

    /* Map this to an update */
    pcmk__xe_set(xml, PCMK_XA_TASK, PCMK__ATTRD_CMD_UPDATE);

    /* Add regular expression matching desired attributes */

    if (rsc) {
        char *pattern;

        if (op == NULL) {
            pattern = pcmk__assert_asprintf(ATTRD_RE_CLEAR_ONE, rsc);

        } else {
            guint interval_ms = 0U;

            pcmk_parse_interval_spec(interval_spec, &interval_ms);
            pattern = pcmk__assert_asprintf(ATTRD_RE_CLEAR_OP, rsc, op,
                                            interval_ms);
        }

        pcmk__xe_set(xml, PCMK__XA_ATTR_REGEX, pattern);
        free(pattern);

    } else {
        pcmk__xe_set(xml, PCMK__XA_ATTR_REGEX, ATTRD_RE_CLEAR_ALL);
    }

    /* Make sure attribute and value are not set, so we delete via regex */
    pcmk__xe_remove_attr(xml, PCMK__XA_ATTR_NAME);
    pcmk__xe_remove_attr(xml, PCMK__XA_ATTR_VALUE);

    attrd_client_update(request);
}

void
attrd_client_peer_remove(pcmk__request_t *request)
{
    xmlNode *xml = request->xml;

    // Host and ID are not used in combination, rather host has precedence
    const char *host = pcmk__xe_get(xml, PCMK__XA_ATTR_HOST);
    char *host_alloc = NULL;

    attrd_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags);

    if (host == NULL) {
        int nodeid = 0;

        pcmk__xe_get_int(xml, PCMK__XA_ATTR_HOST_ID, &nodeid);
        if (nodeid > 0) {
            pcmk__node_status_t *node = NULL;
            char *host_alloc = NULL;

            node = pcmk__search_node_caches(nodeid, NULL, NULL,
                                            pcmk__node_search_cluster_member);
            if ((node != NULL) && (node->name != NULL)) {
                // Use cached name if available
                host = node->name;
            } else {
                // Otherwise ask cluster layer
                host_alloc = pcmk__cluster_node_name(nodeid);
                host = host_alloc;
            }
            pcmk__xe_set(xml, PCMK__XA_ATTR_HOST, host);
        }
    }

    if (host) {
        pcmk__info("Client %s is requesting all values for %s be removed",
                   pcmk__client_name(request->ipc_client), host);
        attrd_send_message(NULL, xml, false); /* ends up at attrd_peer_message() */
        free(host_alloc);
    } else {
        pcmk__info("Ignoring request by client %s to remove all peer values "
                   "without specifying peer",
                   pcmk__client_name(request->ipc_client));
    }

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
}

xmlNode *
attrd_client_query(pcmk__request_t *request)
{
    xmlNode *query = request->xml;
    xmlNode *reply = NULL;
    const char *attr = NULL;

    pcmk__debug("Query arrived from %s",
                pcmk__client_name(request->ipc_client));

    /* Request must specify attribute name to query */
    attr = pcmk__xe_get(query, PCMK__XA_ATTR_NAME);
    if (attr == NULL) {
        pcmk__format_result(&request->result, CRM_EX_ERROR, PCMK_EXEC_ERROR,
                            "Ignoring malformed query from %s (no attribute name given)",
                            pcmk__client_name(request->ipc_client));
        return NULL;
    }

    /* Build the XML reply */
    reply = build_query_reply(attr, pcmk__xe_get(query, PCMK__XA_ATTR_HOST));
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

void
attrd_client_refresh(pcmk__request_t *request)
{
    pcmk__info("Updating all attributes");

    attrd_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags);
    attrd_write_attributes(attrd_write_all|attrd_write_no_delay);

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
}

static void
handle_missing_host(xmlNode *xml)
{
    if (pcmk__xe_get(xml, PCMK__XA_ATTR_HOST) == NULL) {
        pcmk__trace("Inferring local node %s with XML ID %s",
                    attrd_cluster->priv->node_name,
                    attrd_cluster->priv->node_xml_id);
        pcmk__xe_set(xml, PCMK__XA_ATTR_HOST, attrd_cluster->priv->node_name);
        pcmk__xe_set(xml, PCMK__XA_ATTR_HOST_ID,
                     attrd_cluster->priv->node_xml_id);
    }
}

/* Convert a single IPC message with a regex into one with multiple children, one
 * for each regex match.
 */
static int
expand_regexes(xmlNode *xml, const char *attr, const char *value, const char *regex)
{
    if (attr == NULL && regex) {
        bool matched = false;
        GHashTableIter aIter;
        regex_t r_patt;

        pcmk__debug("Setting %s to %s", regex, value);
        if (regcomp(&r_patt, regex, REG_EXTENDED|REG_NOSUB)) {
            return EINVAL;
        }

        g_hash_table_iter_init(&aIter, attributes);
        while (g_hash_table_iter_next(&aIter, (gpointer *) & attr, NULL)) {
            int status = regexec(&r_patt, attr, 0, NULL, 0);

            if (status == 0) {
                xmlNode *child = pcmk__xe_create(xml, PCMK_XE_OP);

                pcmk__trace("Matched %s with %s", attr, regex);
                matched = true;

                /* Copy all the non-conflicting attributes from the parent over,
                 * but remove the regex and replace it with the name.
                 */
                pcmk__xe_copy_attrs(child, xml, pcmk__xaf_no_overwrite);
                pcmk__xe_remove_attr(child, PCMK__XA_ATTR_REGEX);
                pcmk__xe_set(child, PCMK__XA_ATTR_NAME, attr);
            }
        }

        regfree(&r_patt);

        /* Return a code if we never matched anything.  This should not be treated
         * as an error.  It indicates there was a regex, and it was a valid regex,
         * but simply did not match anything and the caller should not continue
         * doing any regex-related processing.
         */
        if (!matched) {
            return pcmk_rc_op_unsatisfied;
        }

    } else if (attr == NULL) {
        return pcmk_rc_bad_nvpair;
    }

    return pcmk_rc_ok;
}

static int
handle_regexes(pcmk__request_t *request)
{
    xmlNode *xml = request->xml;
    int rc = pcmk_rc_ok;

    const char *attr = pcmk__xe_get(xml, PCMK__XA_ATTR_NAME);
    const char *value = pcmk__xe_get(xml, PCMK__XA_ATTR_VALUE);
    const char *regex = pcmk__xe_get(xml, PCMK__XA_ATTR_REGEX);

    rc = expand_regexes(xml, attr, value, regex);

    if (rc == EINVAL) {
        pcmk__format_result(&request->result, CRM_EX_ERROR, PCMK_EXEC_ERROR,
                            "Bad regex '%s' for update from client %s", regex,
                            pcmk__client_name(request->ipc_client));

    } else if (rc == pcmk_rc_bad_nvpair) {
        pcmk__err("Update request did not specify attribute or regular "
                  "expression");
        pcmk__format_result(&request->result, CRM_EX_ERROR, PCMK_EXEC_ERROR,
                            "Client %s update request did not specify attribute or regular expression",
                            pcmk__client_name(request->ipc_client));
    }

    return rc;
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
            const char *host = pcmk__xe_get(xml, PCMK__XA_ATTR_HOST);
            v = g_hash_table_lookup(a->values, host);
        }

        int_value = attrd_expand_value(*value, (v? v->current : NULL));

        pcmk__info("Expanded %s=%s to %d", attr, *value, int_value);
        pcmk__xe_set_int(xml, PCMK__XA_ATTR_VALUE, int_value);

        /* Replacing the value frees the previous memory, so re-query it */
        *value = pcmk__xe_get(xml, PCMK__XA_ATTR_VALUE);
    }

    return pcmk_rc_ok;
}

static void
send_update_msg_to_cluster(pcmk__request_t *request, xmlNode *xml)
{
    if (pcmk__str_eq(attrd_request_sync_point(xml), PCMK__VALUE_CLUSTER, pcmk__str_none)) {
        /* The client is waiting on the cluster-wide sync point.  In this case,
         * the response ACK is not sent until this attrd broadcasts the update
         * and receives its own confirmation back from all peers.
         */
        attrd_expect_confirmations(request, attrd_cluster_sync_point_update);
        attrd_send_message(NULL, xml, true); /* ends up at attrd_peer_message() */

    } else {
        /* The client is either waiting on the local sync point or was not
         * waiting on any sync point at all.  For the local sync point, the
         * response ACK is sent in attrd_peer_update.  For clients not
         * waiting on any sync point, the response ACK is sent in
         * handle_update_request immediately before this function was called.
         */
        attrd_send_message(NULL, xml, false); /* ends up at attrd_peer_message() */
    }
}

static int
send_child_update(xmlNode *child, void *data)
{
    pcmk__request_t *request = (pcmk__request_t *) data;

    /* Calling pcmk__set_result is handled by one of these calls to
     * attrd_client_update, so no need to do it again here.
     */
    request->xml = child;
    attrd_client_update(request);
    return pcmk_rc_ok;
}

void
attrd_client_update(pcmk__request_t *request)
{
    xmlNode *xml = NULL;
    const char *attr, *value, *regex;

    CRM_CHECK((request != NULL) && (request->xml != NULL), return);

    xml = request->xml;

    /* If the message has children, that means it is a message from a newer
     * client that supports sending multiple operations at a time.  There are
     * two ways we can handle that.
     */
    if (xml->children != NULL) {
        if (ATTRD_SUPPORTS_MULTI_MESSAGE(minimum_protocol_version)) {
            /* First, if all peers support a certain protocol version, we can
             * just broadcast the big message and they'll handle it.  However,
             * we also need to apply all the transformations in this function
             * to the children since they don't happen anywhere else.
             */
            for (xmlNode *child = pcmk__xe_first_child(xml, PCMK_XE_OP, NULL,
                                                       NULL);
                 child != NULL; child = pcmk__xe_next(child, PCMK_XE_OP)) {

                attr = pcmk__xe_get(child, PCMK__XA_ATTR_NAME);
                value = pcmk__xe_get(child, PCMK__XA_ATTR_VALUE);

                handle_missing_host(child);

                if (handle_value_expansion(&value, child, request->op, attr) == EINVAL) {
                    pcmk__format_result(&request->result, CRM_EX_NOSUCH, PCMK_EXEC_ERROR,
                                        "Attribute %s does not exist", attr);
                    return;
                }
            }

            send_update_msg_to_cluster(request, xml);
            pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);

        } else {
            /* Save the original xml node pointer so it can be restored after iterating
             * over all the children.
             */
            xmlNode *orig_xml = request->xml;

            /* Second, if they do not support that protocol version, split it
             * up into individual messages and call attrd_client_update on
             * each one.
             */
            pcmk__xe_foreach_child(xml, PCMK_XE_OP, send_child_update, request);
            request->xml = orig_xml;
        }

        return;
    }

    attr = pcmk__xe_get(xml, PCMK__XA_ATTR_NAME);
    value = pcmk__xe_get(xml, PCMK__XA_ATTR_VALUE);
    regex = pcmk__xe_get(xml, PCMK__XA_ATTR_REGEX);

    if (handle_regexes(request) != pcmk_rc_ok) {
        /* Error handling was already dealt with in handle_regexes, so just return. */
        return;
    }

    if (regex != NULL) {
        /* Recursively call attrd_client_update on the new message with regexes
         * expanded.  If supported by the attribute daemon, this means that all
         * matches can also be handled atomically.
         */
        attrd_client_update(request);
        return;
    }

    handle_missing_host(xml);

    if (handle_value_expansion(&value, xml, request->op, attr) == EINVAL) {
        pcmk__format_result(&request->result, CRM_EX_NOSUCH, PCMK_EXEC_ERROR,
                            "Attribute %s does not exist", attr);
        return;
    }

    pcmk__debug("Broadcasting %s[%s]=%s%s", attr,
                pcmk__xe_get(xml, PCMK__XA_ATTR_HOST), value,
                (attrd_election_won()? " (writer)" : ""));

    send_update_msg_to_cluster(request, xml);
    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
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
    pcmk__trace("New client connection %p", c);
    if (attrd_shutting_down()) {
        pcmk__info("Ignoring new connection from pid %d during shutdown",
                   pcmk__client_pid(c));
        return -ECONNREFUSED;
    }

    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -ENOMEM;
    }
    return pcmk_ok;
}

/*!
 * \internal
 * \brief Destroy a client IPC connection
 *
 * \param[in] c  Connection to destroy
 *
 * \return 0 (do not re-run this callback)
 */
static int32_t
attrd_ipc_closed(qb_ipcs_connection_t *c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        pcmk__trace("Ignoring request to clean up unknown connection %p", c);
    } else {
        pcmk__trace("Cleaning up closed client connection %p", c);

        /* Remove the client from the sync point waitlist if it's present. */
        attrd_remove_client_from_waitlist(client);

        /* And no longer wait for confirmations from any peers. */
        attrd_do_not_wait_for_client(client);

        pcmk__free_client(client);
    }

    return 0;
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
    pcmk__trace("Destroying client connection %p", c);
    attrd_ipc_closed(c);
}

static int32_t
attrd_ipc_dispatch(qb_ipcs_connection_t * c, void *data, size_t size)
{
    int rc = pcmk_rc_ok;
    uint32_t id = 0;
    uint32_t flags = 0;
    pcmk__client_t *client = pcmk__find_client(c);
    xmlNode *xml = NULL;

    // Sanity-check, and parse XML from IPC data
    CRM_CHECK(client != NULL, return 0);
    if (data == NULL) {
        pcmk__debug("No IPC data from PID %d", pcmk__client_pid(c));
        return 0;
    }

    rc = pcmk__ipc_msg_append(&client->buffer, data);

    if (rc == pcmk_rc_ipc_more) {
        /* We haven't read the complete message yet, so just return. */
        return 0;

    } else if (rc == pcmk_rc_ok) {
        /* We've read the complete message and there's already a header on
         * the front.  Pass it off for processing.
         */
        xml = pcmk__client_data2xml(client, &id, &flags);
        g_byte_array_free(client->buffer, TRUE);
        client->buffer = NULL;

    } else {
        /* Some sort of error occurred reassembling the message.  All we can
         * do is clean up, log an error and return.
         */
        pcmk__err("Error when reading IPC message: %s", pcmk_rc_str(rc));

        if (client->buffer != NULL) {
            g_byte_array_free(client->buffer, TRUE);
            client->buffer = NULL;
        }

        return 0;
    }

    if (xml == NULL) {
        pcmk__debug("Unrecognizable IPC data from PID %d", pcmk__client_pid(c));
        pcmk__ipc_send_ack(client, id, flags, NULL, CRM_EX_PROTOCOL);
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

        pcmk__assert(client->user != NULL);
        pcmk__update_acl_user(xml, PCMK__XA_ATTR_USER, client->user);

        request.op = pcmk__xe_get_copy(request.xml, PCMK_XA_TASK);
        CRM_CHECK(request.op != NULL, goto done);

        attrd_handle_request(&request);
    }

done:
    pcmk__xml_free(xml);
    return 0;
}

static struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = attrd_ipc_accept,
    .connection_created = NULL,
    .msg_process = attrd_ipc_dispatch,
    .connection_closed = attrd_ipc_closed,
    .connection_destroyed = attrd_ipc_destroy
};

/*!
 * \internal
 * \brief Clean up attrd IPC communication
 */
void
attrd_ipc_cleanup(void)
{
    if (ipcs != NULL) {
        pcmk__drop_all_clients(ipcs);
        g_clear_pointer(&ipcs, qb_ipcs_destroy);
    }

    pcmk__client_cleanup();
}

/*!
 * \internal
 * \brief Set up attrd IPC communication
 */
void
attrd_ipc_init(void)
{
    pcmk__serve_attrd_ipc(&ipcs, &ipc_callbacks);
}
