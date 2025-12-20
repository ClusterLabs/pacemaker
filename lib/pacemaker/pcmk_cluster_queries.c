/*
 * Copyright 2020-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <libxml/tree.h>        // xmlNode

#include <pacemaker.h>
#include <pacemaker-internal.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/common/xml.h>
#include <crm/common/iso8601.h>
#include <crm/common/ipc_controld.h>
#include <crm/common/ipc_pacemakerd.h>

//! Object to store node info from the controller API
typedef struct {
    /* Adapted from pcmk_controld_api_reply_t:data:node_info.
     * (char **) are convenient here for use within callbacks: we can skip
     * copying strings unless the caller passes a non-NULL value.
     */
    uint32_t id;
    char **node_name;
    char **uuid;
    char **state;
    bool have_quorum;
    bool is_remote;
} node_info_t;

//! Object to store API results, a timeout, and an output object
typedef struct {
    pcmk__output_t *out;
    bool show_output;
    int rc;
    unsigned int message_timeout_ms;
    enum pcmk_pacemakerd_state pcmkd_state;
    node_info_t node_info;
} data_t;

/*!
 * \internal
 * \brief Validate that an IPC API event is a good reply
 *
 * \param[in,out] data        API results and options
 * \param[in]     api         IPC API connection
 * \param[in]     event_type  Type of event that occurred
 * \param[in]     status      Event status
 *
 * \return Standard Pacemaker return code
 */
static int
validate_reply_event(data_t *data, const pcmk_ipc_api_t *api,
                     enum pcmk_ipc_event event_type, crm_exit_t status)
{
    pcmk__output_t *out = data->out;

    switch (event_type) {
        case pcmk_ipc_event_reply:
            break;

        case pcmk_ipc_event_disconnect:
            if (data->rc == ECONNRESET) { // Unexpected
                out->err(out, "error: Lost connection to %s",
                         pcmk_ipc_name(api, true));
            }
            // Nothing bad but not the reply we're looking for
            return ENOTSUP;

        default:
            // Ditto
            return ENOTSUP;
    }

    if (status != CRM_EX_OK) {
        out->err(out, "error: Bad reply from %s: %s",
                 pcmk_ipc_name(api, true), crm_exit_str(status));
        data->rc = EBADMSG;
        return data->rc;
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Validate that a controller API event is a good reply of expected type
 *
 * \param[in,out] data           API results and options
 * \param[in]     api            Controller connection
 * \param[in]     event_type     Type of event that occurred
 * \param[in]     status         Event status
 * \param[in]     event_data     Event-specific data
 * \param[in]     expected_type  Expected reply type
 *
 * \return Standard Pacemaker return code
 */
static int
validate_controld_reply(data_t *data, const pcmk_ipc_api_t *api,
                        enum pcmk_ipc_event event_type, crm_exit_t status,
                        const void *event_data,
                        enum pcmk_controld_api_reply expected_type)
{
    pcmk__output_t *out = data->out;
    int rc = pcmk_rc_ok;
    const pcmk_controld_api_reply_t *reply = NULL;

    rc = validate_reply_event(data, api, event_type, status);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    reply = (const pcmk_controld_api_reply_t *) event_data;

    if (reply->reply_type != expected_type) {
        out->err(out, "error: Unexpected reply type '%s' from controller",
                 pcmk__controld_api_reply2str(reply->reply_type));
        data->rc = EBADMSG;
        return data->rc;
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Validate that a \p pacemakerd API event is a good reply of expected
 *        type
 *
 * \param[in,out] data           API results and options
 * \param[in]     api            \p pacemakerd connection
 * \param[in]     event_type     Type of event that occurred
 * \param[in]     status         Event status
 * \param[in]     event_data     Event-specific data
 * \param[in]     expected_type  Expected reply type
 *
 * \return Standard Pacemaker return code
 */
static int
validate_pcmkd_reply(data_t *data, const pcmk_ipc_api_t *api,
                     enum pcmk_ipc_event event_type, crm_exit_t status,
                     const void *event_data,
                     enum pcmk_pacemakerd_api_reply expected_type)
{
    pcmk__output_t *out = data->out;
    const pcmk_pacemakerd_api_reply_t *reply = NULL;
    int rc = validate_reply_event(data, api, event_type, status);

    if (rc != pcmk_rc_ok) {
        return rc;
    }

    reply = (const pcmk_pacemakerd_api_reply_t *) event_data;

    if (reply->reply_type != expected_type) {
        out->err(out, "error: Unexpected reply type '%s' from pacemakerd",
                 pcmk__pcmkd_api_reply2str(reply->reply_type));
        data->rc = EBADMSG;
        return data->rc;
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Process a controller status IPC event
 *
 * \param[in,out] controld_api  Controller connection
 * \param[in]     event_type    Type of event that occurred
 * \param[in]     status        Event status
 * \param[in,out] event_data    \p pcmk_controld_api_reply_t object containing
 *                              event-specific data
 * \param[in,out] user_data     \p data_t object for API results and options
 */
static void
controller_status_event_cb(pcmk_ipc_api_t *controld_api,
                           enum pcmk_ipc_event event_type, crm_exit_t status,
                           void *event_data, void *user_data)
{
    data_t *data = (data_t *) user_data;
    pcmk__output_t *out = data->out;
    const pcmk_controld_api_reply_t *reply = NULL;

    int rc = validate_controld_reply(data, controld_api, event_type, status,
                                     event_data, pcmk_controld_reply_ping);

    if (rc != pcmk_rc_ok) {
        return;
    }

    reply = (const pcmk_controld_api_reply_t *) event_data;
    out->message(out, "health",
                 reply->data.ping.sys_from, reply->host_from,
                 reply->data.ping.fsa_state, reply->data.ping.result);
    data->rc = pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Process a designated controller IPC event
 *
 * \param[in,out] controld_api  Controller connection
 * \param[in]     event_type    Type of event that occurred
 * \param[in]     status        Event status
 * \param[in,out] event_data    \p pcmk_controld_api_reply_t object containing
 *                              event-specific data
 * \param[in,out] user_data     \p data_t object for API results and options
 */
static void
designated_controller_event_cb(pcmk_ipc_api_t *controld_api,
                               enum pcmk_ipc_event event_type,
                               crm_exit_t status, void *event_data,
                               void *user_data)
{
    data_t *data = (data_t *) user_data;
    pcmk__output_t *out = data->out;
    const pcmk_controld_api_reply_t *reply = NULL;

    int rc = validate_controld_reply(data, controld_api, event_type, status,
                                     event_data, pcmk_controld_reply_ping);

    if (rc != pcmk_rc_ok) {
        return;
    }

    reply = (const pcmk_controld_api_reply_t *) event_data;
    out->message(out, "dc", reply->host_from);
    data->rc = reply->host_from ? pcmk_rc_ok : pcmk_rc_no_dc;
}

/*!
 * \internal
 * \brief Process a node info IPC event
 *
 * \param[in,out] controld_api  Controller connection
 * \param[in]     event_type    Type of event that occurred
 * \param[in]     status        Event status
 * \param[in,out] event_data    \p pcmk_controld_api_reply_t object containing
 *                              event-specific data
 * \param[in,out] user_data     \p data_t object for API results and options
 */
static void
node_info_event_cb(pcmk_ipc_api_t *controld_api, enum pcmk_ipc_event event_type,
                   crm_exit_t status, void *event_data, void *user_data)
{
    data_t *data = (data_t *) user_data;
    pcmk__output_t *out = data->out;

    const pcmk_controld_api_reply_t *reply = NULL;

    int rc = validate_controld_reply(data, controld_api, event_type, status,
                                     event_data, pcmk_controld_reply_info);

    if (rc != pcmk_rc_ok) {
        return;
    }

    reply = (const pcmk_controld_api_reply_t *) event_data;

    if (reply->data.node_info.uname == NULL) {
        out->err(out, "Node is not known to cluster");
        data->rc = pcmk_rc_node_unknown;
        return;
    }

    data->node_info.have_quorum = reply->data.node_info.have_quorum;
    data->node_info.is_remote = reply->data.node_info.is_remote;
    data->node_info.id = (uint32_t) reply->data.node_info.id;

    pcmk__str_update(data->node_info.node_name, reply->data.node_info.uname);
    pcmk__str_update(data->node_info.uuid, reply->data.node_info.uuid);
    pcmk__str_update(data->node_info.state, reply->data.node_info.state);

    if (data->show_output) {
        out->message(out, "node-info",
                     (uint32_t) reply->data.node_info.id, reply->data.node_info.uname,
                     reply->data.node_info.uuid, reply->data.node_info.state,
                     reply->data.node_info.have_quorum,
                     reply->data.node_info.is_remote);
    }

    data->rc = pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Process a \p pacemakerd status IPC event
 *
 * \param[in,out] pacemakerd_api  \p pacemakerd connection
 * \param[in]     event_type      Type of event that occurred
 * \param[in]     status          Event status
 * \param[in,out] event_data      \p pcmk_pacemakerd_api_reply_t object
 *                                containing event-specific data
 * \param[in,out] user_data       \p data_t object for API results and options
 */
static void
pacemakerd_event_cb(pcmk_ipc_api_t *pacemakerd_api,
                    enum pcmk_ipc_event event_type, crm_exit_t status,
                    void *event_data, void *user_data)
{
    data_t *data = user_data;
    pcmk__output_t *out = data->out;
    const pcmk_pacemakerd_api_reply_t *reply = NULL;

    int rc = validate_pcmkd_reply(data, pacemakerd_api, event_type, status,
                                  event_data, pcmk_pacemakerd_reply_ping);

    if (rc != pcmk_rc_ok) {
        return;
    }

    // Parse desired information from reply
    reply = (const pcmk_pacemakerd_api_reply_t *) event_data;

    data->pcmkd_state = reply->data.ping.state;
    data->rc = pcmk_rc_ok;

    if (!data->show_output) {
        return;
    }

    if (reply->data.ping.status == pcmk_rc_ok) {
        out->message(out, "pacemakerd-health",
                     reply->data.ping.sys_from, reply->data.ping.state, NULL,
                     reply->data.ping.last_good);
    } else {
        out->message(out, "pacemakerd-health",
                     reply->data.ping.sys_from, reply->data.ping.state,
                     "query failed", time(NULL));
    }
}

static pcmk_ipc_api_t *
ipc_connect(data_t *data, enum pcmk_ipc_server server, pcmk_ipc_callback_t cb,
            enum pcmk_ipc_dispatch dispatch_type, bool eremoteio_ok)
{
    int rc;
    pcmk__output_t *out = data->out;
    pcmk_ipc_api_t *api = NULL;

    rc = pcmk_new_ipc_api(&api, server);
    if (api == NULL) {
        out->err(out, "error: Could not connect to %s: %s",
                pcmk_ipc_name(api, true),
                pcmk_rc_str(rc));
        data->rc = rc;
        return NULL;
    }
    if (cb != NULL) {
        pcmk_register_ipc_callback(api, cb, data);
    }

    rc = pcmk__connect_ipc(api, dispatch_type, 5);
    if (rc != pcmk_rc_ok) {
        if (rc == EREMOTEIO) {
            data->pcmkd_state = pcmk_pacemakerd_state_remote;
            if (eremoteio_ok) {
                /* EREMOTEIO may be expected and acceptable for some callers
                 * on a Pacemaker Remote node
                 */
                pcmk__debug("Ignoring %s connection failure: No Pacemaker "
                            "Remote connection",
                            pcmk_ipc_name(api, true));
                rc = pcmk_rc_ok;
            } else {
                out->err(out, "error: Could not connect to %s: %s",
                         pcmk_ipc_name(api, true), pcmk_rc_str(rc));
            }
        }
        data->rc = rc;
        pcmk_free_ipc_api(api);
        return NULL;
    }

    return api;
}

/*!
 * \internal
 * \brief Poll an IPC API connection until timeout or a reply is received
 *
 * \param[in,out] data     API results and options
 * \param[in,out] api      IPC API connection
 * \param[in]     on_node  If not \p NULL, name of the node to poll (used only
 *                         for logging)
 *
 * \note Sets the \p rc member of \p data on error
 */
static void
poll_until_reply(data_t *data, pcmk_ipc_api_t *api, const char *on_node)
{
    pcmk__output_t *out = data->out;

    uint64_t start_nsec = qb_util_nano_current_get();
    uint64_t end_nsec = 0;
    uint64_t elapsed_ms = 0;
    uint64_t remaining_ms = data->message_timeout_ms;

    while (remaining_ms > 0) {
        int rc = pcmk_poll_ipc(api, remaining_ms);

        if (rc == EAGAIN) {
            // Poll timed out
            break;
        }

        if (rc != pcmk_rc_ok) {
            out->err(out, "error: Failed to poll %s API%s%s: %s",
                     pcmk_ipc_name(api, true), (on_node != NULL)? " on " : "",
                     pcmk__s(on_node, ""), pcmk_rc_str(rc));
            data->rc = rc;
            return;
        }

        pcmk_dispatch_ipc(api);

        if (data->rc != EAGAIN) {
            // Received a reply
            return;
        }
        end_nsec = qb_util_nano_current_get();
        elapsed_ms = (end_nsec - start_nsec) / QB_TIME_NS_IN_MSEC;
        remaining_ms = data->message_timeout_ms - elapsed_ms;
    }

    out->err(out,
             "error: Timed out after %ums waiting for reply from %s API%s%s",
             data->message_timeout_ms, pcmk_ipc_name(api, true),
             (on_node != NULL)? " on " : "", pcmk__s(on_node, ""));
    data->rc = EAGAIN;
}

/*!
 * \internal
 * \brief Get and output controller status
 *
 * \param[in,out] out                 Output object
 * \param[in]     node_name           Name of node whose status is desired
 *                                    (\p NULL for DC)
 * \param[in]     message_timeout_ms  How long to wait for a reply from the
 *                                    the controller API. If 0,
 *                                    \p pcmk_ipc_dispatch_sync will be used.
 *                                    Otherwise, \p pcmk_ipc_dispatch_poll will
 *                                    be used.
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__controller_status(pcmk__output_t *out, const char *node_name,
                        unsigned int message_timeout_ms)
{
    data_t data = {
        .out = out,
        .rc = EAGAIN,
        .message_timeout_ms = message_timeout_ms,
    };
    enum pcmk_ipc_dispatch dispatch_type = pcmk_ipc_dispatch_poll;
    pcmk_ipc_api_t *controld_api = NULL;

    if (message_timeout_ms == 0) {
        dispatch_type = pcmk_ipc_dispatch_sync;
    }
    controld_api = ipc_connect(&data, pcmk_ipc_controld,
                               controller_status_event_cb, dispatch_type,
                               false);

    if (controld_api != NULL) {
        int rc = pcmk_controld_api_ping(controld_api, node_name);
        if (rc != pcmk_rc_ok) {
            out->err(out, "error: Could not ping controller API on %s: %s",
                     pcmk__s(node_name, "DC"), pcmk_rc_str(rc));
            data.rc = rc;
        }

        if (dispatch_type == pcmk_ipc_dispatch_poll) {
            poll_until_reply(&data, controld_api, pcmk__s(node_name, "DC"));
        }
        pcmk_free_ipc_api(controld_api);
    }

    return data.rc;
}


// Documented in header
int
pcmk_controller_status(xmlNodePtr *xml, const char *node_name,
                       unsigned int message_timeout_ms)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    pcmk__register_lib_messages(out);

    rc = pcmk__controller_status(out, node_name, message_timeout_ms);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    return rc;
}

/*!
 * \internal
 * \brief Get and output designated controller node name
 *
 * \param[in,out] out                 Output object
 * \param[in]     message_timeout_ms  How long to wait for a reply from the
 *                                    the controller API. If 0,
 *                                    \p pcmk_ipc_dispatch_sync will be used.
 *                                    Otherwise, \p pcmk_ipc_dispatch_poll will
 *                                    be used.
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__designated_controller(pcmk__output_t *out,
                            unsigned int message_timeout_ms)
{
    data_t data = {
        .out = out,
        .rc = EAGAIN,
        .message_timeout_ms = message_timeout_ms,
    };
    enum pcmk_ipc_dispatch dispatch_type = pcmk_ipc_dispatch_poll;
    pcmk_ipc_api_t *controld_api = NULL;

    if (message_timeout_ms == 0) {
        dispatch_type = pcmk_ipc_dispatch_sync;
    }
    controld_api = ipc_connect(&data, pcmk_ipc_controld,
                               designated_controller_event_cb, dispatch_type,
                               false);

    if (controld_api != NULL) {
        int rc = pcmk_controld_api_ping(controld_api, NULL);
        if (rc != pcmk_rc_ok) {
            out->err(out, "error: Could not ping controller API on DC: %s",
                     pcmk_rc_str(rc));
            data.rc = rc;
        }

        if (dispatch_type == pcmk_ipc_dispatch_poll) {
            poll_until_reply(&data, controld_api, "DC");
        }
        pcmk_free_ipc_api(controld_api);
    }

    return data.rc;
}

// Documented in header
int
pcmk_designated_controller(xmlNodePtr *xml, unsigned int message_timeout_ms)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    pcmk__register_lib_messages(out);

    rc = pcmk__designated_controller(out, message_timeout_ms);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    return rc;
}

/*!
 * \internal
 * \brief Get and optionally output node info corresponding to a node ID from
 *        the controller
 *
 * \param[in,out] out                 Output object
 * \param[in,out] node_id             ID of node whose info to get. If \p NULL
 *                                    or 0, get the local node's info. If not
 *                                    \c NULL, store the true node ID here on
 *                                    success.
 * \param[out]    node_name           If not \c NULL, where to store the node
 *                                    name
 * \param[out]    uuid                If not \c NULL, where to store the node
 *                                    UUID
 * \param[out]    state               If not \c NULL, where to store the
 *                                    membership state
 * \param[out]    is_remote           If not \c NULL, where to store whether the
 *                                    node is a Pacemaker Remote node
 * \param[out]    have_quorum         If not \c NULL, where to store whether the
 *                                    node has quorum
 * \param[in]     show_output         Whether to show the node info
 * \param[in]     message_timeout_ms  How long to wait for a reply from the
 *                                    the controller API. If 0,
 *                                    \c pcmk_ipc_dispatch_sync will be used.
 *                                    Otherwise, \c pcmk_ipc_dispatch_poll will
 *                                    be used.
 *
 * \return Standard Pacemaker return code
 *
 * \note The caller is responsible for freeing \p *node_name, \p *uuid, and
 *       \p *state using \p free().
 */
int
pcmk__query_node_info(pcmk__output_t *out, uint32_t *node_id, char **node_name,
                      char **uuid, char **state, bool *have_quorum,
                      bool *is_remote, bool show_output,
                      unsigned int message_timeout_ms)
{
    data_t data = {
        .out = out,
        .show_output = show_output,
        .rc = EAGAIN,
        .message_timeout_ms = message_timeout_ms,
        .node_info = {
            .id = (node_id == NULL)? 0 : *node_id,
            .node_name = node_name,
            .uuid = uuid,
            .state = state,
        },
    };
    enum pcmk_ipc_dispatch dispatch_type = pcmk_ipc_dispatch_poll;
    pcmk_ipc_api_t *controld_api = NULL;

    if (node_name != NULL) {
        *node_name = NULL;
    }
    if (uuid != NULL) {
        *uuid = NULL;
    }
    if (state != NULL) {
        *state = NULL;
    }

    if (message_timeout_ms == 0) {
        dispatch_type = pcmk_ipc_dispatch_sync;
    }
    controld_api = ipc_connect(&data, pcmk_ipc_controld, node_info_event_cb,
                               dispatch_type, false);

    if (controld_api != NULL) {
        int rc = pcmk_controld_api_node_info(controld_api,
                                             (node_id != NULL)? *node_id : 0);

        if (rc != pcmk_rc_ok) {
            out->err(out,
                     "error: Could not send request to controller API on local "
                     "node: %s", pcmk_rc_str(rc));
            data.rc = rc;
        }

        if (dispatch_type == pcmk_ipc_dispatch_poll) {
            poll_until_reply(&data, controld_api, "local node");
        }
        pcmk_free_ipc_api(controld_api);
    }

    if (data.rc != pcmk_rc_ok) {
        return data.rc;
    }

    // String outputs are set in callback
    if (node_id != NULL) {
        *node_id = data.node_info.id;
    }
    if (have_quorum != NULL) {
        *have_quorum = data.node_info.have_quorum;
    }
    if (is_remote != NULL) {
        *is_remote = data.node_info.is_remote;
    }

    return data.rc;
}

// Documented in header
int
pcmk_query_node_info(xmlNodePtr *xml, uint32_t *node_id, char **node_name,
                     char **uuid, char **state, bool *have_quorum,
                     bool *is_remote, bool show_output,
                     unsigned int message_timeout_ms)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    pcmk__assert(node_name != NULL);

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    pcmk__register_lib_messages(out);

    rc = pcmk__query_node_info(out, node_id, node_name, uuid, state,
                               have_quorum, is_remote, show_output,
                               message_timeout_ms);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    return rc;
}

/*!
 * \internal
 * \brief Get and optionally output \p pacemakerd status
 *
 * \param[in,out] out                 Output object
 * \param[in]     ipc_name            IPC name for request
 * \param[in]     message_timeout_ms  How long to wait for a reply from the
 *                                    \p pacemakerd API. If 0,
 *                                    \p pcmk_ipc_dispatch_sync will be used.
 *                                    Otherwise, \p pcmk_ipc_dispatch_poll will
 *                                    be used.
 * \param[in]     show_output         Whether to output the \p pacemakerd state
 * \param[out]    state               Where to store the \p pacemakerd state, if
 *                                    not \p NULL
 *
 * \return Standard Pacemaker return code
 *
 * \note This function sets \p state to \p pcmk_pacemakerd_state_remote and
 *       returns \p pcmk_rc_ok if the IPC connection attempt returns
 *       \p EREMOTEIO. That code indicates that this is a Pacemaker Remote node
 *       with the remote executor running. The node may be connected to the
 *       cluster.
 */
int
pcmk__pacemakerd_status(pcmk__output_t *out, const char *ipc_name,
                        unsigned int message_timeout_ms, bool show_output,
                        enum pcmk_pacemakerd_state *state)
{
    data_t data = {
        .out = out,
        .show_output = show_output,
        .rc = EAGAIN,
        .message_timeout_ms = message_timeout_ms,
        .pcmkd_state = pcmk_pacemakerd_state_invalid,
    };
    enum pcmk_ipc_dispatch dispatch_type = pcmk_ipc_dispatch_poll;
    pcmk_ipc_api_t *pacemakerd_api = NULL;

    if (message_timeout_ms == 0) {
        dispatch_type = pcmk_ipc_dispatch_sync;
    }
    pacemakerd_api = ipc_connect(&data, pcmk_ipc_pacemakerd,
                                 pacemakerd_event_cb, dispatch_type, true);

    if (pacemakerd_api != NULL) {
        int rc = pcmk_pacemakerd_api_ping(pacemakerd_api, ipc_name);
        if (rc != pcmk_rc_ok) {
            out->err(out, "error: Could not ping launcher API: %s",
                     pcmk_rc_str(rc));
            data.rc = rc;
        }

        if (dispatch_type == pcmk_ipc_dispatch_poll) {
            poll_until_reply(&data, pacemakerd_api, NULL);
        }
        pcmk_free_ipc_api(pacemakerd_api);

    } else if ((data.pcmkd_state == pcmk_pacemakerd_state_remote)
               && show_output) {
        // No API connection so the callback wasn't run
        out->message(out, "pacemakerd-health",
                     NULL, data.pcmkd_state, NULL, time(NULL));
    }

    if (state != NULL) {
        *state = data.pcmkd_state;
    }
    return data.rc;
}

// Documented in header
int
pcmk_pacemakerd_status(xmlNodePtr *xml, const char *ipc_name,
                       unsigned int message_timeout_ms)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    pcmk__register_lib_messages(out);

    rc = pcmk__pacemakerd_status(out, ipc_name, message_timeout_ms, true, NULL);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    return rc;
}

/* user data for looping through remote node xpath searches */
struct node_data {
    pcmk__output_t *out;
    bool found;
    const char *field;  /* XML attribute to check for node name */
    const char *type;
    bool bash_export;
};

static void
remote_node_print_helper(xmlNode *result, void *user_data)
{
    struct node_data *data = user_data;
    pcmk__output_t *out = data->out;
    const char *name = pcmk__xe_get(result, PCMK_XA_UNAME);
    const char *id = pcmk__xe_get(result, data->field);

    // node name and node id are the same for remote/guest nodes
    out->message(out, "crmadmin-node", data->type,
                 pcmk__s(name, id), id, data->bash_export);
    data->found = true;
}

/*!
 * \internal
 * \brief Output list of nodes from the CIB
 *
 * \param[in,out] out          Output object
 * \param[in]     types        Comma-separated list of node types to return.
 *                             Valid types: \c "all", \c "cluster", \c "guest",
 *                             \c "remote". A value of \c NULL is equivalent to
 *                             \c "all".
 * \param[in]     bash_export  If \c true, output a list of shell commands of
 *                             the form <tt>export NODE_NAME=UUID</tt>, if the
 *                             output format supports this
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__list_nodes(pcmk__output_t *out, const char *types, bool bash_export)
{
    struct node_data data = {
        .out = out,
        .found = false,
        .bash_export = bash_export
    };

    gchar **node_types = NULL;
    bool all = false;
    xmlNode *xml_node = NULL;
    int rc = cib__signon_query(out, NULL, &xml_node);

    if (rc != pcmk_rc_ok) {
        return rc;
    }

    /* PCMK_XE_NODES acts as the list's element name for CLI tools that use
     * pcmk__output_enable_list_element(). Otherwise, PCMK_XE_NODES is the value
     * of the list's PCMK_XA_NAME attribute.
     */
    out->begin_list(out, NULL, NULL, PCMK_XE_NODES);

    all = pcmk__str_empty(types);
    if (!all) {
        node_types = g_strsplit(types, ",", 0);
        all = pcmk__g_strv_contains((const gchar *const *) node_types, "all");
    }

    if (all
        || pcmk__g_strv_contains((const gchar *const *) node_types,
                                 "cluster")) {
        data.field = PCMK_XA_ID;
        data.type = "cluster";
        pcmk__xpath_foreach_result(xml_node->doc, PCMK__XP_MEMBER_NODE_CONFIG,
                                   remote_node_print_helper, &data);
    }

    if (all
        || pcmk__g_strv_contains((const gchar *const *) node_types, "guest")) {
        data.field = PCMK_XA_VALUE;
        data.type = "guest";
        pcmk__xpath_foreach_result(xml_node->doc, PCMK__XP_GUEST_NODE_CONFIG,
                                   remote_node_print_helper, &data);
    }

    if (all
        || pcmk__g_strv_contains((const gchar *const *) node_types, "remote")) {
        data.field = PCMK_XA_ID;
        data.type = "remote";
        pcmk__xpath_foreach_result(xml_node->doc, PCMK__XP_REMOTE_NODE_CONFIG,
                                   remote_node_print_helper, &data);
    }

    out->end_list(out);

    if (!data.found) {
        out->info(out, "No nodes configured");
    }

    g_strfreev(node_types);
    pcmk__xml_free(xml_node);
    return pcmk_rc_ok;
}

int
pcmk_list_nodes(xmlNode **xml, const char *types)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    pcmk__register_lib_messages(out);

    rc = pcmk__list_nodes(out, types, false);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    return rc;
}
