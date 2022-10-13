/*
 * Copyright 2020-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>               // gboolean, GMainLoop, etc.
#include <libxml/tree.h>        // xmlNode

#include <pacemaker.h>
#include <pacemaker-internal.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>
#include <crm/common/output_internal.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include <crm/common/iso8601.h>
#include <crm/common/ipc_controld.h>
#include <crm/common/ipc_pacemakerd.h>

//! Object to store API results, a timeout, and an output object
typedef struct {
    pcmk__output_t *out;
    int rc;
    bool reply_received;
    unsigned int message_timeout_ms;
    enum pcmk_pacemakerd_state pcmkd_state;
} data_t;

/*!
 * \internal
 * \brief Validate a reply event from an IPC API
 *
 * \param[in,out] data        API results and options
 * \param[in]     api         IPC API connection
 * \param[in]     event_type  Type of event that occurred
 * \param[in]     status      Event status
 * \param[in]     event_data  \p pcmk_controld_api_reply_t object containing
 *                            event-specific data
 * \param[in]     server      Which Pacemaker daemon \p api is connected to
 *
 * \return Standard Pacemaker return code
 */
static int
validate_reply_event(data_t *data, const pcmk_ipc_api_t *api,
                     enum pcmk_ipc_event event_type, crm_exit_t status,
                     const void *event_data, enum pcmk_ipc_server server)
{
    pcmk__output_t *out = data->out;
    bool valid_reply = false;
    int reply_type = -1;

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

    switch (server) {
        case pcmk_ipc_controld:
            {
                const pcmk_controld_api_reply_t *reply = NULL;

                reply = (const pcmk_controld_api_reply_t *) event_data;
                valid_reply = (reply->reply_type == pcmk_controld_reply_ping);
                reply_type = (int) reply->reply_type;
            }
            break;
        case pcmk_ipc_pacemakerd:
            {
                const pcmk_pacemakerd_api_reply_t *reply = NULL;

                reply = (const pcmk_pacemakerd_api_reply_t *) event_data;
                valid_reply = (reply->reply_type == pcmk_pacemakerd_reply_ping);
                reply_type = (int) reply->reply_type;
            }
            break;
        default:
            out->err(out, "error: Unsupported IPC server type %s",
                     pcmk_ipc_name(api, true));
            data->rc = EINVAL;
            return data->rc;
    }

    if (!valid_reply) {
        out->err(out, "error: Unknown reply type %d from %s",
                 reply_type, pcmk_ipc_name(api, true));
        data->rc = EBADMSG;
        return data->rc;
    }

    data->reply_received = true;
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
    pcmk_controld_api_reply_t *reply = (pcmk_controld_api_reply_t *) event_data;

    int rc = validate_reply_event(data, controld_api, event_type, status,
                                  event_data, pcmk_ipc_controld);

    if (rc == pcmk_rc_ok) {
        out->message(out, "health",
                     reply->data.ping.sys_from, reply->host_from,
                     reply->data.ping.fsa_state, reply->data.ping.result);
        data->rc = pcmk_rc_ok;
    }
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
    pcmk_controld_api_reply_t *reply = (pcmk_controld_api_reply_t *) event_data;

    int rc = validate_reply_event(data, controld_api, event_type, status,
                                  event_data, pcmk_ipc_controld);

    if (rc == pcmk_rc_ok) {
        out->message(out, "dc", reply->host_from);
        data->rc = pcmk_rc_ok;
    }
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
    pcmk_pacemakerd_api_reply_t *reply =
        (pcmk_pacemakerd_api_reply_t *) event_data;

    int rc = validate_reply_event(data, pacemakerd_api, event_type, status,
                                  event_data, pcmk_ipc_pacemakerd);

    if (rc != pcmk_rc_ok) {
        return;
    }

    // Parse desired information from reply
    data->pcmkd_state = reply->data.ping.state;
    if (reply->data.ping.status == pcmk_rc_ok) {
        crm_time_t *when = crm_time_new(NULL);
        char *when_s = NULL;

        crm_time_set_timet(when, &reply->data.ping.last_good);
        when_s = crm_time_as_string(when,
                                    crm_time_log_date
                                    |crm_time_log_timeofday
                                    |crm_time_log_with_timezone);

        out->message(out, "pacemakerd-health",
                     reply->data.ping.sys_from, reply->data.ping.state, NULL,
                     when_s);

        crm_time_free(when);
        free(when_s);

    } else {
        out->message(out, "pacemakerd-health",
                     reply->data.ping.sys_from, reply->data.ping.state,
                     "query failed", NULL);
    }
    data->rc = pcmk_rc_ok;
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

    rc = pcmk_connect_ipc(api, dispatch_type);
    if (rc != pcmk_rc_ok) {
        if ((rc == EREMOTEIO) && eremoteio_ok) {
            /* EREMOTEIO may be expected and acceptable for some callers.
             * Preserve the return code in case callers need to handle it
             * specially.
             */
        } else {
            out->err(out, "error: Could not connect to %s: %s",
                     pcmk_ipc_name(api, true), pcmk_rc_str(rc));
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
    uint64_t end_nsec = start_nsec;
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

        if (data->reply_received) {
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
 *                                    \p pacemaker-controld API. If 0,
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
        .rc = pcmk_rc_ok,
        .reply_received = false,
        .message_timeout_ms = message_timeout_ms,
        .pcmkd_state = pcmk_pacemakerd_state_invalid,
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
    pcmk__xml_output_finish(out, xml);
    return rc;
}

/*!
 * \internal
 * \brief Get and output designated controller node name
 *
 * \param[in,out] out                 Output object
 * \param[in]     message_timeout_ms  How long to wait for a reply from the
 *                                    \p pacemaker-controld API. If 0,
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
        .rc = pcmk_rc_ok,
        .reply_received = false,
        .message_timeout_ms = message_timeout_ms,
        .pcmkd_state = pcmk_pacemakerd_state_invalid,
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
    pcmk__xml_output_finish(out, xml);
    return rc;
}

/*!
 * \internal
 * \brief Get and output \p pacemakerd status
 *
 * \param[in,out] out                 Output object
 * \param[in]     ipc_name            IPC name for request
 * \param[in]     message_timeout_ms  How long to wait for a reply from the
 *                                    \p pacemakerd API. If 0,
 *                                    \p pcmk_ipc_dispatch_sync will be used.
 *                                    Otherwise, \p pcmk_ipc_dispatch_poll will
 *                                    be used.
 * \param[out]    state               Where to store the \p pacemakerd state, if
 *                                    not \p NULL
 *
 * \return Standard Pacemaker return code
 *
 * \note This function returns \p EREMOTEIO if run on a Pacemaker Remote node
 *       with \p pacemaker-remoted running, since \p pacemakerd is not proxied
 *       to remote nodes. The fencer and CIB may still be accessible, but
 *       \p state will be \p pcmk_pacemakerd_state_invalid.
 */
int
pcmk__pacemakerd_status(pcmk__output_t *out, const char *ipc_name,
                        unsigned int message_timeout_ms,
                        enum pcmk_pacemakerd_state *state)
{
    data_t data = {
        .out = out,
        .rc = pcmk_rc_ok,
        .reply_received = false,
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

    rc = pcmk__pacemakerd_status(out, ipc_name, message_timeout_ms, NULL);
    pcmk__xml_output_finish(out, xml);
    return rc;
}

/* user data for looping through remote node xpath searches */
struct node_data {
    pcmk__output_t *out;
    int found;
    const char *field;  /* XML attribute to check for node name */
    const char *type;
    gboolean bash_export;
};

static void
remote_node_print_helper(xmlNode *result, void *user_data)
{
    struct node_data *data = user_data;
    pcmk__output_t *out = data->out;
    const char *name = crm_element_value(result, XML_ATTR_UNAME);
    const char *id = crm_element_value(result, data->field);

    // node name and node id are the same for remote/guest nodes
    out->message(out, "crmadmin-node", data->type,
                 name ? name : id,
                 id,
                 data->bash_export);
    data->found++;
}

// \return Standard Pacemaker return code
int
pcmk__list_nodes(pcmk__output_t *out, char *node_types, gboolean bash_export)
{
    xmlNode *xml_node = NULL;
    int rc;

    rc = cib__signon_query(NULL, &xml_node);

    if (rc == pcmk_rc_ok) {
        struct node_data data = {
            .out = out,
            .found = 0,
            .bash_export = bash_export
        };

        out->begin_list(out, NULL, NULL, "nodes");

        if (!pcmk__str_empty(node_types) && strstr(node_types, "all")) {
            node_types = NULL;
        }

        if (pcmk__str_empty(node_types) || strstr(node_types, "cluster")) {
            data.field = "id";
            data.type = "cluster";
            crm_foreach_xpath_result(xml_node, PCMK__XP_MEMBER_NODE_CONFIG,
                                     remote_node_print_helper, &data);
        }

        if (pcmk__str_empty(node_types) || strstr(node_types, "guest")) {
            data.field = "value";
            data.type = "guest";
            crm_foreach_xpath_result(xml_node, PCMK__XP_GUEST_NODE_CONFIG,
                                     remote_node_print_helper, &data);
        }

        if (pcmk__str_empty(node_types) || !pcmk__strcmp(node_types, ",|^remote", pcmk__str_regex)) {
            data.field = "id";
            data.type = "remote";
            crm_foreach_xpath_result(xml_node, PCMK__XP_REMOTE_NODE_CONFIG,
                                     remote_node_print_helper, &data);
        }

        out->end_list(out);

        if (data.found == 0) {
            out->info(out, "No nodes configured");
        }

        free_xml(xml_node);
    }

    return rc;
}

int
pcmk_list_nodes(xmlNodePtr *xml, char *node_types)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    pcmk__register_lib_messages(out);

    rc = pcmk__list_nodes(out, node_types, FALSE);
    pcmk__xml_output_finish(out, xml);
    return rc;
}
