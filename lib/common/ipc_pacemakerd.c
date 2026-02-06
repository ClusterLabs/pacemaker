/*
 * Copyright 2020-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_pacemakerd.h>
#include "crmcommon_private.h"

typedef struct {
    enum pcmk_pacemakerd_state state;
    char *client_uuid;
} pacemakerd_api_private_t;

static const char *pacemakerd_state_str[] = {
    PCMK__VALUE_INIT,
    PCMK__VALUE_STARTING_DAEMONS,
    PCMK__VALUE_WAIT_FOR_PING,
    PCMK__VALUE_RUNNING,
    PCMK__VALUE_SHUTTING_DOWN,
    PCMK__VALUE_SHUTDOWN_COMPLETE,
    PCMK_VALUE_REMOTE,
};

enum pcmk_pacemakerd_state
pcmk_pacemakerd_api_daemon_state_text2enum(const char *state)
{
    int i;

    if (state == NULL) {
        return pcmk_pacemakerd_state_invalid;
    }
    for (i=pcmk_pacemakerd_state_init; i <= pcmk_pacemakerd_state_max;
         i++) {
        if (pcmk__str_eq(state, pacemakerd_state_str[i], pcmk__str_none)) {
            return i;
        }
    }
    return pcmk_pacemakerd_state_invalid;
}

const char *
pcmk_pacemakerd_api_daemon_state_enum2text(
    enum pcmk_pacemakerd_state state)
{
    if ((state >= pcmk_pacemakerd_state_init) &&
        (state <= pcmk_pacemakerd_state_max)) {
        return pacemakerd_state_str[state];
    }
    return "invalid";
}

/*!
 * \internal
 * \brief Return a friendly string representation of a \p pacemakerd state
 *
 * \param[in] state  \p pacemakerd state
 *
 * \return A user-friendly string representation of \p state, or
 *         <tt>"Invalid pacemakerd state"</tt>
 */
const char *
pcmk__pcmkd_state_enum2friendly(enum pcmk_pacemakerd_state state)
{
    switch (state) {
        case pcmk_pacemakerd_state_init:
            return "Initializing pacemaker";
        case pcmk_pacemakerd_state_starting_daemons:
            return "Pacemaker daemons are starting";
        case pcmk_pacemakerd_state_wait_for_ping:
            return "Waiting for startup trigger from SBD";
        case pcmk_pacemakerd_state_running:
            return "Pacemaker is running";
        case pcmk_pacemakerd_state_shutting_down:
            return "Pacemaker daemons are shutting down";
        case pcmk_pacemakerd_state_shutdown_complete:
            /* Assuming pacemakerd won't process messages while in
             * shutdown_complete state unless reporting to SBD
             */
            return "Pacemaker daemons are shut down (reporting to SBD)";
        case pcmk_pacemakerd_state_remote:
            return PCMK__SERVER_REMOTED " is running "
                   "(on a Pacemaker Remote node)";
        default:
            return "Invalid pacemakerd state";
    }
}

/*!
 * \internal
 * \brief Get a string representation of a \p pacemakerd API reply type
 *
 * \param[in] reply  \p pacemakerd API reply type
 *
 * \return String representation of a \p pacemakerd API reply type
 */
const char *
pcmk__pcmkd_api_reply2str(enum pcmk_pacemakerd_api_reply reply)
{
    switch (reply) {
        case pcmk_pacemakerd_reply_ping:
            return "ping";
        case pcmk_pacemakerd_reply_shutdown:
            return "shutdown";
        default:
            return "unknown";
    }
}

// \return Standard Pacemaker return code
static int
new_data(pcmk_ipc_api_t *api)
{
    pacemakerd_api_private_t *private = NULL;

    api->api_data = calloc(1, sizeof(pacemakerd_api_private_t));

    if (api->api_data == NULL) {
        return errno;
    }

    private = api->api_data;
    private->state = pcmk_pacemakerd_state_invalid;
    /* other as with cib, controld, ... we are addressing pacemakerd just
       from the local node -> pid is unique and thus sufficient as an ID
     */
    private->client_uuid = pcmk__getpid_s();

    return pcmk_rc_ok;
}

static void
free_data(void *data)
{
    free(((pacemakerd_api_private_t *) data)->client_uuid);
    free(data);
}

// \return Standard Pacemaker return code
static int
post_connect(pcmk_ipc_api_t *api)
{
    pacemakerd_api_private_t *private = NULL;

    if (api->api_data == NULL) {
        return EINVAL;
    }
    private = api->api_data;
    private->state = pcmk_pacemakerd_state_invalid;

    return pcmk_rc_ok;
}

static void
post_disconnect(pcmk_ipc_api_t *api)
{
    pacemakerd_api_private_t *private = NULL;

    if (api->api_data == NULL) {
        return;
    }
    private = api->api_data;
    private->state = pcmk_pacemakerd_state_invalid;
}

static bool
reply_expected(pcmk_ipc_api_t *api, const xmlNode *request)
{
    const char *command = pcmk__xe_get(request, PCMK__XA_CRM_TASK);

    if (command == NULL) {
        return false;
    }

    // We only need to handle commands that functions in this file can send
    return pcmk__str_any_of(command, CRM_OP_PING, CRM_OP_QUIT, NULL);
}

static bool
dispatch(pcmk_ipc_api_t *api, xmlNode *reply)
{
    crm_exit_t status = CRM_EX_OK;
    xmlNode *wrapper = NULL;
    xmlNode *msg_data = NULL;
    pcmk_pacemakerd_api_reply_t reply_data = {
        pcmk_pacemakerd_reply_unknown
    };
    const char *value = NULL;

    if (pcmk__xe_is(reply, PCMK__XE_ACK)) {
        long long int ack_status = 0;
        const char *status = pcmk__xe_get(reply, PCMK_XA_STATUS);
        int rc = pcmk__scan_ll(status, &ack_status, CRM_EX_OK);

        if (rc != pcmk_rc_ok) {
            pcmk__warn("Ack reply from %s has invalid " PCMK_XA_STATUS " '%s' "
                       "(bug?)",
                       pcmk_ipc_name(api, true), pcmk__s(status, ""));
        }
        return ack_status == CRM_EX_INDETERMINATE;
    }

    value = pcmk__xe_get(reply, PCMK__XA_T);
    if (pcmk__parse_server(value) != pcmk_ipc_pacemakerd) {
        /* @COMPAT pacemakerd <3.0.0 sets PCMK__VALUE_CRMD as the message type,
         * so we can't enforce this check until we no longer support
         * Pacemaker Remote nodes connecting to cluster nodes older than that.
         */
        pcmk__trace("Message from %s has unexpected message type '%s' (bug if "
                    "not from pacemakerd <3.0.0)",
                    pcmk_ipc_name(api, true), pcmk__s(value, ""));
    }

    value = pcmk__xe_get(reply, PCMK__XA_SUBT);
    if (!pcmk__str_eq(value, PCMK__VALUE_RESPONSE, pcmk__str_none)) {
        pcmk__info("Unrecognizable message from %s: message type '%s' not "
                   "'" PCMK__VALUE_RESPONSE "'",
                   pcmk_ipc_name(api, true), pcmk__s(value, ""));
        status = CRM_EX_PROTOCOL;
        goto done;
    }

    if (pcmk__str_empty(pcmk__xe_get(reply, PCMK_XA_REFERENCE))) {
        pcmk__info("Unrecognizable message from %s: no reference",
                   pcmk_ipc_name(api, true));
        status = CRM_EX_PROTOCOL;
        goto done;
    }

    value = pcmk__xe_get(reply, PCMK__XA_CRM_TASK);

    // Parse useful info from reply
    wrapper = pcmk__xe_first_child(reply, PCMK__XE_CRM_XML, NULL, NULL);
    msg_data = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

    if (pcmk__str_eq(value, CRM_OP_PING, pcmk__str_none)) {
        reply_data.reply_type = pcmk_pacemakerd_reply_ping;
        reply_data.data.ping.state =
            pcmk_pacemakerd_api_daemon_state_text2enum(
                pcmk__xe_get(msg_data, PCMK__XA_PACEMAKERD_STATE));
        reply_data.data.ping.status =
            pcmk__str_eq(pcmk__xe_get(msg_data, PCMK_XA_RESULT), "ok",
                         pcmk__str_casei)?pcmk_rc_ok:pcmk_rc_error;

        pcmk__xe_get_time(msg_data, PCMK__XA_CRM_TIMESTAMP,
                          &reply_data.data.ping.last_good);
        if (reply_data.data.ping.last_good < 0) {
            reply_data.data.ping.last_good = 0;
        }

        reply_data.data.ping.sys_from =
            pcmk__xe_get(msg_data, PCMK__XA_CRM_SUBSYSTEM);
    } else if (pcmk__str_eq(value, CRM_OP_QUIT, pcmk__str_none)) {
        const char *op_status = pcmk__xe_get(msg_data, PCMK__XA_OP_STATUS);

        reply_data.reply_type = pcmk_pacemakerd_reply_shutdown;
        reply_data.data.shutdown.status = atoi(op_status);
    } else {
        pcmk__info("Unrecognizable message from %s: unknown command '%s'",
                   pcmk_ipc_name(api, true), pcmk__s(value, ""));
        status = CRM_EX_PROTOCOL;
        goto done;
    }

done:
    pcmk__call_ipc_callback(api, pcmk_ipc_event_reply, status, &reply_data);
    return false;
}

pcmk__ipc_methods_t *
pcmk__pacemakerd_api_methods(void)
{
    pcmk__ipc_methods_t *cmds = calloc(1, sizeof(pcmk__ipc_methods_t));

    if (cmds != NULL) {
        cmds->new_data = new_data;
        cmds->free_data = free_data;
        cmds->post_connect = post_connect;
        cmds->reply_expected = reply_expected;
        cmds->dispatch = dispatch;
        cmds->post_disconnect = post_disconnect;
    }
    return cmds;
}

static int
do_pacemakerd_api_call(pcmk_ipc_api_t *api, const char *ipc_name, const char *task)
{
    pacemakerd_api_private_t *private;
    char *sender_system = NULL;
    xmlNode *cmd;
    int rc;

    if (api == NULL) {
        return EINVAL;
    }

    private = api->api_data;
    pcmk__assert(private != NULL);

    sender_system = pcmk__assert_asprintf("%s_%s", private->client_uuid,
                                          pcmk__ipc_sys_name(ipc_name,
                                                             "client"));
    cmd = pcmk__new_request(pcmk_ipc_pacemakerd, sender_system, NULL,
                            CRM_SYSTEM_MCP, task, NULL);
    free(sender_system);

    if (cmd) {
        rc = pcmk__send_ipc_request(api, cmd);
        if (rc != pcmk_rc_ok) {
            pcmk__debug("Couldn't send request to %s: %s rc=%d",
                        pcmk_ipc_name(api, true), pcmk_rc_str(rc), rc);
        }
        pcmk__xml_free(cmd);
    } else {
        rc = ENOMSG;
    }

    return rc;
}

int
pcmk_pacemakerd_api_ping(pcmk_ipc_api_t *api, const char *ipc_name)
{
    return do_pacemakerd_api_call(api, ipc_name, CRM_OP_PING);
}

int
pcmk_pacemakerd_api_shutdown(pcmk_ipc_api_t *api, const char *ipc_name)
{
    return do_pacemakerd_api_call(api, ipc_name, CRM_OP_QUIT);
}
