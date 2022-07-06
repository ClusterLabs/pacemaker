/*
 * Copyright 2021-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdlib.h>
#include <time.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/ipc_schedulerd.h>
#include "crmcommon_private.h"

typedef struct schedulerd_api_private_s {
    char *client_uuid;
} schedulerd_api_private_t;

// \return Standard Pacemaker return code
static int
new_data(pcmk_ipc_api_t *api)
{
    struct schedulerd_api_private_s *private = NULL;

    api->api_data = calloc(1, sizeof(struct schedulerd_api_private_s));

    if (api->api_data == NULL) {
        return errno;
    }

    private = api->api_data;
    /* See comments in ipc_pacemakerd.c. */
    private->client_uuid = pcmk__getpid_s();

    return pcmk_rc_ok;
}

static void
free_data(void *data)
{
    free(((struct schedulerd_api_private_s *) data)->client_uuid);
    free(data);
}

// \return Standard Pacemaker return code
static int
post_connect(pcmk_ipc_api_t *api)
{
    if (api->api_data == NULL) {
        return EINVAL;
    }

    return pcmk_rc_ok;
}

static bool
reply_expected(pcmk_ipc_api_t *api, xmlNode *request)
{
    const char *command = crm_element_value(request, F_CRM_TASK);

    if (command == NULL) {
        return false;
    }

    // We only need to handle commands that functions in this file can send
    return pcmk__str_any_of(command, CRM_OP_PECALC, NULL);
}

static bool
dispatch(pcmk_ipc_api_t *api, xmlNode *reply)
{
    crm_exit_t status = CRM_EX_OK;
    xmlNode *msg_data = NULL;
    pcmk_schedulerd_api_reply_t reply_data = {
        pcmk_schedulerd_reply_unknown
    };
    const char *value = NULL;

    if (pcmk__str_eq((const char *) reply->name, "ack", pcmk__str_casei)) {
        return false;
    }

    value = crm_element_value(reply, F_CRM_MSG_TYPE);
    if (!pcmk__str_eq(value, XML_ATTR_RESPONSE, pcmk__str_none)) {
        crm_info("Unrecognizable message from schedulerd: "
                  "message type '%s' not '" XML_ATTR_RESPONSE "'",
                  pcmk__s(value, ""));
        status = CRM_EX_PROTOCOL;
        goto done;
    }

    if (pcmk__str_empty(crm_element_value(reply, XML_ATTR_REFERENCE))) {
        crm_info("Unrecognizable message from schedulerd: no reference");
        status = CRM_EX_PROTOCOL;
        goto done;
    }

    // Parse useful info from reply
    msg_data = get_message_xml(reply, F_CRM_DATA);
    value = crm_element_value(reply, F_CRM_TASK);

    if (pcmk__str_eq(value, CRM_OP_PECALC, pcmk__str_none)) {
        reply_data.reply_type = pcmk_schedulerd_reply_graph;
        reply_data.data.graph.reference = crm_element_value(reply, XML_ATTR_REFERENCE);
        reply_data.data.graph.input = crm_element_value(reply, F_CRM_TGRAPH_INPUT);
        reply_data.data.graph.tgraph = msg_data;
    } else {
        crm_info("Unrecognizable message from schedulerd: "
                  "unknown command '%s'", pcmk__s(value, ""));
        status = CRM_EX_PROTOCOL;
        goto done;
    }

done:
    pcmk__call_ipc_callback(api, pcmk_ipc_event_reply, status, &reply_data);
    return false;
}

pcmk__ipc_methods_t *
pcmk__schedulerd_api_methods()
{
    pcmk__ipc_methods_t *cmds = calloc(1, sizeof(pcmk__ipc_methods_t));

    if (cmds != NULL) {
        cmds->new_data = new_data;
        cmds->free_data = free_data;
        cmds->post_connect = post_connect;
        cmds->reply_expected = reply_expected;
        cmds->dispatch = dispatch;
    }
    return cmds;
}

static int
do_schedulerd_api_call(pcmk_ipc_api_t *api, const char *task, xmlNode *cib, char **ref)
{
    schedulerd_api_private_t *private;
    xmlNode *cmd = NULL;
    int rc;

    if (!pcmk_ipc_is_connected(api)) {
        return ENOTCONN;
    }

    private = api->api_data;
    CRM_ASSERT(private != NULL);

    cmd = create_request(task, cib, NULL, CRM_SYSTEM_PENGINE,
                         crm_system_name? crm_system_name : "client",
                         private->client_uuid);

    if (cmd) {
        rc = pcmk__send_ipc_request(api, cmd);
        if (rc != pcmk_rc_ok) {
            crm_debug("Couldn't send request to schedulerd: %s rc=%d",
                      pcmk_rc_str(rc), rc);
        }

        *ref = strdup(crm_element_value(cmd, F_CRM_REFERENCE));
        free_xml(cmd);
    } else {
        rc = ENOMSG;
    }

    return rc;
}

int
pcmk_schedulerd_api_graph(pcmk_ipc_api_t *api, xmlNode *cib, char **ref)
{
    return do_schedulerd_api_call(api, CRM_OP_PECALC, cib, ref);
}
