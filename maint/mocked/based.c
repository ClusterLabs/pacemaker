/*
 * Copyright 2019-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * Licensed under the GNU General Public License version 2 or later (GPLv2+).
 */

/*
 * Clean room attempt (admittedly with lot of code borrowed or inspired from
 * the full-blown daemon), minimalistic implementation of based daemon, with
 * only important aspects being implemented at the moment.
 *
 * Hopefully easy to adapt for variety of purposes.
 *
 * NOTE: currently, only cib_rw API end-point is opened, future refinements
 *       as new modules are added should conditionalize per what the module
 *       indicates in the context (which is intentionally very loose data glue
 *       between the skeleton and modules themselves (like CGI variables so
 *       to say, but more structurally predestined so as to avoid complexities
 *       of hash table lookups etc.)
 */

#include <crm_internal.h>
#if 0
#include "crm/common/ipc_internal.h"  /* pcmk__client_t */
#include "crm/common/xml.h"  /* crm_xml_add */
#endif
#include "crm/msg_xml.h"  /* F_SUBTYPE */
#include "daemons/based/pacemaker-based.h"  /* cib_notify_diff */

#include <qb/qbipcs.h>  /* qb_ipcs_connection_t */

#include "based.h"


/* direct global access violated in one case only
   - mock_based_ipc_accept adds a reference to it to crm_cient_t->userdata */
mock_based_context_t mock_based_context;


/* see based/based_callbacks.c:cib_ipc_accept */
static int32_t
mock_based_ipc_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    int32_t ret = 0;
    pcmk__client_t *cib_client;

    crm_trace("Connection %p", c);
    cib_client = pcmk__new_client(c, uid, gid);
    if (cib_client == NULL) {
        ret = -EIO;
    }

    cib_client->userdata = &mock_based_context;

    return ret;
}

/* see based/based_callbacks.c:cib_ipc_closed */
static int32_t
mock_based_ipc_closed(qb_ipcs_connection_t *c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client != NULL) {
        crm_trace("Connection %p", c);
        pcmk__free_client(client);
    }

    return 0;
}

/* see based/based_callbacks.c:cib_ipc_destroy */
static void
mock_based_ipc_destroy(qb_ipcs_connection_t *c)
{
    crm_trace("Connection %p", c);
    mock_based_ipc_closed(c);
}

/* see based/based_callbacks.c:cib_process_command (and more) */
static void
mock_based_handle_query(pcmk__client_t *cib_client, uint32_t flags,
                        const xmlNode *op_request)
{
    xmlNode *reply, *cib;
    const char cib_str[] =
#if 0
"<cib/>";
#else
"<cib validate-with='pacemaker-1.2' admin_epoch='0' epoch='0' num_updates='0'>"\
"  <configuration>"\
"    <crm_config/>"\
"    <nodes/>"\
"    <resources/>"\
"    <constraints/>"\
"  </configuration>"\
"  <status/>"\
"</cib>";
#endif
    cib = xmlReadMemory(cib_str, sizeof(cib_str), "file:///tmp/foo", NULL, 0)->children;

    reply = create_xml_node(NULL, "cib-reply");
    crm_xml_add(reply, F_TYPE, T_CIB);
    crm_xml_add(reply, F_CIB_OPERATION,
                crm_element_value(op_request, F_CIB_OPERATION));
    crm_xml_add(reply, F_CIB_CALLID,
                crm_element_value(op_request, F_CIB_CALLID));
    crm_xml_add(reply, F_CIB_CLIENTID,
                crm_element_value(op_request, F_CIB_CLIENTID));
    crm_xml_add_int(reply, F_CIB_CALLOPTS, flags);
    crm_xml_add_int(reply, F_CIB_RC, pcmk_ok);

    if (cib != NULL) {
        crm_trace("Attaching reply output");
        add_message_xml(reply, F_CIB_CALLDATA, cib);
    }

    pcmk__ipc_send_xml(cib_client, cib_client->request_id, reply,
                       ((flags & cib_sync_call)? crm_ipc_flags_none
                        : crm_ipc_server_event));

    free_xml(reply);
    free_xml(cib);
}

/* see based/based_callbacks.c:cib_common_callback_worker */
static void
mock_based_common_callback_worker(uint32_t id, uint32_t flags,
                                  xmlNode *op_request,
                                  pcmk__client_t *cib_client)
{
    const char *op = crm_element_value(op_request, F_CIB_OPERATION);
    mock_based_context_t *ctxt;

    if (!strcmp(op, CRM_OP_REGISTER)) {
        if (flags & crm_ipc_client_response) {
            xmlNode *ack = create_xml_node(NULL, __func__);
            crm_xml_add(ack, F_CIB_OPERATION, CRM_OP_REGISTER);
            crm_xml_add(ack, F_CIB_CLIENTID, cib_client->id);
            pcmk__ipc_send_xml(cib_client, id, ack, flags);
            cib_client->request_id = 0;
            free_xml(ack);
        }

    } else if (!strcmp(op, T_CIB_NOTIFY)) {
        int on_off = 0;
        const char *type = crm_element_value(op_request, F_CIB_NOTIFY_TYPE);
        crm_element_value_int(op_request, F_CIB_NOTIFY_ACTIVATE, &on_off);

        crm_debug("Setting %s callbacks for %s (%s): %s",
                  type, cib_client->name, cib_client->id, on_off ? "on" : "off");

        if (!strcmp(type, T_CIB_DIFF_NOTIFY) && on_off) {
            pcmk__set_client_flags(cib_client, cib_notify_diff);
        }

        ctxt = (mock_based_context_t *) cib_client->userdata;
        for (size_t c = ctxt->modules_cnt; c > 0; c--) {
            if (ctxt->modules[c - 1]->hooks.cib_notify != NULL) {
                ctxt->modules[c - 1]->hooks.cib_notify(cib_client);
            }
        }

        if (flags & crm_ipc_client_response) {
            pcmk__ipc_send_ack(cib_client, id, flags, "ack", CRM_EX_OK);
        }

    } else if (!strcmp(op, CIB_OP_QUERY)) {
        mock_based_handle_query(cib_client, flags, op_request);

    } else {
        crm_notice("Discarded request %s", op);
    }
}

/* see based/based_callbacks.c:cib_ipc_dispatch_rw */
static int32_t
mock_based_dispatch_command(qb_ipcs_connection_t *c, void *data, size_t size)
{
    uint32_t id = 0, flags = 0;
    int call_options = 0;
    pcmk__client_t *cib_client = pcmk__find_client(c);
    xmlNode *op_request = pcmk__client_data2xml(cib_client, data, &id, &flags);

    crm_notice("Got connection %p", c);
    assert(op_request != NULL);

    if (cib_client == NULL || op_request == NULL) {
        if (op_request == NULL) {
            crm_trace("Invalid message from %p", c);
            pcmk__ipc_send_ack(cib_client, id, flags, "nack", CRM_EX_PROTOCOL);
        }
        return 0;
    }

    crm_element_value_int(op_request, F_CIB_CALLOPTS, &call_options);
    if (call_options & cib_sync_call) {
        assert(flags & crm_ipc_client_response);
        cib_client->request_id = id;  /* reply only to last in-flight request */
    }

    assert(cib_client->name == NULL);
    crm_element_value_int(op_request, F_CIB_CALLOPTS, &call_options);
    crm_xml_add(op_request, F_CIB_CLIENTID, cib_client->id);
    crm_xml_add(op_request, F_CIB_CLIENTNAME, cib_client->name);

    mock_based_common_callback_worker(id, flags, op_request, cib_client);
    free_xml(op_request);

    return 0;
}

/* * */

size_t mock_based_register_module(module_t mod) {
    module_t *module;
    size_t ret = mock_based_context.modules_cnt++;

    mock_based_context.modules = realloc(mock_based_context.modules,
                                         sizeof(*mock_based_context.modules)
                                          * mock_based_context.modules_cnt);
    if (mock_based_context.modules == NULL
            || (module = malloc(sizeof(module_t))) == NULL) {
        abort();
    }

    memcpy(module, &mod, sizeof(mod));
    mock_based_context.modules[mock_based_context.modules_cnt - 1] = module;

    return ret;
}

static int
mock_based_options(mock_based_context_t *ctxt,
                   bool usage, int argc, const char *argv[])
{
    const char **args2argv;
    char *s;
    int ret = 0;

    if (argc <= 1) {
        const char *help_argv[] = {argv[0], "-h"};
        return mock_based_options(ctxt, false, 2, (const char **) &help_argv);
    }

    for (size_t i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] != '-' && argv[i][1] != '\0') {
            if (usage) {
                printf("\t-%c\t", argv[i][1]);
            }
            switch(argv[i][1]) {
            case 'h':
                if (usage) {
                    printf("show this help message\n");
                    ret = 1;

                } else {
                    if ((args2argv
                            = malloc((ctxt->modules_cnt + 2) * sizeof(*args2argv))) == NULL
                        || (s
                            = malloc((ctxt->modules_cnt * 2 + 2) * sizeof(*s))) == NULL) {
                        return -1;
                    }
                    s[0] = 'h';
                    args2argv[ctxt->modules_cnt + 1] = (char[]){'-', 'h', '\0'};
                    for (size_t c = ctxt->modules_cnt; c > 0; c--) {
                        args2argv[c] = (char[]){'-', ctxt->modules[c - 1]->shortopt, '\0'};
                        s[(ctxt->modules_cnt - i) + 1] = '|';
                        s[(ctxt->modules_cnt - i) + 2] = ctxt->modules[c - 1]->shortopt;
                    }
                    s[ctxt->modules_cnt * 2 + 1] = '\0';
                    printf("Usage: %s [-{%s}]\n", argv[0], s);
                    (void) mock_based_options(ctxt, true, 2 + ctxt->modules_cnt, args2argv);
                    free(args2argv);
                    free(s);
                }
                return ret;
            default:
                for (size_t c = ctxt->modules_cnt; c > 0; c--) {
                    if (ctxt->modules[c - 1]->shortopt == argv[i][1]) {
                        ret = ctxt->modules[c - 1]->hooks.argparse(ctxt, usage, argc - i, &argv[i]);
                        if (ret < 0) {
                            break;
                        } else if (ret > 1) {
                            i += (ret - 1);
                        }
                    }
                }
                if (ret == 0) {
                    printf("uknown option \"%s\"\n", argv[i]);
                }
                break;
            }
        }
    }
    return ret;
}

int main(int argc, char *argv[])
{
    mock_based_context_t *ctxt = &mock_based_context;

    if (mock_based_options(ctxt, false, argc, (const char **) argv) > 0) {
        struct qb_ipcs_service_handlers cib_ipc_callbacks = {
            .connection_accept = mock_based_ipc_accept,
            .connection_created = NULL,
            .msg_process = mock_based_dispatch_command,
            .connection_closed = mock_based_ipc_closed,
            .connection_destroyed = mock_based_ipc_destroy,
        };
        crm_log_preinit(NULL, argc, argv);
        crm_log_init(NULL, LOG_DEBUG, false, true, argc, argv, false);
        qb_ipcs_service_t *ipcs_command =
            mainloop_add_ipc_server(PCMK__SERVER_BASED_RW, QB_IPC_NATIVE,
                                    &cib_ipc_callbacks);
        g_main_loop_run(g_main_loop_new(NULL, false));
        qb_ipcs_destroy(ipcs_command);
    }

    for (size_t c = ctxt->modules_cnt; c > 0; c--) {
        if (ctxt->modules[c - 1]->hooks.destroy != NULL) {
            ctxt->modules[c - 1]->hooks.destroy(ctxt->modules[c - 1]);
        }
        free(mock_based_context.modules[c - 1]);
    }

    free(mock_based_context.modules);
}
