/*
 * Copyright 2019-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * Licensed under the GNU General Public License version 2 or later (GPLv2+).
 */

/*
 * Intended demo use case:
 *
 * - as root, start corosync
 * - start "./based -N"; hint:
 *   su -s /bin/sh -c './based -N' hacluster
 * - start pacemaker-fenced; hint:
 *   su -c 'env PCMK_logpriority=crit ../../daemons/fenced/pacemaker-fenced'
 * - wait a bit (5 < seconds < 20)
 * - as haclient group (or root), run "stonith admin --list-registered"
 * - observe whether such invocation is blocked or not
 */


#include <stdio.h>  /* printf, perror */

#include "crm/cib.h"  /* cib_zero_copy */
#include "crm/cib/internal.h"  /* CIB_OP_CREATE */
#include "crm/msg_xml.h"  /* F_SUBTYPE */
#include "daemons/based/pacemaker-based.h"  /* cib_notify_diff */

#include "based.h"


#define OPTCHAR 'N'
static size_t module_handle;


struct cib_notification_s {
    xmlNode *msg;
    struct iovec *iov;
    int32_t iov_size;
};

/* see based/based_notify.c:cib_notify_send_one */
static bool
mock_based_cib_notify_send_one(pcmk__client_t *client, xmlNode *xml)
{
    const char *type = NULL;
    bool do_send = false;
    struct iovec *iov;
    ssize_t bytes;
    struct cib_notification_s update = {
        .msg = xml,
    };

    CRM_CHECK(client != NULL, return true);
    pcmk__ipc_prepare_iov(0, xml, 0, &iov, &bytes);
    update.iov = iov;
    update.iov_size = bytes;
    if (client->ipcs == NULL && client->remote == NULL) {
        crm_warn("Skipping client with NULL channel");
        return FALSE;
    }

    type = crm_element_value(update.msg, F_SUBTYPE);
    CRM_LOG_ASSERT(type != NULL);
    if (pcmk_is_set(client->options, cib_notify_diff)
        && pcmk__str_eq(type, T_CIB_DIFF_NOTIFY, pcmk__str_casei)) {

        if (pcmk__ipc_send_iov(client, update.iov,
                               crm_ipc_server_event) != pcmk_rc_ok) {
            crm_warn("Notification of client %s/%s failed", client->name, client->id);
        }

    }
    pcmk_free_ipc_event(iov);

    return FALSE;
}

/* see based/based_notify.c:do_cib_notify + cib_notify_send */
void
do_cib_notify(pcmk__client_t *cib_client, int options, const char *op,
              xmlNode *update, int result, xmlNode *result_data,
              const char *msg_type)
{
    xmlNode *update_msg = NULL;
    const char *id = NULL;

    update_msg = create_xml_node(NULL, "notify");


    crm_xml_add(update_msg, F_TYPE, T_CIB_NOTIFY);
    crm_xml_add(update_msg, F_SUBTYPE, msg_type);
    crm_xml_add(update_msg, F_CIB_OPERATION, op);
    crm_xml_add_int(update_msg, F_CIB_RC, result);

    if (result_data != NULL) {
        id = crm_element_value(result_data, XML_ATTR_ID);
        if (id != NULL)
            crm_xml_add(update_msg, F_CIB_OBJID, id);
    }

    if (update != NULL) {
        crm_trace("Setting type to update->name: %s", crm_element_name(update));
        crm_xml_add(update_msg, F_CIB_OBJTYPE, crm_element_name(update));

    } else if (result_data != NULL) {
        crm_trace("Setting type to new_obj->name: %s", crm_element_name(result_data));
        crm_xml_add(update_msg, F_CIB_OBJTYPE, crm_element_name(result_data));

    } else {
        crm_trace("Not Setting type");
    }

#if 0
    attach_cib_generation(update_msg, "cib_generation", the_cib);
#endif

    if (update != NULL) {
        add_message_xml(update_msg, F_CIB_UPDATE, update);
    }
    if (result_data != NULL) {
        add_message_xml(update_msg, F_CIB_UPDATE_RESULT, result_data);
    }

    mock_based_cib_notify_send_one(cib_client, update_msg);
    free_xml(update_msg);
}

static gboolean
mock_based_notifyfencedmer_callback_worker(gpointer data)
{
    pcmk__client_t *cib_client = (pcmk__client_t *) data;

    xmlNode *result_data;
    xmlNode *input, *update;
    int options;
    char update_str[4096];

    cib__set_call_options(options, crm_system_name, cib_zero_copy);


    input = create_xml_node(NULL, "cib");

    /* spam it */
#if 0
    for (size_t i = 0; i < SIZE_MAX - 1; i++) {
#else
    for (size_t i = 0; i < 10000; i++) {
#endif
        /* NOTE: we need to trigger fenced attention, add new fence device */
        snprintf(update_str, sizeof(update_str),
"<diff crm_feature_set='3.1.0' format='1'>\n"
"  <diff-removed admin_epoch='%1$llu' epoch='%1$llu' num_updates='%1$llu'>\n"
"    <cib admin_epoch='%1$llu' epoch='%1$llu' num_updates='%1$llu'/>\n"
"  </diff-removed>\n"
"  <diff-added admin_epoch='%2$llu' epoch='%2$llu' num_updates='%2$llu'>\n"
"    <cib validate-with='pacemaker-1.2' admin_epoch='%2$llu' epoch='%2$llu' num_updates='%2$llu'>\n"
"      <configuration>\n"
"        <resources>\n"
"          <primitive id='FENCEDEV-fence-dummy-%2$llu' class='stonith' type='__apparently_bogus__' __crm_diff_marker__='added:top'/>\n"
"        </resources>\n"
"      </configuration>\n"
"    </cib>\n"
"  </diff-added>\n"
"</diff>\n", i, i+1);
        update = xmlReadMemory(update_str, sizeof(update_str),
                               "file:///tmp/update", NULL, 0)->children;
        do_cib_notify(cib_client, options, CIB_OP_CREATE, input, pcmk_ok,
                      update, T_CIB_DIFF_NOTIFY);
        free_xml(update);
    };

    free_xml(input);
}

static void
mock_based_notifyfenced_cib_notify_hook(pcmk__client_t *cib_client)
{

    /* MOCK: client asked for upcoming diff's, let's
             spam it a bit after a while... */
    crm_info("Going to spam %s (%s) in 5 seconds...",
             cib_client->name, cib_client->id);
    mainloop_timer_start(mainloop_timer_add("spammer", 5000, FALSE,
                         mock_based_notifyfencedmer_callback_worker,
                         cib_client));
}

/* * */

static int
mock_based_notifyfenced_argparse_hook(struct mock_based_context_s *ctxt,
                                    bool usage, int argc_to_go,
                                    const char *argv_to_go[])
{
    const char *opt = *argv_to_go;
restart:
    switch(*opt) {
    case '-':
        if (opt == *argv_to_go) {
            opt++;
            goto restart;
        }
        break;
    case OPTCHAR:
        if (usage) {
            printf("spam the \"cib diff\" notification client"
                   " (targeting pacemaker-fenced in particular)\n");

        } else {
#if 0
            ctxt->modules[module_handle]->priv =
                malloc(sizeof(mock_based_notifyfenced_priv_t));
            if (ctxt->modules[module_handle]->priv == NULL) {
                perror("malloc");
                return -1;
            }
#endif
        }
        return 1;
    }
    return 0;
}

#if 0
static void
mock_based_notifyfenced_destroy_hook(module_t *mod) {
    free(mod->priv);
}
#endif

__attribute__((__constructor__))
void
mock_based_notifyfenced_init(void) {
    module_handle = mock_based_register_module((module_t){
        .shortopt = OPTCHAR,
        .hooks = {
            .argparse = mock_based_notifyfenced_argparse_hook,
            //.destroy = mock_based_notifyfenced_destroy_hook,
            /* specialized hooks */
            .cib_notify = mock_based_notifyfenced_cib_notify_hook,
        }
    });
}
