/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>           // PRIx64

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <time.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>

#include <crm/common/xml.h>
#include <crm/common/remote_internal.h>
#include <pacemaker-based.h>

int pending_updates = 0;

struct cib_notification_s {
    xmlNode *msg;
    struct iovec *iov;
    int32_t iov_size;
};

void attach_cib_generation(xmlNode * msg, const char *field, xmlNode * a_cib);

static void do_cib_notify(int options, const char *op, xmlNode *update,
                          int result, xmlNode * result_data,
                          const char *msg_type);

static void
cib_notify_send_one(gpointer key, gpointer value, gpointer user_data)
{
    const char *type = NULL;
    gboolean do_send = FALSE;
    int rc = pcmk_rc_ok;

    pcmk__client_t *client = value;
    struct cib_notification_s *update = user_data;

    if (client->ipcs == NULL && client->remote == NULL) {
        crm_warn("Skipping client with NULL channel");
        return;
    }

    type = crm_element_value(update->msg, F_SUBTYPE);
    CRM_LOG_ASSERT(type != NULL);

    if (pcmk_is_set(client->flags, cib_notify_diff)
        && pcmk__str_eq(type, T_CIB_DIFF_NOTIFY, pcmk__str_casei)) {

        do_send = TRUE;

    } else if (pcmk_is_set(client->flags, cib_notify_replace)
               && pcmk__str_eq(type, T_CIB_REPLACE_NOTIFY, pcmk__str_casei)) {
        do_send = TRUE;

    } else if (pcmk_is_set(client->flags, cib_notify_confirm)
               && pcmk__str_eq(type, T_CIB_UPDATE_CONFIRM, pcmk__str_casei)) {
        do_send = TRUE;

    } else if (pcmk_is_set(client->flags, cib_notify_pre)
               && pcmk__str_eq(type, T_CIB_PRE_NOTIFY, pcmk__str_casei)) {
        do_send = TRUE;

    } else if (pcmk_is_set(client->flags, cib_notify_post)
               && pcmk__str_eq(type, T_CIB_POST_NOTIFY, pcmk__str_casei)) {

        do_send = TRUE;
    }

    if (do_send) {
        switch (PCMK__CLIENT_TYPE(client)) {
            case pcmk__client_ipc:
                rc = pcmk__ipc_send_iov(client, update->iov,
                                        crm_ipc_server_event);
                if (rc != pcmk_rc_ok) {
                    crm_warn("Could not notify client %s: %s " CRM_XS " id=%s",
                             pcmk__client_name(client), pcmk_rc_str(rc),
                             client->id);
                }
                break;
#ifdef HAVE_GNUTLS_GNUTLS_H
            case pcmk__client_tls:
#endif
            case pcmk__client_tcp:
                crm_debug("Sent %s notification to client %s (id %s)",
                          type, pcmk__client_name(client), client->id);
                pcmk__remote_send_xml(client->remote, update->msg);
                break;
            default:
                crm_err("Unknown transport for client %s "
                        CRM_XS " flags=%#016" PRIx64,
                        pcmk__client_name(client), client->flags);
        }
    }
}

static void
cib_notify_send(xmlNode * xml)
{
    struct iovec *iov;
    struct cib_notification_s update;

    ssize_t bytes = 0;
    int rc = pcmk__ipc_prepare_iov(0, xml, 0, &iov, &bytes);

    if (rc == pcmk_rc_ok) {
        update.msg = xml;
        update.iov = iov;
        update.iov_size = bytes;
        pcmk__foreach_ipc_client(cib_notify_send_one, &update);

    } else {
        crm_notice("Could not notify clients: %s " CRM_XS " rc=%d",
                   pcmk_rc_str(rc), rc);
    }
    pcmk_free_ipc_event(iov);
}

void
cib_diff_notify(int options, const char *client, const char *call_id, const char *op,
                xmlNode * update, int result, xmlNode * diff)
{
    int add_updates = 0;
    int add_epoch = 0;
    int add_admin_epoch = 0;

    int del_updates = 0;
    int del_epoch = 0;
    int del_admin_epoch = 0;

    int log_level = LOG_TRACE;

    if (diff == NULL) {
        return;
    }

    if (result != pcmk_ok) {
        log_level = LOG_WARNING;
    }

    cib_diff_version_details(diff, &add_admin_epoch, &add_epoch, &add_updates,
                             &del_admin_epoch, &del_epoch, &del_updates);

    if (add_updates != del_updates) {
        do_crm_log(log_level,
                   "Update (client: %s%s%s): %d.%d.%d -> %d.%d.%d (%s)",
                   client, call_id ? ", call:" : "", call_id ? call_id : "",
                   del_admin_epoch, del_epoch, del_updates,
                   add_admin_epoch, add_epoch, add_updates, pcmk_strerror(result));

    } else if (diff != NULL) {
        do_crm_log(log_level,
                   "Local-only Change (client:%s%s%s): %d.%d.%d (%s)",
                   client, call_id ? ", call: " : "", call_id ? call_id : "",
                   add_admin_epoch, add_epoch, add_updates, pcmk_strerror(result));
    }

    do_cib_notify(options, op, update, result, diff, T_CIB_DIFF_NOTIFY);
}

static void
do_cib_notify(int options, const char *op, xmlNode * update,
              int result, xmlNode * result_data, const char *msg_type)
{
    xmlNode *update_msg = NULL;
    const char *id = NULL;

    update_msg = create_xml_node(NULL, "notify");

    if (result_data != NULL) {
        id = crm_element_value(result_data, XML_ATTR_ID);
    }

    crm_xml_add(update_msg, F_TYPE, T_CIB_NOTIFY);
    crm_xml_add(update_msg, F_SUBTYPE, msg_type);
    crm_xml_add(update_msg, F_CIB_OPERATION, op);
    crm_xml_add_int(update_msg, F_CIB_RC, result);

    if (id != NULL) {
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

    attach_cib_generation(update_msg, "cib_generation", the_cib);
    if (update != NULL) {
        add_message_xml(update_msg, F_CIB_UPDATE, update);
    }
    if (result_data != NULL) {
        add_message_xml(update_msg, F_CIB_UPDATE_RESULT, result_data);
    }

    cib_notify_send(update_msg);
    free_xml(update_msg);
}

void
attach_cib_generation(xmlNode * msg, const char *field, xmlNode * a_cib)
{
    xmlNode *generation = create_xml_node(NULL, XML_CIB_TAG_GENERATION_TUPPLE);

    if (a_cib != NULL) {
        copy_in_properties(generation, a_cib);
    }
    add_message_xml(msg, field, generation);
    free_xml(generation);
}

void
cib_replace_notify(const char *origin, xmlNode * update, int result, xmlNode * diff, int change_section)
{
    xmlNode *replace_msg = NULL;

    int add_updates = 0;
    int add_epoch = 0;
    int add_admin_epoch = 0;

    int del_updates = 0;
    int del_epoch = 0;
    int del_admin_epoch = 0;

    if (diff == NULL) {
        return;
    }

    cib_diff_version_details(diff, &add_admin_epoch, &add_epoch, &add_updates,
                             &del_admin_epoch, &del_epoch, &del_updates);

    if (del_updates < 0) {
        crm_log_xml_debug(diff, "Bad replace diff");
    }

    if (add_updates != del_updates) {
        crm_info("Replaced: %d.%d.%d -> %d.%d.%d from %s",
                 del_admin_epoch, del_epoch, del_updates,
                 add_admin_epoch, add_epoch, add_updates,
                 pcmk__s(origin, "unspecified peer"));
    } else if (diff != NULL) {
        crm_info("Local-only Replace: %d.%d.%d from %s",
                 add_admin_epoch, add_epoch, add_updates,
                 pcmk__s(origin, "unspecified peer"));
    }

    replace_msg = create_xml_node(NULL, "notify-replace");
    crm_xml_add(replace_msg, F_TYPE, T_CIB_NOTIFY);
    crm_xml_add(replace_msg, F_SUBTYPE, T_CIB_REPLACE_NOTIFY);
    crm_xml_add(replace_msg, F_CIB_OPERATION, CIB_OP_REPLACE);
    crm_xml_add_int(replace_msg, F_CIB_RC, result);
    crm_xml_add_int(replace_msg, F_CIB_CHANGE_SECTION, change_section);
    attach_cib_generation(replace_msg, "cib-replace-generation", update);

    crm_log_xml_trace(replace_msg, "CIB Replaced");

    cib_notify_send(replace_msg);
    free_xml(replace_msg);
}
