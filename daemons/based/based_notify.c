/*
 * Copyright 2004-2023 the Pacemaker project contributors
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

#include <glib.h>
#include <libxml/tree.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>

#include <crm/common/xml.h>
#include <crm/common/remote_internal.h>
#include <pacemaker-based.h>

struct cib_notification_s {
    xmlNode *msg;
    struct iovec *iov;
    int32_t iov_size;
};

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

static void
attach_cib_generation(xmlNode *msg, const char *field, xmlNode *a_cib)
{
    xmlNode *generation = create_xml_node(NULL, XML_CIB_TAG_GENERATION_TUPPLE);

    if (a_cib != NULL) {
        copy_in_properties(generation, a_cib);
    }
    add_message_xml(msg, field, generation);
    free_xml(generation);
}

void
cib_diff_notify(const char *op, int result, const char *call_id,
                const char *client_id, const char *client_name,
                const char *origin, xmlNode *update, xmlNode *diff)
{
    int add_updates = 0;
    int add_epoch = 0;
    int add_admin_epoch = 0;

    int del_updates = 0;
    int del_epoch = 0;
    int del_admin_epoch = 0;

    uint8_t log_level = LOG_TRACE;

    xmlNode *update_msg = NULL;
    const char *type = NULL;

    if (diff == NULL) {
        return;
    }

    if (result != pcmk_ok) {
        log_level = LOG_WARNING;
    }

    cib_diff_version_details(diff, &add_admin_epoch, &add_epoch, &add_updates,
                             &del_admin_epoch, &del_epoch, &del_updates);

    if ((add_admin_epoch != del_admin_epoch)
        || (add_epoch != del_epoch)
        || (add_updates != del_updates)) {

        do_crm_log(log_level,
                   "Updated CIB generation %d.%d.%d to %d.%d.%d from client "
                   "%s%s%s (%s) (%s)",
                   del_admin_epoch, del_epoch, del_updates,
                   add_admin_epoch, add_epoch, add_updates,
                   client_name,
                   ((call_id != NULL)? " call " : ""), pcmk__s(call_id, ""),
                   pcmk__s(origin, "unspecified peer"), pcmk_strerror(result));

    } else if ((add_admin_epoch != 0)
               || (add_epoch != 0)
               || (add_updates != 0)) {

        do_crm_log(log_level,
                   "Local-only change to CIB generation %d.%d.%d from client "
                   "%s%s%s (%s) (%s)",
                   add_admin_epoch, add_epoch, add_updates,
                   client_name,
                   ((call_id != NULL)? " call " : ""), pcmk__s(call_id, ""),
                   pcmk__s(origin, "unspecified peer"), pcmk_strerror(result));
    }

    update_msg = create_xml_node(NULL, "notify");

    crm_xml_add(update_msg, F_TYPE, T_CIB_NOTIFY);
    crm_xml_add(update_msg, F_SUBTYPE, T_CIB_DIFF_NOTIFY);
    crm_xml_add(update_msg, F_CIB_OPERATION, op);
    crm_xml_add(update_msg, F_CIB_CLIENTID, client_id);
    crm_xml_add(update_msg, F_CIB_CALLID, call_id);
    crm_xml_add(update_msg, F_ORIG, origin);
    crm_xml_add_int(update_msg, F_CIB_RC, result);

    if (update != NULL) {
        type = (const char *) update->name;
        crm_trace("Setting type to update->name: %s", type);
    } else {
        type = (const char *) diff->name;
        crm_trace("Setting type to new_obj->name: %s", type);
    }
    crm_xml_add(update_msg, F_CIB_OBJID, ID(diff));
    crm_xml_add(update_msg, F_CIB_OBJTYPE, type);
    attach_cib_generation(update_msg, "cib_generation", the_cib);

    if (update != NULL) {
        add_message_xml(update_msg, F_CIB_UPDATE, update);
    }
    add_message_xml(update_msg, F_CIB_UPDATE_RESULT, diff);

    cib_notify_send(update_msg);
    free_xml(update_msg);
}

void
cib_replace_notify(const char *op, int result, const char *call_id,
                   const char *client_id, const char *client_name,
                   const char *origin, xmlNode *update, xmlNode *diff,
                   uint32_t change_section)
{
    xmlNode *replace_msg = NULL;

    int add_updates = 0;
    int add_epoch = 0;
    int add_admin_epoch = 0;

    int del_updates = 0;
    int del_epoch = 0;
    int del_admin_epoch = 0;

    uint8_t log_level = LOG_INFO;

    if (diff == NULL) {
        return;
    }

    if (result != pcmk_ok) {
        log_level = LOG_WARNING;
    }

    cib_diff_version_details(diff, &add_admin_epoch, &add_epoch, &add_updates,
                             &del_admin_epoch, &del_epoch, &del_updates);

    if (del_updates < 0) {
        crm_log_xml_debug(diff, "Bad replace diff");
    }

    if ((add_admin_epoch != del_admin_epoch)
        || (add_epoch != del_epoch)
        || (add_updates != del_updates)) {

        do_crm_log(log_level,
                   "Replaced CIB generation %d.%d.%d with %d.%d.%d from client "
                   "%s%s%s (%s) (%s)",
                   del_admin_epoch, del_epoch, del_updates,
                   add_admin_epoch, add_epoch, add_updates,
                   client_name,
                   ((call_id != NULL)? " call " : ""), pcmk__s(call_id, ""),
                   pcmk__s(origin, "unspecified peer"), pcmk_strerror(result));

    } else if ((add_admin_epoch != 0)
               || (add_epoch != 0)
               || (add_updates != 0)) {

        do_crm_log(log_level,
                   "Local-only replace of CIB generation %d.%d.%d from client "
                   "%s%s%s (%s) (%s)",
                   add_admin_epoch, add_epoch, add_updates,
                   client_name,
                   ((call_id != NULL)? " call " : ""), pcmk__s(call_id, ""),
                   pcmk__s(origin, "unspecified peer"), pcmk_strerror(result));
    }

    replace_msg = create_xml_node(NULL, "notify-replace");

    crm_xml_add(replace_msg, F_TYPE, T_CIB_NOTIFY);
    crm_xml_add(replace_msg, F_SUBTYPE, T_CIB_REPLACE_NOTIFY);
    crm_xml_add(replace_msg, F_CIB_OPERATION, op);
    crm_xml_add(replace_msg, F_CIB_CLIENTID, client_id);
    crm_xml_add(replace_msg, F_CIB_CALLID, call_id);
    crm_xml_add(replace_msg, F_ORIG, origin);
    crm_xml_add_int(replace_msg, F_CIB_RC, result);
    crm_xml_add_ll(replace_msg, F_CIB_CHANGE_SECTION,
                   (long long) change_section);
    attach_cib_generation(replace_msg, "cib-replace-generation", update);

    /* We can include update and diff if a replace callback needs them. Until
     * then, avoid the overhead.
     */

    crm_log_xml_trace(replace_msg, "CIB replaced");

    cib_notify_send(replace_msg);
    free_xml(replace_msg);
}
