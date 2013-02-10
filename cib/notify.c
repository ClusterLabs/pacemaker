/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <time.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>

#include <crm/common/xml.h>
#include <cibio.h>
#include <callbacks.h>
#include <notify.h>

int pending_updates = 0;

struct cib_notification_s
{
        xmlNode *msg;
        struct iovec *iov;
};

void attach_cib_generation(xmlNode * msg, const char *field, xmlNode * a_cib);

void do_cib_notify(int options, const char *op, xmlNode * update,
                   int result, xmlNode * result_data, const char *msg_type);

static void
need_pre_notify(gpointer key, gpointer value, gpointer user_data)
{
    crm_client_t *client = value;

    if (is_set(client->options, cib_notify_pre)) {
        gboolean *needed = user_data;

        *needed = TRUE;
    }
}

static void
need_post_notify(gpointer key, gpointer value, gpointer user_data)
{
    crm_client_t *client = value;

    if (is_set(client->options, cib_notify_post)) {
        gboolean *needed = user_data;

        *needed = TRUE;
    }
}

static gboolean
cib_notify_send_one(gpointer key, gpointer value, gpointer user_data)
{
    const char *type = NULL;
    gboolean do_send = FALSE;

    crm_client_t *client = value;
    struct cib_notification_s *update = user_data;

    CRM_CHECK(client != NULL, return TRUE);
    CRM_CHECK(update != NULL, return TRUE);

    if (client->ipcs == NULL && client->remote == NULL) {
        crm_warn("Skipping client with NULL channel");
        return FALSE;
    }

    type = crm_element_value(update->msg, F_SUBTYPE);

    CRM_LOG_ASSERT(type != NULL);
    if (is_set(client->options, cib_notify_diff) && safe_str_eq(type, T_CIB_DIFF_NOTIFY)) {
        do_send = TRUE;

    } else if (is_set(client->options, cib_notify_replace) && safe_str_eq(type, T_CIB_REPLACE_NOTIFY)) {
        do_send = TRUE;

    } else if (is_set(client->options, cib_notify_confirm) && safe_str_eq(type, T_CIB_UPDATE_CONFIRM)) {
        do_send = TRUE;

    } else if (is_set(client->options, cib_notify_pre) && safe_str_eq(type, T_CIB_PRE_NOTIFY)) {
        do_send = TRUE;

    } else if (is_set(client->options, cib_notify_post) && safe_str_eq(type, T_CIB_POST_NOTIFY)) {
        do_send = TRUE;
    }

    if (do_send) {
        switch(client->kind) {
            case CRM_CLIENT_IPC:
                if(crm_ipcs_sendv(client, update->iov, crm_ipc_server_event) < 0) {
                    crm_warn("Notification of client %s/%s failed", client->name, client->id);
                }
                break;
#  ifdef HAVE_GNUTLS_GNUTLS_H
            case CRM_CLIENT_TLS:
#  endif
            case CRM_CLIENT_TCP:
                crm_debug("Sent %s notification to client %s/%s", type, client->name, client->id);
                crm_remote_send(client->remote, update->msg);
                break;
            default:
                crm_err("Unknown transport %d for %s", client->kind, client->name);
        }
    }
    return FALSE;
}

static void cib_notify_send(xmlNode *xml)
{
    struct iovec *iov;
    struct cib_notification_s update;

    ssize_t rc = crm_ipcs_prepare(0, xml, &iov);

    crm_trace("Notifying clients");

    if(rc > 0) {
        update.msg = xml;
        update.iov = iov;
        g_hash_table_foreach_remove(client_connections, cib_notify_send_one, &update);

    } else {
        crm_notice("Notification failed: %s (%d)", pcmk_strerror(rc), rc);
    }

    if(iov) {
        free(iov[0].iov_base);
        free(iov[1].iov_base);
        free(iov);
    }

    crm_trace("Notify complete");
}

void
cib_pre_notify(int options, const char *op, xmlNode * existing, xmlNode * update)
{
    xmlNode *update_msg = NULL;
    const char *type = NULL;
    const char *id = NULL;
    gboolean needed = FALSE;

    g_hash_table_foreach(client_connections, need_pre_notify, &needed);
    if (needed == FALSE) {
        return;
    }

    /* TODO: consider pre-notification for removal */
    update_msg = create_xml_node(NULL, "pre-notify");

    if (update != NULL) {
        id = crm_element_value(update, XML_ATTR_ID);
    }

    crm_xml_add(update_msg, F_TYPE, T_CIB_NOTIFY);
    crm_xml_add(update_msg, F_SUBTYPE, T_CIB_PRE_NOTIFY);
    crm_xml_add(update_msg, F_CIB_OPERATION, op);

    if (id != NULL) {
        crm_xml_add(update_msg, F_CIB_OBJID, id);
    }

    if (update != NULL) {
        crm_xml_add(update_msg, F_CIB_OBJTYPE, crm_element_name(update));
    } else if (existing != NULL) {
        crm_xml_add(update_msg, F_CIB_OBJTYPE, crm_element_name(existing));
    }

    type = crm_element_value(update_msg, F_CIB_OBJTYPE);
    attach_cib_generation(update_msg, "cib_generation", the_cib);

    if (existing != NULL) {
        add_message_xml(update_msg, F_CIB_EXISTING, existing);
    }
    if (update != NULL) {
        add_message_xml(update_msg, F_CIB_UPDATE, update);
    }

    cib_notify_send(update_msg);

    if (update == NULL) {
        crm_trace("Performing operation %s (on section=%s)", op, type);

    } else {
        crm_trace("Performing %s on <%s%s%s>", op, type, id ? " id=" : "", id ? id : "");
    }

    free_xml(update_msg);
}

void
cib_post_notify(int options, const char *op, xmlNode * update,
                int result, xmlNode * new_obj)
{
    gboolean needed = FALSE;

    g_hash_table_foreach(client_connections, need_post_notify, &needed);
    if (needed == FALSE) {
        return;
    }

    do_cib_notify(options, op, update, result, new_obj, T_CIB_UPDATE_CONFIRM);
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

    int log_level = LOG_DEBUG_2;

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

void
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
cib_replace_notify(const char *origin, xmlNode * update, int result, xmlNode * diff)
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

    if(del_updates < 0) {
        crm_log_xml_debug(diff, "Bad replace diff");
    }

    if (add_updates != del_updates) {
        crm_info("Replaced: %d.%d.%d -> %d.%d.%d from %s",
                 del_admin_epoch, del_epoch, del_updates,
                 add_admin_epoch, add_epoch, add_updates, crm_str(origin));
    } else if (diff != NULL) {
        crm_info("Local-only Replace: %d.%d.%d from %s",
                 add_admin_epoch, add_epoch, add_updates, crm_str(origin));
    }

    replace_msg = create_xml_node(NULL, "notify-replace");
    crm_xml_add(replace_msg, F_TYPE, T_CIB_NOTIFY);
    crm_xml_add(replace_msg, F_SUBTYPE, T_CIB_REPLACE_NOTIFY);
    crm_xml_add(replace_msg, F_CIB_OPERATION, CIB_OP_REPLACE);
    crm_xml_add_int(replace_msg, F_CIB_RC, result);
    attach_cib_generation(replace_msg, "cib-replace-generation", update);

    crm_log_xml_trace(replace_msg, "CIB Replaced");

    cib_notify_send(replace_msg);
    free_xml(replace_msg);
}
