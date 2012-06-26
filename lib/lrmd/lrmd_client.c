/*
 * Copyright (c) 2012 David Vossel <dvossel@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <crm_internal.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <glib.h>
#include <dirent.h>

#include <crm/crm.h>
#include <crm/lrmd.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>
#include <crm/msg_xml.h>

#include <crm/stonith-ng.h>

CRM_TRACE_INIT_DATA(lrmd);

static stonith_t *stonith_api = NULL;
typedef struct lrmd_key_value_s {
    char *key;
    char *value;
    struct lrmd_key_value_s *next;
} lrmd_key_value_t;

typedef struct lrmd_private_s {
    int call_id;

    char *token;
    crm_ipc_t *ipc;
    mainloop_io_t *source;

    lrmd_event_callback callback;

} lrmd_private_t;

static lrmd_list_t *
lrmd_list_add(lrmd_list_t * head, const char *value)
{
    lrmd_list_t *p, *end;

    p = calloc(1, sizeof(lrmd_list_t));
    p->val = crm_strdup(value);

    end = head;
    while (end && end->next) {
        end = end->next;
    }

    if (end) {
        end->next = p;
    } else {
        head = p;
    }

    return head;
}

void
lrmd_list_freeall(lrmd_list_t * head)
{
    lrmd_list_t *p;

    while (head) {
        char *val = (char *)head->val;

        p = head->next;
        free(val);
        free(head);
        head = p;
    }
}

lrmd_key_value_t *
lrmd_key_value_add(lrmd_key_value_t * head, const char *key, const char *value)
{
    lrmd_key_value_t *p, *end;

    p = calloc(1, sizeof(lrmd_key_value_t));
    p->key = crm_strdup(key);
    p->value = crm_strdup(value);

    end = head;
    while (end && end->next) {
        end = end->next;
    }

    if (end) {
        end->next = p;
    } else {
        head = p;
    }

    return head;
}

static void
lrmd_key_value_freeall(lrmd_key_value_t * head)
{
    lrmd_key_value_t *p;

    while (head) {
        p = head->next;
        free(head->key);
        free(head->value);
        free(head);
        head = p;
    }
}

static void
dup_attr(gpointer key, gpointer value, gpointer user_data)
{
    g_hash_table_replace(user_data, crm_strdup(key), crm_strdup(value));
}

lrmd_event_data_t *
lrmd_copy_event(lrmd_event_data_t * event)
{
    lrmd_event_data_t *copy = NULL;

    copy = calloc(1, sizeof(lrmd_event_data_t));

    /* This will get all the int values.
     * we just have to be careful not to leave any
     * dangling pointers to strings. */
    memcpy(copy, event, sizeof(lrmd_event_data_t));

    copy->rsc_id = event->rsc_id ? crm_strdup(event->rsc_id) : NULL;
    copy->op_type = event->op_type ? crm_strdup(event->op_type) : NULL;
    copy->user_data = event->user_data ? crm_strdup(event->user_data) : NULL;
    copy->output = event->output ? crm_strdup(event->output) : NULL;

    if (event->params) {
        copy->params = g_hash_table_new_full(crm_str_hash,
                                             g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

        if (copy->params != NULL) {
            g_hash_table_foreach(event->params, dup_attr, copy->params);
        }
    }

    return copy;
}

void
lrmd_free_event(lrmd_event_data_t * event)
{
    if (!event) {
        return;
    }

    /* free gives me grief if i try to cast */
    free((char *)event->rsc_id);
    free((char *)event->op_type);
    free((char *)event->user_data);
    free((char *)event->output);
    if (event->params) {
        g_hash_table_destroy(event->params);
    }
    free(event);
}

static int
lrmd_dispatch_internal(const char *buffer, ssize_t length, gpointer userdata)
{
    const char *type;
    lrmd_t *lrmd = userdata;
    lrmd_private_t *native = lrmd->private;
    lrmd_event_data_t event = { 0, };
    xmlNode *msg;

    if (!native->callback) {
        /* no callback set */
        return 1;
    }

    msg = string2xml(buffer);
    type = crm_element_value(msg, F_LRMD_OPERATION);
    crm_element_value_int(msg, F_LRMD_CALLID, &event.call_id);
    event.rsc_id = crm_element_value(msg, F_LRMD_RSC_ID);

    if (crm_str_eq(type, LRMD_OP_RSC_REG, TRUE)) {
        event.type = lrmd_event_register;
    } else if (crm_str_eq(type, LRMD_OP_RSC_UNREG, TRUE)) {
        event.type = lrmd_event_unregister;
    } else if (crm_str_eq(type, LRMD_OP_RSC_EXEC, TRUE)) {
        crm_element_value_int(msg, F_LRMD_TIMEOUT, &event.timeout);
        crm_element_value_int(msg, F_LRMD_RSC_INTERVAL, &event.interval);
        crm_element_value_int(msg, F_LRMD_RSC_START_DELAY, &event.start_delay);
        crm_element_value_int(msg, F_LRMD_EXEC_RC, (int *)&event.rc);
        crm_element_value_int(msg, F_LRMD_OP_STATUS, &event.op_status);
        crm_element_value_int(msg, F_LRMD_RSC_DELETED, &event.rsc_deleted);

        crm_element_value_int(msg, F_LRMD_RSC_RUN_TIME, (int *)&event.t_run);
        crm_element_value_int(msg, F_LRMD_RSC_RCCHANGE_TIME, (int *)&event.t_rcchange);
        crm_element_value_int(msg, F_LRMD_RSC_EXEC_TIME, (int *)&event.exec_time);
        crm_element_value_int(msg, F_LRMD_RSC_QUEUE_TIME, (int *)&event.queue_time);

        event.op_type = crm_element_value(msg, F_LRMD_RSC_ACTION);
        event.user_data = crm_element_value(msg, F_LRMD_RSC_USERDATA_STR);
        event.output = crm_element_value(msg, F_LRMD_RSC_OUTPUT);
        event.type = lrmd_event_exec_complete;

        event.params = xml2list(msg);
    }

    native->callback(&event);

    if (event.params) {
        g_hash_table_destroy(event.params);
    }
    free_xml(msg);
    return 1;
}

/* Not used with mainloop */
bool
lrmd_dispatch(lrmd_t * lrmd)
{
    gboolean stay_connected = TRUE;
    lrmd_private_t *private = NULL;

    CRM_ASSERT(lrmd != NULL);
    private = lrmd->private;

    while (crm_ipc_ready(private->ipc)) {
        if (crm_ipc_read(private->ipc) > 0) {
            const char *msg = crm_ipc_buffer(private->ipc);

            lrmd_dispatch_internal(msg, strlen(msg), lrmd);
        }
        if (crm_ipc_connected(private->ipc) == FALSE) {
            crm_err("Connection closed");
            stay_connected = FALSE;
        }
    }

    return stay_connected;
}

static xmlNode *
lrmd_create_op(int call_id,
               const char *token, const char *op, xmlNode * data, enum lrmd_call_options options)
{
    xmlNode *op_msg = create_xml_node(NULL, "lrmd_command");

    CRM_CHECK(op_msg != NULL, return NULL);
    CRM_CHECK(token != NULL, return NULL);

    crm_xml_add(op_msg, F_XML_TAGNAME, "lrmd_command");

    crm_xml_add(op_msg, F_TYPE, T_LRMD);
    crm_xml_add(op_msg, F_LRMD_CALLBACK_TOKEN, token);
    crm_xml_add(op_msg, F_LRMD_OPERATION, op);
    crm_xml_add_int(op_msg, F_LRMD_CALLID, call_id);
    crm_trace("Sending call options: %.8lx, %d", (long)options, options);
    crm_xml_add_int(op_msg, F_LRMD_CALLOPTS, options);

    if (data != NULL) {
        add_message_xml(op_msg, F_LRMD_CALLDATA, data);
    }

    return op_msg;
}

static void
lrmd_connection_destroy(gpointer userdata)
{
    lrmd_t *lrmd = userdata;
    lrmd_private_t *native = lrmd->private;

    crm_info("connection destroyed");
    if (native->callback) {
        lrmd_event_data_t event = { 0, };
        event.type = lrmd_event_disconnect;
        native->callback(&event);
    }
}

static int
lrmd_send_command(lrmd_t * lrmd, const char *op, xmlNode * data, xmlNode ** output_data, int timeout,   /* ms. defaults to 1000 if set to 0 */
                  enum lrmd_call_options options)
{
    int rc = lrmd_ok;
    int reply_id = -1;
    lrmd_private_t *native = lrmd->private;
    xmlNode *op_msg = NULL;
    xmlNode *op_reply = NULL;

    if (!native->ipc) {
        return lrmd_err_connection;
    }

    if (op == NULL) {
        crm_err("No operation specified");
        return lrmd_err_missing;
    }

    native->call_id++;
    if (native->call_id < 1) {
        native->call_id = 1;
    }

    CRM_CHECK(native->token != NULL,;);

    op_msg = lrmd_create_op(native->call_id, native->token, op, data, options);

    if (op_msg == NULL) {
        return lrmd_err_missing;
    }

    crm_xml_add_int(op_msg, F_LRMD_TIMEOUT, timeout);

    rc = crm_ipc_send(native->ipc, op_msg, &op_reply, timeout);
    free_xml(op_msg);

    if (rc < 0) {
        crm_perror(LOG_ERR, "Couldn't perform %s operation (timeout=%d): %d", op, timeout, rc);
        rc = lrmd_err_ipc;
        goto done;
    }

    rc = lrmd_ok;
    crm_element_value_int(op_reply, F_LRMD_CALLID, &reply_id);
    if (reply_id == native->call_id) {
        crm_trace("reply received");
        if (crm_element_value_int(op_reply, F_LRMD_RC, &rc) != 0) {
            rc = lrmd_err_peer;
            goto done;
        }

        if (output_data) {
            *output_data = op_reply;
            op_reply = NULL;    /* Prevent subsequent free */
        }

    } else if (reply_id <= 0) {
        crm_err("Recieved bad reply: No id set");
        crm_log_xml_err(op_reply, "Bad reply");
        rc = lrmd_err_peer;
    } else {
        crm_err("Recieved bad reply: %d (wanted %d)", reply_id, native->call_id);
        crm_log_xml_err(op_reply, "Old reply");
        rc = lrmd_err_peer;
    }

    crm_log_xml_trace(op_reply, "Reply");

  done:
    if (crm_ipc_connected(native->ipc) == FALSE) {
        crm_err("LRMD disconnected");
    }

    free_xml(op_reply);
    return rc;
}

static int
lrmd_api_connect(lrmd_t * lrmd, const char *name, int *fd)
{
    int rc = lrmd_ok;
    lrmd_private_t *native = lrmd->private;

    static struct ipc_client_callbacks lrmd_callbacks = {
        .dispatch = lrmd_dispatch_internal,
        .destroy = lrmd_connection_destroy
    };

    crm_info("Connecting to lrmd");

    if (fd) {
        /* No mainloop */
        native->ipc = crm_ipc_new("lrmd", 0);
        if (native->ipc && crm_ipc_connect(native->ipc)) {
            *fd = crm_ipc_get_fd(native->ipc);
        } else if (native->ipc) {
            rc = lrmd_err_connection;
        }
    } else {
        native->source = mainloop_add_ipc_client("lrmd", 0, lrmd, &lrmd_callbacks);
        native->ipc = mainloop_get_ipc_client(native->source);
    }

    if (native->ipc == NULL) {
        crm_debug("Could not connect to the LRMD API");
        rc = lrmd_err_connection;
    }

    if (!rc) {
        xmlNode *reply = NULL;
        xmlNode *hello = create_xml_node(NULL, "lrmd_command");

        crm_xml_add(hello, F_TYPE, T_LRMD);
        crm_xml_add(hello, F_LRMD_OPERATION, CRM_OP_REGISTER);
        crm_xml_add(hello, F_LRMD_CLIENTNAME, name);

        rc = crm_ipc_send(native->ipc, hello, &reply, -1);

        if (rc < 0) {
            crm_perror(LOG_DEBUG, "Couldn't complete registration with the lrmd API: %d", rc);
            rc = lrmd_err_ipc;
        } else if (reply == NULL) {
            crm_err("Did not receive registration reply");
            rc = lrmd_err_internal;
        } else {
            const char *msg_type = crm_element_value(reply, F_LRMD_OPERATION);
            const char *tmp_ticket = crm_element_value(reply, F_LRMD_CLIENTID);

            if (safe_str_neq(msg_type, CRM_OP_REGISTER)) {
                crm_err("Invalid registration message: %s", msg_type);
                crm_log_xml_err(reply, "Bad reply");
                rc = lrmd_err_internal;
            } else if (tmp_ticket == NULL) {
                crm_err("No registration token provided");
                crm_log_xml_err(reply, "Bad reply");
                rc = lrmd_err_internal;
            } else {
                crm_trace("Obtained registration token: %s", tmp_ticket);
                native->token = crm_strdup(tmp_ticket);
                rc = lrmd_ok;
            }
        }

        free_xml(reply);
        free_xml(hello);
    }

    return rc;
}

static int
lrmd_api_disconnect(lrmd_t * lrmd)
{
    lrmd_private_t *native = lrmd->private;

    crm_info("Disconnecting from lrmd service");

    if (native->source) {
        mainloop_del_ipc_client(native->source);
        native->source = NULL;
        native->ipc = NULL;
    } else if (native->ipc) {
        crm_ipc_close(native->ipc);
        crm_ipc_destroy(native->ipc);
        native->source = NULL;
        native->ipc = NULL;
    }

    free(native->token);
    native->token = NULL;
    return 0;
}

static int
lrmd_api_register_rsc(lrmd_t * lrmd,
                      const char *rsc_id,
                      const char *class,
                      const char *provider, const char *type, enum lrmd_call_options options)
{
    int rc = lrmd_ok;
    xmlNode *data = NULL;

    if (!class || !type || !rsc_id) {
        return lrmd_err_missing;
    }
    if (safe_str_eq(class, "ocf") && !provider) {
        return lrmd_err_provider_required;
    }

    data = create_xml_node(NULL, F_LRMD_RSC);

    crm_xml_add(data, F_LRMD_ORIGIN, __FUNCTION__);
    crm_xml_add(data, F_LRMD_RSC_ID, rsc_id);
    crm_xml_add(data, F_LRMD_CLASS, class);
    crm_xml_add(data, F_LRMD_PROVIDER, provider);
    crm_xml_add(data, F_LRMD_TYPE, type);
    rc = lrmd_send_command(lrmd, LRMD_OP_RSC_REG, data, NULL, 0, options);
    free_xml(data);

    return rc;
}

static int
lrmd_api_unregister_rsc(lrmd_t * lrmd, const char *rsc_id, enum lrmd_call_options options)
{
    int rc = lrmd_ok;
    xmlNode *data = create_xml_node(NULL, F_LRMD_RSC);

    crm_xml_add(data, F_LRMD_ORIGIN, __FUNCTION__);
    crm_xml_add(data, F_LRMD_RSC_ID, rsc_id);
    rc = lrmd_send_command(lrmd, LRMD_OP_RSC_UNREG, data, NULL, 0, options);
    free_xml(data);

    return rc;
}

lrmd_rsc_info_t *
lrmd_copy_rsc_info(lrmd_rsc_info_t * rsc_info)
{
    lrmd_rsc_info_t *copy = NULL;

    copy = calloc(1, sizeof(lrmd_rsc_info_t));

    copy->id = crm_strdup(rsc_info->id);
    copy->type = crm_strdup(rsc_info->type);
    copy->class = crm_strdup(rsc_info->class);
    if (rsc_info->provider) {
        copy->provider = crm_strdup(rsc_info->provider);
    }

    return copy;
}

void
lrmd_free_rsc_info(lrmd_rsc_info_t * rsc_info)
{
    if (!rsc_info) {
        return;
    }
    free(rsc_info->id);
    free(rsc_info->type);
    free(rsc_info->class);
    free(rsc_info->provider);
    free(rsc_info);
}

static lrmd_rsc_info_t *
lrmd_api_get_rsc_info(lrmd_t * lrmd, const char *rsc_id, enum lrmd_call_options options)
{
    int rc = lrmd_ok;
    lrmd_rsc_info_t *rsc_info = NULL;
    xmlNode *data = create_xml_node(NULL, F_LRMD_RSC);
    xmlNode *output = NULL;
    const char *class = NULL;
    const char *provider = NULL;
    const char *type = NULL;

    crm_xml_add(data, F_LRMD_ORIGIN, __FUNCTION__);
    crm_xml_add(data, F_LRMD_RSC_ID, rsc_id);
    rc = lrmd_send_command(lrmd, LRMD_OP_RSC_INFO, data, &output, 0, options);
    free_xml(data);

    class = crm_element_value(output, F_LRMD_CLASS);
    provider = crm_element_value(output, F_LRMD_PROVIDER);
    type = crm_element_value(output, F_LRMD_TYPE);

    if (!output) {
        return NULL;
    } else if (!class || !type) {
        free_xml(output);
        return NULL;
    } else if (safe_str_eq(class, "ocf") && !provider) {
        free_xml(output);
        return NULL;
    }

    rsc_info = calloc(1, sizeof(lrmd_rsc_info_t));
    rsc_info->id = crm_strdup(rsc_id);
    rsc_info->class = crm_strdup(class);
    if (provider) {
        rsc_info->provider = crm_strdup(provider);
    }
    rsc_info->type = crm_strdup(type);

    free_xml(output);
    return rsc_info;
}

static void
lrmd_api_set_callback(lrmd_t * lrmd, lrmd_event_callback callback)
{
    lrmd_private_t *native = lrmd->private;

    native->callback = callback;
}

static int
stonith_get_metadata(const char *provider, const char *type, char **output)
{
    int rc = lrmd_ok;

    stonith_api->cmds->metadata(stonith_api, st_opt_sync_call, type, provider, output, 0);
    if (*output == NULL) {
        rc = lrmd_err_no_metadata;
    }
    return rc;
}

static int
lsb_get_metadata(const char *type, char **output)
{

#define lsb_metadata_template  \
"<?xml version=\"1.0\"?>\n"\
"<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"\
"<resource-agent name=\"%s\" version=\"0.1\">\n"\
"  <version>1.0</version>\n"\
"  <longdesc lang=\"en\">\n"\
"    %s"\
"  </longdesc>\n"\
"  <shortdesc lang=\"en\">%s</shortdesc>\n"\
"  <parameters>\n"\
"  </parameters>\n"\
"  <actions>\n"\
"    <action name=\"start\"   timeout=\"15\" />\n"\
"    <action name=\"stop\"    timeout=\"15\" />\n"\
"    <action name=\"status\"  timeout=\"15\" />\n"\
"    <action name=\"restart\"  timeout=\"15\" />\n"\
"    <action name=\"force-reload\"  timeout=\"15\" />\n"\
"    <action name=\"monitor\" timeout=\"15\" interval=\"15\" />\n"\
"    <action name=\"meta-data\"  timeout=\"5\" />\n"\
"  </actions>\n"\
"  <special tag=\"LSB\">\n"\
"    <Provides>%s</Provides>\n"\
"    <Required-Start>%s</Required-Start>\n"\
"    <Required-Stop>%s</Required-Stop>\n"\
"    <Should-Start>%s</Should-Start>\n"\
"    <Should-Stop>%s</Should-Stop>\n"\
"    <Default-Start>%s</Default-Start>\n"\
"    <Default-Stop>%s</Default-Stop>\n"\
"  </special>\n"\
"</resource-agent>\n"

#define LSB_INITSCRIPT_INFOBEGIN_TAG "### BEGIN INIT INFO"
#define LSB_INITSCRIPT_INFOEND_TAG "### END INIT INFO"
#define PROVIDES    "# Provides:"
#define REQ_START   "# Required-Start:"
#define REQ_STOP    "# Required-Stop:"
#define SHLD_START  "# Should-Start:"
#define SHLD_STOP   "# Should-Stop:"
#define DFLT_START  "# Default-Start:"
#define DFLT_STOP   "# Default-Stop:"
#define SHORT_DSCR  "# Short-Description:"
#define DESCRIPTION "# Description:"

#define lsb_meta_helper_free_value(m)				\
	if ((m) != NULL) {		\
		xmlFree(m);		\
		(m) = NULL;		\
	}

#define lsb_meta_helper_get_value(buffer, ptr, keyword)	\
	if (!ptr && !strncasecmp(buffer, keyword, strlen(keyword))) { \
		(ptr) = (char *)xmlEncodeEntitiesReentrant(NULL, BAD_CAST buffer+strlen(keyword)); \
		continue; \
	}

    char ra_pathname[PATH_MAX] = { 0, };
    FILE *fp;
    GString *meta_data = NULL;
    char buffer[1024];
    char *provides = NULL;
    char *req_start = NULL;
    char *req_stop = NULL;
    char *shld_start = NULL;
    char *shld_stop = NULL;
    char *dflt_start = NULL;
    char *dflt_stop = NULL;
    char *s_dscrpt = NULL;
    char *xml_l_dscrpt = NULL;
    GString *l_dscrpt = NULL;

    snprintf(ra_pathname, sizeof(ra_pathname), "%s%s%s",
             type[0] == '/' ? "" : LSB_ROOT_DIR, type[0] == '/' ? "" : "/", type);

    if (!(fp = fopen(ra_pathname, "r"))) {
        return lrmd_err_no_metadata;
    }

    /* Enter into the lsb-compliant comment block */
    while (fgets(buffer, sizeof(buffer), fp)) {
        /* Now suppose each of the following eight arguments contain only one line */
        lsb_meta_helper_get_value(buffer, provides, PROVIDES)
            lsb_meta_helper_get_value(buffer, req_start, REQ_START)
            lsb_meta_helper_get_value(buffer, req_stop, REQ_STOP)
            lsb_meta_helper_get_value(buffer, shld_start, SHLD_START)
            lsb_meta_helper_get_value(buffer, shld_stop, SHLD_STOP)
            lsb_meta_helper_get_value(buffer, dflt_start, DFLT_START)
            lsb_meta_helper_get_value(buffer, dflt_stop, DFLT_STOP)
            lsb_meta_helper_get_value(buffer, s_dscrpt, SHORT_DSCR)

            /* Long description may cross multiple lines */
            if ((l_dscrpt == NULL) && (0 == strncasecmp(buffer, DESCRIPTION, strlen(DESCRIPTION)))) {
            l_dscrpt = g_string_new(buffer + strlen(DESCRIPTION));
            /* Between # and keyword, more than one space, or a tab character,
             * indicates the continuation line.     Extracted from LSB init script standard */
            while (fgets(buffer, sizeof(buffer), fp)) {
                if (!strncmp(buffer, "#  ", 3) || !strncmp(buffer, "#\t", 2)) {
                    buffer[0] = ' ';
                    l_dscrpt = g_string_append(l_dscrpt, buffer);
                } else {
                    fputs(buffer, fp);
                    break;      /* Long description ends */
                }
            }
            continue;
        }
        if (l_dscrpt) {
            xml_l_dscrpt = (char *)xmlEncodeEntitiesReentrant(NULL, BAD_CAST(l_dscrpt->str));
        }
        if (!strncasecmp(buffer, LSB_INITSCRIPT_INFOEND_TAG, strlen(LSB_INITSCRIPT_INFOEND_TAG))) {
            /* Get to the out border of LSB comment block */
            break;
        }
        if (buffer[0] != '#') {
            break;              /* Out of comment block in the beginning */
        }
    }
    fclose(fp);

    meta_data = g_string_new("");
    g_string_sprintf(meta_data, lsb_metadata_template, type,
                     (xml_l_dscrpt == NULL) ? type : xml_l_dscrpt,
                     (s_dscrpt == NULL) ? type : s_dscrpt, (provides == NULL) ? "" : provides,
                     (req_start == NULL) ? "" : req_start, (req_stop == NULL) ? "" : req_stop,
                     (shld_start == NULL) ? "" : shld_start, (shld_stop == NULL) ? "" : shld_stop,
                     (dflt_start == NULL) ? "" : dflt_start, (dflt_stop == NULL) ? "" : dflt_stop);

    lsb_meta_helper_free_value(xml_l_dscrpt);
    lsb_meta_helper_free_value(s_dscrpt);
    lsb_meta_helper_free_value(provides);
    lsb_meta_helper_free_value(req_start);
    lsb_meta_helper_free_value(req_stop);
    lsb_meta_helper_free_value(shld_start);
    lsb_meta_helper_free_value(shld_stop);
    lsb_meta_helper_free_value(dflt_start);
    lsb_meta_helper_free_value(dflt_stop);

    if (l_dscrpt) {
        g_string_free(l_dscrpt, TRUE);
    }

    *output = crm_strdup(meta_data->str);
    g_string_free(meta_data, TRUE);

    return lrmd_ok;
}

static int
generic_get_metadata(const char *standard, const char *provider, const char *type, char **output)
{
    svc_action_t *action = resources_action_create(type,
                                                   standard,
                                                   provider,
                                                   type,
                                                   "meta-data",
                                                   0,
                                                   5000,
                                                   NULL);

    if (!(services_action_sync(action))) {
        crm_err("Failed to retrieve meta-data for %s:%s:%s", standard, provider, type);
        services_action_free(action);
        return lrmd_err_no_metadata;
    }

    if (!action->stdout_data) {
        crm_err("Failed to retrieve meta-data for %s:%s:%s", standard, provider, type);
        services_action_free(action);
        return lrmd_err_no_metadata;
    }

    *output = crm_strdup(action->stdout_data);
    services_action_free(action);

    return lrmd_ok;
}

static int
lrmd_api_get_metadata(lrmd_t * lrmd,
                      const char *class,
                      const char *provider,
                      const char *type, char **output, enum lrmd_call_options options)
{
    if (!class || !type) {
        return lrmd_err_missing;
    }

    if (safe_str_eq(class, "stonith")) {
        return stonith_get_metadata(provider, type, output);
    } else if (safe_str_eq(class, "lsb")) {
        return lsb_get_metadata(type, output);
    }
    return generic_get_metadata(class, provider, type, output);
}

static int
lrmd_api_exec(lrmd_t * lrmd, const char *rsc_id, const char *action, const char *userdata, int interval,        /* ms */
              int timeout,      /* ms */
              int start_delay,  /* ms */
              enum lrmd_call_options options, lrmd_key_value_t * params)
{
    int rc = lrmd_ok;
    xmlNode *data = create_xml_node(NULL, F_LRMD_RSC);
    xmlNode *args = create_xml_node(data, XML_TAG_ATTRS);

    crm_xml_add(data, F_LRMD_ORIGIN, __FUNCTION__);
    crm_xml_add(data, F_LRMD_RSC_ID, rsc_id);
    crm_xml_add(data, F_LRMD_RSC_ACTION, action);
    crm_xml_add(data, F_LRMD_RSC_USERDATA_STR, userdata);
    crm_xml_add_int(data, F_LRMD_RSC_INTERVAL, interval);
    crm_xml_add_int(data, F_LRMD_TIMEOUT, timeout);
    crm_xml_add_int(data, F_LRMD_RSC_START_DELAY, start_delay);

    for (; params; params = params->next) {
        hash2field((gpointer) params->key, (gpointer) params->value, args);
    }

    rc = lrmd_send_command(lrmd, LRMD_OP_RSC_EXEC, data, NULL, timeout, options);
    free_xml(data);

    lrmd_key_value_freeall(params);
    return rc;
}

static int
lrmd_api_cancel(lrmd_t * lrmd, const char *rsc_id, const char *action, int interval)
{
    int rc = lrmd_ok;
    xmlNode *data = create_xml_node(NULL, F_LRMD_RSC);

    crm_xml_add(data, F_LRMD_ORIGIN, __FUNCTION__);
    crm_xml_add(data, F_LRMD_RSC_ACTION, action);
    crm_xml_add(data, F_LRMD_RSC_ID, rsc_id);
    crm_xml_add_int(data, F_LRMD_RSC_INTERVAL, interval);
    rc = lrmd_send_command(lrmd, LRMD_OP_RSC_CANCEL, data, NULL, 0, 0);
    free_xml(data);
    return rc;
}

static int
list_stonith_agents(lrmd_list_t ** resources)
{
    int rc = 0;
    stonith_key_value_t *stonith_resources = NULL;
    stonith_key_value_t *dIter = NULL;

    stonith_api->cmds->list(stonith_api, st_opt_sync_call, NULL, &stonith_resources, 0);

    for (dIter = stonith_resources; dIter; dIter = dIter->next) {
        rc++;
        *resources = lrmd_list_add(*resources, dIter->value);
    }

    stonith_key_value_freeall(stonith_resources, 1, 0);
    return rc;
}

static int
list_lsb_agents(lrmd_list_t ** resources)
{
    int rc = 0;
    GListPtr gIter = NULL;
    GList *agents = NULL;

    agents = resources_list_agents("lsb", NULL);
    for (gIter = agents; gIter != NULL; gIter = gIter->next) {
        *resources = lrmd_list_add(*resources, (const char *)gIter->data);
        rc++;
    }
    g_list_free_full(agents, free);
    return rc;
}

static int
list_service_agents(lrmd_list_t ** resources)
{
    int rc = 0;
    GListPtr gIter = NULL;
    GList *agents = NULL;

    agents = resources_list_agents("service", NULL);
    for (gIter = agents; gIter != NULL; gIter = gIter->next) {
        *resources = lrmd_list_add(*resources, (const char *)gIter->data);
        rc++;
    }
    g_list_free_full(agents, free);
    return rc;
}

static int
list_systemd_agents(lrmd_list_t ** resources)
{
    int rc = 0;
    GListPtr gIter = NULL;
    GList *agents = NULL;

    agents = resources_list_agents("systemd", NULL);
    for (gIter = agents; gIter != NULL; gIter = gIter->next) {
        *resources = lrmd_list_add(*resources, (const char *)gIter->data);
        rc++;
    }
    g_list_free_full(agents, free);
    return rc;
}

static int
list_upstart_agents(lrmd_list_t ** resources)
{
    int rc = 0;
    GListPtr gIter = NULL;
    GList *agents = NULL;

    agents = resources_list_agents("upstart", NULL);
    for (gIter = agents; gIter != NULL; gIter = gIter->next) {
        *resources = lrmd_list_add(*resources, (const char *)gIter->data);
        rc++;
    }
    g_list_free_full(agents, free);
    return rc;
}

static int
list_ocf_agents(lrmd_list_t ** resources, const char *list_provider)
{
    int rc = 0;
    char *provider = NULL;
    GList *ocf_providers = NULL;
    GList *agents = NULL;
    GListPtr gIter = NULL;
    GListPtr gIter2 = NULL;

    ocf_providers = resources_list_providers("ocf");

    for (gIter = ocf_providers; gIter != NULL; gIter = gIter->next) {
        provider = gIter->data;

        if (list_provider && !safe_str_eq(list_provider, provider)) {
            continue;
        }
        agents = resources_list_agents("ocf", provider);
        for (gIter2 = agents; gIter2 != NULL; gIter2 = gIter2->next) {
            *resources = lrmd_list_add(*resources, (const char *)gIter2->data);
            rc++;
        }
        g_list_free_full(agents, free);
    }

    g_list_free_full(ocf_providers, free);
    return rc;
}

static int
lrmd_api_list_agents(lrmd_t * lrmd, lrmd_list_t ** resources, const char *class,
                     const char *provider)
{
    int rc = lrmd_ok;

    if (safe_str_eq(class, "ocf")) {
        rc += list_ocf_agents(resources, provider);
    } else if (safe_str_eq(class, "lsb")) {
        rc += list_lsb_agents(resources);
    } else if (safe_str_eq(class, "systemd")) {
        rc += list_systemd_agents(resources);
    } else if (safe_str_eq(class, "upstart")) {
        rc += list_upstart_agents(resources);
    } else if (safe_str_eq(class, "service")) {
        rc += list_service_agents(resources);
    } else if (safe_str_eq(class, "stonith")) {
        rc += list_stonith_agents(resources);
    } else if (!class) {
        rc += list_ocf_agents(resources, provider);
        rc += list_systemd_agents(resources);
        rc += list_upstart_agents(resources);
        rc += list_lsb_agents(resources);
        rc += list_stonith_agents(resources);
    } else {
        crm_err("Unknown class %s", class);
        rc = lrmd_err_generic;
    }

    return rc;
}

static int
does_provider_have_agent(const char *agent, const char *provider, const char *class)
{
    int found = 0;
    GList *agents = NULL;
    GListPtr gIter2 = NULL;

    agents = resources_list_agents(class, provider);
    for (gIter2 = agents; gIter2 != NULL; gIter2 = gIter2->next) {
        if (safe_str_eq(agent, gIter2->data)) {
            found = 1;
        }
    }
    g_list_free_full(agents, free);

    return found;
}

static int
lrmd_api_list_ocf_providers(lrmd_t * lrmd, const char *agent, lrmd_list_t ** providers)
{
    int rc = lrmd_ok;
    char *provider = NULL;
    GList *ocf_providers = NULL;
    GListPtr gIter = NULL;

    ocf_providers = resources_list_providers("ocf");

    for (gIter = ocf_providers; gIter != NULL; gIter = gIter->next) {
        provider = gIter->data;
        if (!agent || does_provider_have_agent(agent, provider, "ocf")) {
            *providers = lrmd_list_add(*providers, (const char *)gIter->data);
            rc++;
        }
    }

    g_list_free_full(ocf_providers, free);

    return rc;
}

static int
lrmd_api_list_standards(lrmd_t * lrmd, lrmd_list_t ** supported)
{
    int rc = 0;
    char *standard = NULL;
    GList *standards = NULL;
    GListPtr gIter = NULL;

    standards = resources_list_standards();

    for (gIter = standards; gIter != NULL; gIter = gIter->next) {
        standard = gIter->data;
        *supported = lrmd_list_add(*supported, (const char *)gIter->data);
        rc++;
    }

    g_list_free_full(standards, free);

    return rc;
}

lrmd_t *
lrmd_api_new(void)
{
    lrmd_t *new_lrmd = NULL;
    lrmd_private_t *pvt = NULL;

    new_lrmd = calloc(1, sizeof(lrmd_t));
    pvt = calloc(1, sizeof(lrmd_private_t));
    new_lrmd->cmds = calloc(1, sizeof(lrmd_api_operations_t));

    new_lrmd->private = pvt;

    new_lrmd->cmds->connect = lrmd_api_connect;
    new_lrmd->cmds->disconnect = lrmd_api_disconnect;
    new_lrmd->cmds->register_rsc = lrmd_api_register_rsc;
    new_lrmd->cmds->unregister_rsc = lrmd_api_unregister_rsc;
    new_lrmd->cmds->get_rsc_info = lrmd_api_get_rsc_info;
    new_lrmd->cmds->set_callback = lrmd_api_set_callback;
    new_lrmd->cmds->get_metadata = lrmd_api_get_metadata;
    new_lrmd->cmds->exec = lrmd_api_exec;
    new_lrmd->cmds->cancel = lrmd_api_cancel;
    new_lrmd->cmds->list_agents = lrmd_api_list_agents;
    new_lrmd->cmds->list_ocf_providers = lrmd_api_list_ocf_providers;
    new_lrmd->cmds->list_standards = lrmd_api_list_standards;

    if (!stonith_api) {
        stonith_api = stonith_api_new();
    }

    return new_lrmd;
}

void
lrmd_api_delete(lrmd_t * lrmd)
{
    lrmd->cmds->disconnect(lrmd);       /* no-op if already disconnected */
    free(lrmd->cmds);
    free(lrmd->private);
    free(lrmd);
}
