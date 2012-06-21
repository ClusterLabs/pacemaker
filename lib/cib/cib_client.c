/*
 * Copyright (c) 2004 Andrew Beekhof <andrew@beekhof.net>
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
#include <pwd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <glib.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <cib_private.h>

GHashTable *cib_op_callback_table = NULL;

int cib_client_set_op_callback(cib_t * cib, void (*callback) (const xmlNode * msg, int call_id,
                                                              int rc, xmlNode * output));

int cib_client_add_notify_callback(cib_t * cib, const char *event,
                                   void (*callback) (const char *event, xmlNode * msg));

int cib_client_del_notify_callback(cib_t * cib, const char *event,
                                   void (*callback) (const char *event, xmlNode * msg));

gint ciblib_GCompareFunc(gconstpointer a, gconstpointer b);

#define op_common(cib) do {                                             \
        if(cib == NULL) {                                               \
            return cib_missing;						\
        } else if(cib->cmds->variant_op == NULL) {                      \
            return cib_variant;						\
        }                                                               \
    } while(0)

static int
cib_client_noop(cib_t * cib, int call_options)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CRM_OP_NOOP, NULL, NULL, NULL, NULL, call_options);
}

static int
cib_client_ping(cib_t * cib, xmlNode ** output_data, int call_options)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CRM_OP_PING, NULL, NULL, NULL, output_data, call_options);
}

static int
cib_client_query(cib_t * cib, const char *section, xmlNode ** output_data, int call_options)
{
    return cib->cmds->query_from(cib, NULL, section, output_data, call_options);
}

static int
cib_client_query_from(cib_t * cib, const char *host, const char *section,
                      xmlNode ** output_data, int call_options)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CIB_OP_QUERY, host, section, NULL, output_data, call_options);
}

static int
cib_client_is_master(cib_t * cib)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CIB_OP_ISMASTER, NULL, NULL, NULL, NULL,
                                 cib_scope_local | cib_sync_call);
}

static int
cib_client_set_slave(cib_t * cib, int call_options)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CIB_OP_SLAVE, NULL, NULL, NULL, NULL, call_options);
}

static int
cib_client_set_slave_all(cib_t * cib, int call_options)
{
    return cib_NOTSUPPORTED;
}

static int
cib_client_set_master(cib_t * cib, int call_options)
{
    op_common(cib);
    crm_trace("Adding cib_scope_local to options");
    return cib->cmds->variant_op(cib, CIB_OP_MASTER, NULL, NULL, NULL, NULL,
                                 call_options | cib_scope_local);
}

static int
cib_client_bump_epoch(cib_t * cib, int call_options)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CIB_OP_BUMP, NULL, NULL, NULL, NULL, call_options);
}

static int
cib_client_upgrade(cib_t * cib, int call_options)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CIB_OP_UPGRADE, NULL, NULL, NULL, NULL, call_options);
}

static int
cib_client_sync(cib_t * cib, const char *section, int call_options)
{
    return cib->cmds->sync_from(cib, NULL, section, call_options);
}

static int
cib_client_sync_from(cib_t * cib, const char *host, const char *section, int call_options)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CIB_OP_SYNC, host, section, NULL, NULL, call_options);
}

static int
cib_client_create(cib_t * cib, const char *section, xmlNode * data, int call_options)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CIB_OP_CREATE, NULL, section, data, NULL, call_options);
}

static int
cib_client_modify(cib_t * cib, const char *section, xmlNode * data, int call_options)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CIB_OP_MODIFY, NULL, section, data, NULL, call_options);
}

static int
cib_client_update(cib_t * cib, const char *section, xmlNode * data, int call_options)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CIB_OP_MODIFY, NULL, section, data, NULL, call_options);
}

static int
cib_client_replace(cib_t * cib, const char *section, xmlNode * data, int call_options)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CIB_OP_REPLACE, NULL, section, data, NULL, call_options);
}

static int
cib_client_delete(cib_t * cib, const char *section, xmlNode * data, int call_options)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CIB_OP_DELETE, NULL, section, data, NULL, call_options);
}

static int
cib_client_delete_absolute(cib_t * cib, const char *section, xmlNode * data, int call_options)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CIB_OP_DELETE_ALT, NULL, section, data, NULL, call_options);
}

static int
cib_client_erase(cib_t * cib, xmlNode ** output_data, int call_options)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CIB_OP_ERASE, NULL, NULL, NULL, output_data, call_options);
}

static int
cib_client_quit(cib_t * cib, int call_options)
{
    op_common(cib);
    return cib->cmds->variant_op(cib, CRM_OP_QUIT, NULL, NULL, NULL, NULL, call_options);
}

static void
cib_destroy_op_callback(gpointer data)
{
    cib_callback_client_t *blob = data;

    if (blob->timer && blob->timer->ref > 0) {
        g_source_remove(blob->timer->ref);
    }
    free(blob->timer);
    free(blob);
}

char *
get_shadow_file(const char *suffix)
{
    char *cib_home = NULL;
    char *fullname = NULL;
    char *name = crm_concat("shadow", suffix, '.');
    const char *dir = getenv("CIB_shadow_dir");

    if (dir == NULL) {
        uid_t uid = geteuid();
        struct passwd *pwent = getpwuid(uid);
        const char *user = NULL;

        if (pwent) {
            user = pwent->pw_name;
        } else {
            crm_perror(LOG_ERR, "Cannot get password entry for uid: %d", uid);
            user = getenv("USER");
        }

        if (safe_str_eq(user, "root") || safe_str_eq(user, CRM_DAEMON_USER)) {
            dir = CRM_CONFIG_DIR;

        } else {
            const char *home = NULL;

            if ((home = getenv("HOME")) == NULL) {
                if (pwent) {
                    home = pwent->pw_dir;
                }
            }

            if ((dir = getenv("TMPDIR")) == NULL) {
                dir = "/tmp";
            }
            if (home && home[0] == '/') {
                int rc = 0;

                cib_home = crm_concat(home, ".cib", '/');

                rc = mkdir(cib_home, 0700);
                if (rc < 0 && errno != EEXIST) {
                    crm_perror(LOG_ERR, "Couldn't create user-specific shadow directory: %s",
                               cib_home);
                    errno = 0;

                } else {
                    dir = cib_home;
                }
            }
        }
    }

    fullname = crm_concat(dir, name, '/');
    free(cib_home);
    free(name);

    return fullname;
}

cib_t *
cib_shadow_new(const char *shadow)
{
    cib_t *new_cib = NULL;
    char *shadow_file = NULL;

    CRM_CHECK(shadow != NULL, return NULL);

    shadow_file = get_shadow_file(shadow);
    new_cib = cib_file_new(shadow_file);
    free(shadow_file);

    return new_cib;
}

cib_t *
cib_new_no_shadow(void)
{
    unsetenv("CIB_shadow");
    return cib_new();
}

cib_t *
cib_new(void)
{
    const char *value = getenv("CIB_shadow");

    if (value) {
        return cib_shadow_new(value);
    }

    value = getenv("CIB_file");
    if (value) {
        return cib_file_new(value);
    }

    value = getenv("CIB_port");
    if (value) {
        gboolean encrypted = TRUE;
        int port = crm_parse_int(value, NULL);
        const char *server = getenv("CIB_server");
        const char *user = getenv("CIB_user");
        const char *pass = getenv("CIB_passwd");

        value = getenv("CIB_encrypted");
        if (value && crm_is_true(value) == FALSE) {
            crm_info("Disabling TLS");
            encrypted = FALSE;
        }

        if (user == NULL) {
            user = CRM_DAEMON_USER;
            crm_info("Defaulting to user: %s", user);
        }

        if (server == NULL) {
            server = "localhost";
            crm_info("Defaulting to localhost");
        }

        return cib_remote_new(server, user, pass, port, encrypted);
    }

    return cib_native_new();
}

/* this is backwards...
   cib_*_new should call this not the other way around
 */

cib_t *
cib_new_variant(void)
{
    cib_t *new_cib = NULL;

    new_cib = calloc(1, sizeof(cib_t));

    if (cib_op_callback_table != NULL) {
        g_hash_table_destroy(cib_op_callback_table);
        cib_op_callback_table = NULL;
    }
    if (cib_op_callback_table == NULL) {
        cib_op_callback_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                                      NULL, cib_destroy_op_callback);
    }

    new_cib->call_id = 1;
    new_cib->variant = cib_undefined;

    new_cib->type = cib_none;
    new_cib->state = cib_disconnected;

    new_cib->op_callback = NULL;
    new_cib->variant_opaque = NULL;
    new_cib->notify_list = NULL;

    /* the rest will get filled in by the variant constructor */
    new_cib->cmds = calloc(1, sizeof(cib_api_operations_t));

    new_cib->cmds->set_op_callback = cib_client_set_op_callback;
    new_cib->cmds->add_notify_callback = cib_client_add_notify_callback;
    new_cib->cmds->del_notify_callback = cib_client_del_notify_callback;
    new_cib->cmds->register_callback = cib_client_register_callback;

    new_cib->cmds->noop = cib_client_noop;
    new_cib->cmds->ping = cib_client_ping;
    new_cib->cmds->query = cib_client_query;
    new_cib->cmds->sync = cib_client_sync;

    new_cib->cmds->query_from = cib_client_query_from;
    new_cib->cmds->sync_from = cib_client_sync_from;

    new_cib->cmds->is_master = cib_client_is_master;
    new_cib->cmds->set_master = cib_client_set_master;
    new_cib->cmds->set_slave = cib_client_set_slave;
    new_cib->cmds->set_slave_all = cib_client_set_slave_all;

    new_cib->cmds->upgrade = cib_client_upgrade;
    new_cib->cmds->bump_epoch = cib_client_bump_epoch;

    new_cib->cmds->create = cib_client_create;
    new_cib->cmds->modify = cib_client_modify;
    new_cib->cmds->update = cib_client_update;
    new_cib->cmds->replace = cib_client_replace;
    new_cib->cmds->delete = cib_client_delete;
    new_cib->cmds->erase = cib_client_erase;
    new_cib->cmds->quit = cib_client_quit;

    new_cib->cmds->delete_absolute = cib_client_delete_absolute;

    return new_cib;
}

void
cib_delete(cib_t * cib)
{
    GList *list = cib->notify_list;

    while (list != NULL) {
        cib_notify_client_t *client = g_list_nth_data(list, 0);

        list = g_list_remove(list, client);
        free(client);
    }

    g_hash_table_destroy(cib_op_callback_table);
    cib_op_callback_table = NULL;
    cib->cmds->free(cib);
    cib = NULL;
}

int
cib_client_set_op_callback(cib_t * cib, void (*callback) (const xmlNode * msg, int call_id,
                                                          int rc, xmlNode * output))
{
    if (callback == NULL) {
        crm_info("Un-Setting operation callback");

    } else {
        crm_trace("Setting operation callback");
    }
    cib->op_callback = callback;
    return cib_ok;
}

int
cib_client_add_notify_callback(cib_t * cib, const char *event,
                               void (*callback) (const char *event, xmlNode * msg))
{
    GList *list_item = NULL;
    cib_notify_client_t *new_client = NULL;

    if (cib->variant != cib_native && cib->variant != cib_remote) {
        return cib_NOTSUPPORTED;
    }

    crm_trace("Adding callback for %s events (%d)", event, g_list_length(cib->notify_list));

    new_client = calloc(1, sizeof(cib_notify_client_t));
    new_client->event = event;
    new_client->callback = callback;

    list_item = g_list_find_custom(cib->notify_list, new_client, ciblib_GCompareFunc);

    if (list_item != NULL) {
        crm_warn("Callback already present");
        free(new_client);
        return cib_EXISTS;

    } else {
        cib->notify_list = g_list_append(cib->notify_list, new_client);

        cib->cmds->register_notification(cib, event, 1);

        crm_trace("Callback added (%d)", g_list_length(cib->notify_list));
    }
    return cib_ok;
}

int
cib_client_del_notify_callback(cib_t * cib, const char *event,
                               void (*callback) (const char *event, xmlNode * msg))
{
    GList *list_item = NULL;
    cib_notify_client_t *new_client = NULL;

    if (cib->variant != cib_native && cib->variant != cib_remote) {
        return cib_NOTSUPPORTED;
    }

    crm_debug("Removing callback for %s events", event);

    new_client = calloc(1, sizeof(cib_notify_client_t));
    new_client->event = event;
    new_client->callback = callback;

    list_item = g_list_find_custom(cib->notify_list, new_client, ciblib_GCompareFunc);

    cib->cmds->register_notification(cib, event, 0);

    if (list_item != NULL) {
        cib_notify_client_t *list_client = list_item->data;

        cib->notify_list = g_list_remove(cib->notify_list, list_client);
        free(list_client);

        crm_trace("Removed callback");

    } else {
        crm_trace("Callback not present");
    }
    free(new_client);
    return cib_ok;
}

gint
ciblib_GCompareFunc(gconstpointer a, gconstpointer b)
{
    int rc = 0;
    const cib_notify_client_t *a_client = a;
    const cib_notify_client_t *b_client = b;

    CRM_CHECK(a_client->event != NULL && b_client->event != NULL, return 0);
    rc = strcmp(a_client->event, b_client->event);
    if (rc == 0) {
        if (a_client->callback == b_client->callback) {
            return 0;
        } else if (((long)a_client->callback) < ((long)b_client->callback)) {
            crm_trace("callbacks for %s are not equal: %p < %p",
                      a_client->event, a_client->callback, b_client->callback);
            return -1;
        }
        crm_trace("callbacks for %s are not equal: %p > %p",
                  a_client->event, a_client->callback, b_client->callback);
        return 1;
    }
    return rc;
}

static gboolean
cib_async_timeout_handler(gpointer data)
{
    struct timer_rec_s *timer = data;

    crm_debug("Async call %d timed out after %ds", timer->call_id, timer->timeout);
    cib_native_callback(timer->cib, NULL, timer->call_id, cib_remote_timeout);

    /* Always return TRUE, never remove the handler
     * We do that in remove_cib_op_callback()
     */
    return TRUE;
}

gboolean
cib_client_register_callback(cib_t * cib, int call_id, int timeout, gboolean only_success,
                             void *user_data, const char *callback_name,
                             void (*callback) (xmlNode *, int, int, xmlNode *, void *))
{
    cib_callback_client_t *blob = NULL;

    if (call_id < 0) {
        if (only_success == FALSE) {
            callback(NULL, call_id, call_id, NULL, user_data);
        } else {
            crm_warn("CIB call failed: %s", cib_error2string(call_id));
        }
        return FALSE;
    }

    blob = calloc(1, sizeof(cib_callback_client_t));
    blob->id = callback_name;
    blob->only_success = only_success;
    blob->user_data = user_data;
    blob->callback = callback;

    if (timeout > 0) {
        struct timer_rec_s *async_timer = NULL;

        async_timer = calloc(1, sizeof(struct timer_rec_s));
        blob->timer = async_timer;

        async_timer->cib = cib;
        async_timer->call_id = call_id;
        async_timer->timeout = timeout * 1000;
        async_timer->ref =
            g_timeout_add(async_timer->timeout, cib_async_timeout_handler, async_timer);
    }

    crm_trace("Adding callback %s for call %d", callback_name, call_id);
    g_hash_table_insert(cib_op_callback_table, GINT_TO_POINTER(call_id), blob);

    return TRUE;
}

void
remove_cib_op_callback(int call_id, gboolean all_callbacks)
{
    if (all_callbacks) {
        if (cib_op_callback_table != NULL) {
            g_hash_table_destroy(cib_op_callback_table);
        }

        cib_op_callback_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                                      NULL, cib_destroy_op_callback);

    } else {
        g_hash_table_remove(cib_op_callback_table, GINT_TO_POINTER(call_id));
    }
}

int
num_cib_op_callbacks(void)
{
    if (cib_op_callback_table == NULL) {
        return 0;
    }
    return g_hash_table_size(cib_op_callback_table);
}

static void
cib_dump_pending_op(gpointer key, gpointer value, gpointer user_data)
{
    int call = GPOINTER_TO_INT(key);
    cib_callback_client_t *blob = value;

    crm_debug("Call %d (%s): pending", call, crm_str(blob->id));
}

void
cib_dump_pending_callbacks(void)
{
    if (cib_op_callback_table == NULL) {
        return;
    }
    return g_hash_table_foreach(cib_op_callback_table, cib_dump_pending_op, NULL);
}
