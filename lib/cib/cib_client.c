/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pwd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <glib.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/common/xml.h>

static GHashTable *cib_op_callback_table = NULL;

static gint
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
            pcmk__trace("callbacks for %s are not equal: %p < %p",
                        a_client->event, a_client->callback, b_client->callback);
            return -1;
        }
        pcmk__trace("callbacks for %s are not equal: %p > %p", a_client->event,
                    a_client->callback, b_client->callback);
        return 1;
    }
    return rc;
}

static int
cib_client_add_notify_callback(cib_t * cib, const char *event,
                               void (*callback) (const char *event,
                                                 xmlNode * msg))
{
    GList *list_item = NULL;
    cib_notify_client_t *new_client = NULL;

    if ((cib->variant != cib_native) && (cib->variant != cib_remote)) {
        return -EPROTONOSUPPORT;
    }

    pcmk__trace("Adding callback for %s events (%u)", event,
                g_list_length(cib->notify_list));

    new_client = pcmk__assert_alloc(1, sizeof(cib_notify_client_t));
    new_client->event = event;
    new_client->callback = callback;

    list_item = g_list_find_custom(cib->notify_list, new_client,
                                   ciblib_GCompareFunc);

    if (list_item != NULL) {
        pcmk__warn("Callback already present");
        free(new_client);
        return -EINVAL;

    } else {
        cib->notify_list = g_list_append(cib->notify_list, new_client);

        cib->cmds->register_notification(cib, event, 1);

        pcmk__trace("Callback added (%d)", g_list_length(cib->notify_list));
    }
    return pcmk_ok;
}

static int
get_notify_list_event_count(cib_t *cib, const char *event)
{
    int count = 0;

    for (GList *iter = g_list_first(cib->notify_list); iter != NULL;
         iter = iter->next) {
        cib_notify_client_t *client = (cib_notify_client_t *) iter->data;

        if (strcmp(client->event, event) == 0) {
            count++;
        }
    }
    pcmk__trace("event(%s) count : %d", event, count);
    return count;
}

static int
cib_client_del_notify_callback(cib_t *cib, const char *event,
                               void (*callback) (const char *event,
                                                 xmlNode *msg))
{
    GList *list_item = NULL;
    cib_notify_client_t *new_client = NULL;

    if (cib->variant != cib_native && cib->variant != cib_remote) {
        return -EPROTONOSUPPORT;
    }

    if (get_notify_list_event_count(cib, event) == 0) {
        pcmk__debug("The callback of the event does not exist(%s)", event);
        return pcmk_ok;
    }

    pcmk__debug("Removing callback for %s events", event);

    new_client = pcmk__assert_alloc(1, sizeof(cib_notify_client_t));
    new_client->event = event;
    new_client->callback = callback;

    list_item = g_list_find_custom(cib->notify_list, new_client, ciblib_GCompareFunc);

    if (list_item != NULL) {
        cib_notify_client_t *list_client = list_item->data;

        cib->notify_list = g_list_remove(cib->notify_list, list_client);
        free(list_client);

        pcmk__trace("Removed callback");

    } else {
        pcmk__trace("Callback not present");
    }

    if (get_notify_list_event_count(cib, event) == 0) {
        /* When there is not the registration of the event, the processing turns off a notice. */
        cib->cmds->register_notification(cib, event, 0);
    }

    free(new_client);
    return pcmk_ok;
}

static gboolean
cib_async_timeout_handler(gpointer data)
{
    struct timer_rec_s *timer = data;

    pcmk__debug("Async call %d timed out after %ds", timer->call_id,
                timer->timeout);
    cib_native_callback(timer->cib, NULL, timer->call_id, -ETIME);

    // We remove the handler in remove_cib_op_callback()
    return G_SOURCE_CONTINUE;
}

static gboolean
cib_client_register_callback_full(cib_t *cib, int call_id, int timeout,
                                  gboolean only_success, void *user_data,
                                  const char *callback_name,
                                  void (*callback)(xmlNode *, int, int,
                                                   xmlNode *, void *),
                                  void (*free_func)(void *))
{
    cib_callback_client_t *blob = NULL;

    if (call_id < 0) {
        if (only_success == FALSE) {
            callback(NULL, call_id, call_id, NULL, user_data);
        } else {
            pcmk__warn("CIB call failed: %s", pcmk_strerror(call_id));
        }
        if (user_data && free_func) {
            free_func(user_data);
        }
        return FALSE;
    }

    blob = pcmk__assert_alloc(1, sizeof(cib_callback_client_t));
    blob->id = callback_name;
    blob->only_success = only_success;
    blob->user_data = user_data;
    blob->callback = callback;
    blob->free_func = free_func;

    if (timeout > 0) {
        struct timer_rec_s *async_timer =
            pcmk__assert_alloc(1, sizeof(struct timer_rec_s));

        blob->timer = async_timer;

        async_timer->cib = cib;
        async_timer->call_id = call_id;
        async_timer->timeout = timeout * 1000;
        async_timer->ref = pcmk__create_timer(async_timer->timeout,
                                              cib_async_timeout_handler,
                                              async_timer);
    }

    pcmk__trace("Adding callback %s for call %d", callback_name, call_id);
    pcmk__intkey_table_insert(cib_op_callback_table, call_id, blob);

    return TRUE;
}

static gboolean
cib_client_register_callback(cib_t *cib, int call_id, int timeout,
                             gboolean only_success, void *user_data,
                             const char *callback_name,
                             void (*callback) (xmlNode *, int, int, xmlNode *,
                                               void *))
{
    return cib_client_register_callback_full(cib, call_id, timeout,
                                             only_success, user_data,
                                             callback_name, callback, NULL);
}

static int
cib_client_noop(cib_t * cib, int call_options)
{
    return cib_internal_op(cib, PCMK__CIB_REQUEST_NOOP, NULL, NULL, NULL, NULL,
                           call_options, cib->user);
}

static int
cib_client_ping(cib_t * cib, xmlNode ** output_data, int call_options)
{
    return cib_internal_op(cib, CRM_OP_PING, NULL, NULL, NULL, output_data,
                           call_options, cib->user);
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
    return cib_internal_op(cib, PCMK__CIB_REQUEST_QUERY, host, section, NULL,
                           output_data, call_options, cib->user);
}

static int
set_secondary(cib_t *cib, int call_options)
{
    return cib_internal_op(cib, PCMK__CIB_REQUEST_SECONDARY, NULL, NULL, NULL,
                           NULL, call_options, cib->user);
}

static int
set_primary(cib_t *cib, int call_options)
{
    return cib_internal_op(cib, PCMK__CIB_REQUEST_PRIMARY, NULL, NULL, NULL,
                           NULL, call_options, cib->user);
}

static int
cib_client_bump_epoch(cib_t * cib, int call_options)
{
    return cib_internal_op(cib, PCMK__CIB_REQUEST_BUMP, NULL, NULL, NULL, NULL,
                           call_options, cib->user);
}

static int
cib_client_upgrade(cib_t * cib, int call_options)
{
    return cib_internal_op(cib, PCMK__CIB_REQUEST_UPGRADE, NULL, NULL, NULL,
                           NULL, call_options, cib->user);
}

static int
cib_client_sync(cib_t * cib, const char *section, int call_options)
{
    return cib->cmds->sync_from(cib, NULL, section, call_options);
}

static int
cib_client_sync_from(cib_t * cib, const char *host, const char *section, int call_options)
{
    return cib_internal_op(cib, PCMK__CIB_REQUEST_SYNC, host, section, NULL,
                           NULL, call_options, cib->user);
}

static int
cib_client_create(cib_t * cib, const char *section, xmlNode * data, int call_options)
{
    return cib_internal_op(cib, PCMK__CIB_REQUEST_CREATE, NULL, section, data,
                           NULL, call_options, cib->user);
}

static int
cib_client_modify(cib_t * cib, const char *section, xmlNode * data, int call_options)
{
    return cib_internal_op(cib, PCMK__CIB_REQUEST_MODIFY, NULL, section, data,
                           NULL, call_options, cib->user);
}

static int
cib_client_replace(cib_t * cib, const char *section, xmlNode * data, int call_options)
{
    return cib_internal_op(cib, PCMK__CIB_REQUEST_REPLACE, NULL, section, data,
                           NULL, call_options, cib->user);
}

static int
cib_client_delete(cib_t * cib, const char *section, xmlNode * data, int call_options)
{
    return cib_internal_op(cib, PCMK__CIB_REQUEST_DELETE, NULL, section, data,
                           NULL, call_options, cib->user);
}

static int
cib_client_erase(cib_t * cib, xmlNode ** output_data, int call_options)
{
    return cib_internal_op(cib, PCMK__CIB_REQUEST_ERASE, NULL, NULL, NULL,
                           output_data, call_options, cib->user);
}

static int
cib_client_init_transaction(cib_t *cib)
{
    int rc = pcmk_rc_ok;

    if (cib == NULL) {
        return -EINVAL;
    }

    if (cib->transaction != NULL) {
        // A client can have at most one transaction at a time
        rc = pcmk_rc_already;
    }

    if (rc == pcmk_rc_ok) {
        cib->transaction = pcmk__xe_create(NULL, PCMK__XE_CIB_TRANSACTION);
    }

    if (rc != pcmk_rc_ok) {
        const char *client_id = NULL;

        cib->cmds->client_id(cib, NULL, &client_id);
        pcmk__err("Failed to initialize CIB transaction for client %s: %s",
                  client_id, pcmk_rc_str(rc));
    }
    return pcmk_rc2legacy(rc);
}

static int
cib_client_end_transaction(cib_t *cib, bool commit, int call_options)
{
    const char *client_id = NULL;
    int rc = pcmk_ok;

    if (cib == NULL) {
        return -EINVAL;
    }

    cib->cmds->client_id(cib, NULL, &client_id);
    client_id = pcmk__s(client_id, "(unidentified)");

    if (commit) {
        if (cib->transaction == NULL) {
            rc = pcmk_rc_no_transaction;

            pcmk__err("Failed to commit transaction for CIB client %s: %s",
                      client_id, pcmk_rc_str(rc));
            return pcmk_rc2legacy(rc);
        }
        rc = cib_internal_op(cib, PCMK__CIB_REQUEST_COMMIT_TRANSACT, NULL, NULL,
                             cib->transaction, NULL, call_options, cib->user);

    } else {
        // Discard always succeeds
        if (cib->transaction != NULL) {
            pcmk__trace("Discarded transaction for CIB client %s", client_id);
        } else {
            pcmk__trace("No transaction found for CIB client %s", client_id);
        }
    }
    pcmk__xml_free(cib->transaction);
    cib->transaction = NULL;
    return rc;
}

static int
cib_client_fetch_schemas(cib_t *cib, xmlNode **output_data, const char *after_ver,
                         int call_options)
{
    xmlNode *data = pcmk__xe_create(NULL, PCMK__XA_SCHEMA);
    int rc = pcmk_ok;

    pcmk__xe_set(data, PCMK_XA_VERSION, after_ver);

    rc = cib_internal_op(cib, PCMK__CIB_REQUEST_SCHEMAS, NULL, NULL, data,
                         output_data, call_options, NULL);
    pcmk__xml_free(data);
    return rc;
}

static void
cib_client_set_user(cib_t *cib, const char *user)
{
    pcmk__str_update(&(cib->user), user);
}

static void
cib_destroy_op_callback(gpointer data)
{
    cib_callback_client_t *blob = data;

    if (blob->timer && blob->timer->ref > 0) {
        g_source_remove(blob->timer->ref);
    }
    free(blob->timer);

    if (blob->user_data && blob->free_func) {
        blob->free_func(blob->user_data);
    }

    free(blob);
}

static void
destroy_op_callback_table(void)
{
    if (cib_op_callback_table != NULL) {
        g_hash_table_destroy(cib_op_callback_table);
        cib_op_callback_table = NULL;
    }
}

char *
get_shadow_file(const char *suffix)
{
    char *cib_home = NULL;
    char *fullname = NULL;
    char *name = pcmk__assert_asprintf("shadow.%s", suffix);
    const char *dir = getenv("CIB_shadow_dir");

    if (dir == NULL) {
        /* @TODO This basically duplicates pcmk__uid2username(), but we need the
         * password database entry, not just the user name from it. We should
         * reduce the duplication.
         */
        struct passwd *pwent = NULL;
        const char *user = NULL;

        errno = 0;
        pwent = getpwuid(geteuid());

        if (pwent) {
            user = pwent->pw_name;

        } else {
            // Save errno before getenv()
            int rc = errno;

            user = getenv("USER");
            pcmk__warn("Could not get password database entry for effective "
                       "user ID %lld: %s. Assuming user is %s.",
                       (long long) geteuid(),
                       ((rc != 0)? strerror(rc) : "No matching entry found"),
                       pcmk__s(user, "unprivileged user"));
        }

        if (pcmk__strcase_any_of(user, "root", CRM_DAEMON_USER, NULL)) {
            dir = CRM_CONFIG_DIR;

        } else {
            const char *home = NULL;

            if ((home = getenv("HOME")) == NULL) {
                if (pwent) {
                    home = pwent->pw_dir;
                }
            }

            dir = pcmk__get_tmpdir();
            if (home && home[0] == '/') {
                int rc = 0;

                cib_home = pcmk__assert_asprintf("%s/.cib", home);

                rc = mkdir(cib_home, 0700);
                if (rc < 0 && errno != EEXIST) {
                    pcmk__err("Couldn't create user-specific shadow directory "
                              "%s: %s",
                              cib_home, strerror(errno));

                } else {
                    dir = cib_home;
                }
            }
        }
    }

    fullname = pcmk__assert_asprintf("%s/%s", dir, name);
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

/*!
 * \brief Create a new CIB connection object
 *
 * Create a new live, remote, file, or shadow file CIB connection object based
 * on the values of CIB-related environment variables (CIB_shadow, CIB_file,
 * CIB_port, CIB_server, CIB_user, and CIB_passwd). The object will not be
 * connected.
 *
 * \return Newly allocated CIB connection object
 * \note The CIB API does not fully support opening multiple CIB connection
 *       objects simultaneously, so the returned object should be treated as a
 *       singleton.
 */
/* @TODO Ensure all APIs support multiple simultaneous CIB connection objects
 * (at least cib_free_callbacks() currently does not).
 */
cib_t *
cib_new(void)
{
    const char *value = getenv("CIB_shadow");
    const char *server = NULL;
    const char *user = NULL;
    const char *pass = NULL;
    gboolean encrypted = TRUE;
    int port;

    if (!pcmk__str_empty(value)) {
        return cib_shadow_new(value);
    }

    value = getenv("CIB_file");
    if (!pcmk__str_empty(value)) {
        return cib_file_new(value);
    }

    value = getenv("CIB_port");
    if (pcmk__str_empty(value)) {
        return cib_native_new();
    }

    /* We don't ensure port is valid (>= 0) because cib_new() currently can't
     * return NULL in practice, and introducing a NULL return here could cause
     * core dumps that would previously just cause signon() failures.
     */
    pcmk__scan_port(value, &port);

    if (!pcmk__is_true(getenv("CIB_encrypted"))) {
        encrypted = FALSE;
    }

    server = getenv("CIB_server");
    user = getenv("CIB_user");
    pass = getenv("CIB_passwd");

    if (pcmk__str_empty(user)) {
        user = CRM_DAEMON_USER;
    }

    if (pcmk__str_empty(server)) {
        server = "localhost";
    }

    pcmk__debug("Initializing %s remote CIB access to %s:%d as user %s",
                (encrypted? "encrypted" : "plain-text"), server, port, user);
    return cib_remote_new(server, user, pass, port, encrypted);
}

/*!
 * \internal
 * \brief Create a generic CIB connection instance
 *
 * \return Newly allocated and initialized cib_t instance
 *
 * \note This is called by each variant's cib_*_new() function before setting
 *       variant-specific values.
 */
cib_t *
cib_new_variant(void)
{
    cib_t *new_cib = NULL;

    new_cib = calloc(1, sizeof(cib_t));

    if (new_cib == NULL) {
        return NULL;
    }

    remove_cib_op_callback(0, TRUE); /* remove all */

    new_cib->call_id = 1;
    new_cib->variant = cib_undefined;

    new_cib->type = cib_no_connection;
    new_cib->state = cib_disconnected;
    new_cib->variant_opaque = NULL;
    new_cib->notify_list = NULL;

    /* the rest will get filled in by the variant constructor */
    new_cib->cmds = calloc(1, sizeof(cib_api_operations_t));

    if (new_cib->cmds == NULL) {
        free(new_cib);
        return NULL;
    }

    new_cib->cmds->add_notify_callback = cib_client_add_notify_callback;
    new_cib->cmds->del_notify_callback = cib_client_del_notify_callback;
    new_cib->cmds->register_callback = cib_client_register_callback;
    new_cib->cmds->register_callback_full = cib_client_register_callback_full;

    new_cib->cmds->noop = cib_client_noop; // Deprecated method
    new_cib->cmds->ping = cib_client_ping;
    new_cib->cmds->query = cib_client_query;
    new_cib->cmds->sync = cib_client_sync;

    new_cib->cmds->query_from = cib_client_query_from;
    new_cib->cmds->sync_from = cib_client_sync_from;

    new_cib->cmds->set_primary = set_primary;
    new_cib->cmds->set_secondary = set_secondary;

    new_cib->cmds->upgrade = cib_client_upgrade;
    new_cib->cmds->bump_epoch = cib_client_bump_epoch;

    new_cib->cmds->create = cib_client_create;
    new_cib->cmds->modify = cib_client_modify;
    new_cib->cmds->replace = cib_client_replace;
    new_cib->cmds->remove = cib_client_delete;
    new_cib->cmds->erase = cib_client_erase;

    new_cib->cmds->init_transaction = cib_client_init_transaction;
    new_cib->cmds->end_transaction = cib_client_end_transaction;

    new_cib->cmds->set_user = cib_client_set_user;

    new_cib->cmds->fetch_schemas = cib_client_fetch_schemas;

    return new_cib;
}

void 
cib_free_notify(cib_t *cib)
{

    if (cib) {
        GList *list = cib->notify_list;

        while (list != NULL) {
            cib_notify_client_t *client = g_list_nth_data(list, 0);

            list = g_list_remove(list, client);
            free(client);
        }
        cib->notify_list = NULL;
    }
}

/*!
 * \brief Free all callbacks for a CIB connection
 *
 * \param[in,out] cib  CIB connection to clean up
 */
void
cib_free_callbacks(cib_t *cib)
{
    cib_free_notify(cib);

    destroy_op_callback_table();
}

/*!
 * \brief Free all memory used by CIB connection
 *
 * \param[in,out] cib  CIB connection to delete
 */
void
cib_delete(cib_t *cib)
{
    cib_free_callbacks(cib);
    if (cib) {
        cib->cmds->free(cib);
    }
}

void
remove_cib_op_callback(int call_id, gboolean all_callbacks)
{
    if (all_callbacks) {
        destroy_op_callback_table();
        cib_op_callback_table = pcmk__intkey_table(cib_destroy_op_callback);
    } else {
        pcmk__intkey_table_remove(cib_op_callback_table, call_id);
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

    pcmk__debug("Call %d (%s): pending", call, pcmk__s(blob->id, "without ID"));
}

void
cib_dump_pending_callbacks(void)
{
    if (cib_op_callback_table == NULL) {
        return;
    }
    return g_hash_table_foreach(cib_op_callback_table, cib_dump_pending_op, NULL);
}

cib_callback_client_t*
cib__lookup_id (int call_id)
{
    return pcmk__intkey_table_lookup(cib_op_callback_table, call_id);
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/cib_compat.h>

cib_t *
cib_new_no_shadow(void)
{
    const char *shadow = getenv("CIB_shadow");
    cib_t *cib = NULL;

    unsetenv("CIB_shadow");
    cib = cib_new();

    if (shadow != NULL) {
        setenv("CIB_shadow", shadow, 1);
    }
    return cib;
}

// LCOV_EXCL_STOP
// End deprecated API
