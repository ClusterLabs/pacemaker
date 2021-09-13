/*
 * Copyright 2012-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>

#include <sys/stat.h>
#include <gio/gio.h>
#include <services_private.h>
#include <systemd.h>
#include <dbus/dbus.h>
#include <pcmk-dbus.h>

gboolean systemd_unit_exec_with_unit(svc_action_t * op, const char *unit);

#define BUS_NAME         "org.freedesktop.systemd1"
#define BUS_NAME_MANAGER BUS_NAME ".Manager"
#define BUS_NAME_UNIT    BUS_NAME ".Unit"
#define BUS_PATH         "/org/freedesktop/systemd1"

static inline DBusMessage *
systemd_new_method(const char *method)
{
    crm_trace("Calling: %s on " BUS_NAME_MANAGER, method);
    return dbus_message_new_method_call(BUS_NAME, BUS_PATH, BUS_NAME_MANAGER,
                                        method);
}

/*
 * Functions to manage a static DBus connection
 */

static DBusConnection* systemd_proxy = NULL;

static inline DBusPendingCall *
systemd_send(DBusMessage *msg,
             void(*done)(DBusPendingCall *pending, void *user_data),
             void *user_data, int timeout)
{
    return pcmk_dbus_send(msg, systemd_proxy, done, user_data, timeout);
}

static inline DBusMessage *
systemd_send_recv(DBusMessage *msg, DBusError *error, int timeout)
{
    return pcmk_dbus_send_recv(msg, systemd_proxy, error, timeout);
}

/*!
 * \internal
 * \brief Send a method to systemd without arguments, and wait for reply
 *
 * \param[in] method  Method to send
 *
 * \return Systemd reply on success, NULL (and error will be logged) otherwise
 *
 * \note The caller must call dbus_message_unref() on the reply after
 *       handling it.
 */
static DBusMessage *
systemd_call_simple_method(const char *method)
{
    DBusMessage *msg = systemd_new_method(method);
    DBusMessage *reply = NULL;
    DBusError error;

    /* Don't call systemd_init() here, because that calls this */
    CRM_CHECK(systemd_proxy, return NULL);

    if (msg == NULL) {
        crm_err("Could not create message to send %s to systemd", method);
        return NULL;
    }

    dbus_error_init(&error);
    reply = systemd_send_recv(msg, &error, DBUS_TIMEOUT_USE_DEFAULT);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&error)) {
        crm_err("Could not send %s to systemd: %s (%s)",
                method, error.message, error.name);
        dbus_error_free(&error);
        return NULL;

    } else if (reply == NULL) {
        crm_err("Could not send %s to systemd: no reply received", method);
        return NULL;
    }

    return reply;
}

static gboolean
systemd_init(void)
{
    static int need_init = 1;
    // https://dbus.freedesktop.org/doc/api/html/group__DBusConnection.html

    if (systemd_proxy
        && dbus_connection_get_is_connected(systemd_proxy) == FALSE) {
        crm_warn("Connection to System DBus is closed. Reconnecting...");
        pcmk_dbus_disconnect(systemd_proxy);
        systemd_proxy = NULL;
        need_init = 1;
    }

    if (need_init) {
        need_init = 0;
        systemd_proxy = pcmk_dbus_connect();
    }
    if (systemd_proxy == NULL) {
        return FALSE;
    }
    return TRUE;
}

static inline char *
systemd_get_property(const char *unit, const char *name,
                     void (*callback)(const char *name, const char *value, void *userdata),
                     void *userdata, DBusPendingCall **pending, int timeout)
{
    return systemd_proxy?
           pcmk_dbus_get_property(systemd_proxy, BUS_NAME, unit, BUS_NAME_UNIT,
                                  name, callback, userdata, pending, timeout)
           : NULL;
}

void
systemd_cleanup(void)
{
    if (systemd_proxy) {
        pcmk_dbus_disconnect(systemd_proxy);
        systemd_proxy = NULL;
    }
}

/*
 * end of systemd_proxy functions
 */

/*!
 * \internal
 * \brief Check whether a file name represents a manageable systemd unit
 *
 * \param[in] name  File name to check
 *
 * \return Pointer to "dot" before filename extension if so, NULL otherwise
 */
static const char *
systemd_unit_extension(const char *name)
{
    if (name) {
        const char *dot = strrchr(name, '.');

        if (dot && (!strcmp(dot, ".service")
                    || !strcmp(dot, ".socket")
                    || !strcmp(dot, ".mount")
                    || !strcmp(dot, ".timer")
                    || !strcmp(dot, ".path"))) {
            return dot;
        }
    }
    return NULL;
}

static char *
systemd_service_name(const char *name)
{
    if (name == NULL) {
        return NULL;
    }

    if (systemd_unit_extension(name)) {
        return strdup(name);
    }

    return crm_strdup_printf("%s.service", name);
}

static void
systemd_daemon_reload_complete(DBusPendingCall *pending, void *user_data)
{
    DBusError error;
    DBusMessage *reply = NULL;
    unsigned int reload_count = GPOINTER_TO_UINT(user_data);

    dbus_error_init(&error);
    if(pending) {
        reply = dbus_pending_call_steal_reply(pending);
    }

    if (pcmk_dbus_find_error(pending, reply, &error)) {
        crm_err("Could not issue systemd reload %d: %s", reload_count, error.message);
        dbus_error_free(&error);

    } else {
        crm_trace("Reload %d complete", reload_count);
    }

    if(pending) {
        dbus_pending_call_unref(pending);
    }
    if(reply) {
        dbus_message_unref(reply);
    }
}

static bool
systemd_daemon_reload(int timeout)
{
    static unsigned int reload_count = 0;
    DBusMessage *msg = systemd_new_method("Reload");

    reload_count++;
    CRM_ASSERT(msg != NULL);
    systemd_send(msg, systemd_daemon_reload_complete,
                 GUINT_TO_POINTER(reload_count), timeout);
    dbus_message_unref(msg);

    return TRUE;
}

static bool
systemd_mask_error(svc_action_t *op, const char *error)
{
    crm_trace("Could not issue %s for %s: %s", op->action, op->rsc, error);
    if(strstr(error, "org.freedesktop.systemd1.InvalidName")
       || strstr(error, "org.freedesktop.systemd1.LoadFailed")
       || strstr(error, "org.freedesktop.systemd1.NoSuchUnit")) {

        if (pcmk__str_eq(op->action, "stop", pcmk__str_casei)) {
            crm_trace("Masking %s failure for %s: unknown services are stopped", op->action, op->rsc);
            op->rc = PCMK_OCF_OK;
            return TRUE;

        } else {
            crm_trace("Mapping %s failure for %s: unknown services are not installed", op->action, op->rsc);
            op->rc = PCMK_OCF_NOT_INSTALLED;
            op->status = PCMK_EXEC_NOT_INSTALLED;
            return FALSE;
        }
    }

    return FALSE;
}

static const char *
systemd_loadunit_result(DBusMessage *reply, svc_action_t * op)
{
    const char *path = NULL;
    DBusError error;

    if (pcmk_dbus_find_error((void*)&path, reply, &error)) {
        if(op && !systemd_mask_error(op, error.name)) {
            crm_err("Could not load systemd unit %s for %s: %s",
                    op->agent, op->id, error.message);
        }
        dbus_error_free(&error);

    } else if (!pcmk_dbus_type_check(reply, NULL, DBUS_TYPE_OBJECT_PATH,
                                     __func__, __LINE__)) {
        crm_err("Could not load systemd unit %s for %s: "
                "systemd reply has unexpected type", op->agent, op->id);

    } else {
        dbus_message_get_args (reply, NULL,
                               DBUS_TYPE_OBJECT_PATH, &path,
                               DBUS_TYPE_INVALID);
    }

    if(op) {
        if (path) {
            systemd_unit_exec_with_unit(op, path);

        } else if (op->synchronous == FALSE) {
            services__finalize_async_op(op);
        }
    }

    return path;
}


static void
systemd_loadunit_cb(DBusPendingCall *pending, void *user_data)
{
    DBusMessage *reply = NULL;
    svc_action_t * op = user_data;

    if(pending) {
        reply = dbus_pending_call_steal_reply(pending);
    }

    crm_trace("Got result: %p for %p / %p for %s", reply, pending, op->opaque->pending, op->id);

    CRM_LOG_ASSERT(pending == op->opaque->pending);
    services_set_op_pending(op, NULL);

    systemd_loadunit_result(reply, user_data);

    if(reply) {
        dbus_message_unref(reply);
    }
}

static char *
systemd_unit_by_name(const gchar * arg_name, svc_action_t *op)
{
    DBusMessage *msg;
    DBusMessage *reply = NULL;
    DBusPendingCall* pending = NULL;
    char *name = NULL;

/*
  Equivalent to GetUnit if it's already loaded
  <method name="LoadUnit">
   <arg name="name" type="s" direction="in"/>
   <arg name="unit" type="o" direction="out"/>
  </method>
 */

    if (systemd_init() == FALSE) {
        return FALSE;
    }

    msg = systemd_new_method("LoadUnit");
    CRM_ASSERT(msg != NULL);

    name = systemd_service_name(arg_name);
    CRM_LOG_ASSERT(dbus_message_append_args(msg, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID));
    free(name);

    if(op == NULL || op->synchronous) {
        const char *unit = NULL;
        char *munit = NULL;

        reply = systemd_send_recv(msg, NULL,
                                  (op? op->timeout : DBUS_TIMEOUT_USE_DEFAULT));
        dbus_message_unref(msg);

        unit = systemd_loadunit_result(reply, op);
        if(unit) {
            munit = strdup(unit);
        }
        if(reply) {
            dbus_message_unref(reply);
        }
        return munit;
    }

    pending = systemd_send(msg, systemd_loadunit_cb, op, op->timeout);
    if(pending) {
        services_set_op_pending(op, pending);
    }

    dbus_message_unref(msg);
    return NULL;
}

/*!
 * \internal
 * \brief Compare two strings alphabetically (case-insensitive)
 *
 * \param[in] a  First string to compare
 * \param[in] b  Second string to compare
 *
 * \return 0 if strings are equal, -1 if a < b, 1 if a > b
 *
 * \note Usable as a GCompareFunc with g_list_sort().
 *       NULL is considered less than non-NULL.
 */
static gint
sort_str(gconstpointer a, gconstpointer b)
{
    if (!a && !b) {
        return 0;
    } else if (!a) {
        return -1;
    } else if (!b) {
        return 1;
    }
    return strcasecmp(a, b);
}

GList *
systemd_unit_listall(void)
{
    int nfiles = 0;
    GList *units = NULL;
    DBusMessageIter args;
    DBusMessageIter unit;
    DBusMessageIter elem;
    DBusMessage *reply = NULL;

    if (systemd_init() == FALSE) {
        return NULL;
    }

/*
        "  <method name=\"ListUnitFiles\">\n"                               \
        "   <arg name=\"files\" type=\"a(ss)\" direction=\"out\"/>\n" \
        "  </method>\n"                                                 \
*/

    reply = systemd_call_simple_method("ListUnitFiles");
    if (reply == NULL) {
        return NULL;
    }
    if (!dbus_message_iter_init(reply, &args)) {
        crm_err("Could not list systemd unit files: systemd reply has no arguments");
        dbus_message_unref(reply);
        return NULL;
    }
    if (!pcmk_dbus_type_check(reply, &args, DBUS_TYPE_ARRAY,
                              __func__, __LINE__)) {
        crm_err("Could not list systemd unit files: systemd reply has invalid arguments");
        dbus_message_unref(reply);
        return NULL;
    }

    dbus_message_iter_recurse(&args, &unit);
    for (; dbus_message_iter_get_arg_type(&unit) != DBUS_TYPE_INVALID;
        dbus_message_iter_next(&unit)) {

        DBusBasicValue value;
        const char *match = NULL;
        char *unit_name = NULL;
        char *basename = NULL;

        if(!pcmk_dbus_type_check(reply, &unit, DBUS_TYPE_STRUCT, __func__, __LINE__)) {
            crm_warn("Skipping systemd reply argument with unexpected type");
            continue;
        }

        dbus_message_iter_recurse(&unit, &elem);
        if(!pcmk_dbus_type_check(reply, &elem, DBUS_TYPE_STRING, __func__, __LINE__)) {
            crm_warn("Skipping systemd reply argument with no string");
            continue;
        }

        dbus_message_iter_get_basic(&elem, &value);
        if (value.str == NULL) {
            crm_debug("ListUnitFiles reply did not provide a string");
            continue;
        }
        crm_trace("DBus ListUnitFiles listed: %s", value.str);

        match = systemd_unit_extension(value.str);
        if (match == NULL) {
            // This is not a unit file type we know how to manage
            crm_debug("ListUnitFiles entry '%s' is not supported as resource",
                      value.str);
            continue;
        }

        // ListUnitFiles returns full path names, we just want base name
        basename = strrchr(value.str, '/');
        if (basename) {
            basename = basename + 1;
        } else {
            basename = value.str;
        }

        if (!strcmp(match, ".service")) {
            // Service is the "default" unit type, so strip it
            unit_name = strndup(basename, match - basename);
        } else {
            unit_name = strdup(basename);
        }

        nfiles++;
        units = g_list_prepend(units, unit_name);
    }

    dbus_message_unref(reply);

    crm_trace("Found %d manageable systemd unit files", nfiles);
    units = g_list_sort(units, sort_str);
    return units;
}

gboolean
systemd_unit_exists(const char *name)
{
    char *unit = NULL;

    /* Note: Makes a blocking dbus calls
     * Used by resources_find_service_class() when resource class=service
     */
    unit = systemd_unit_by_name(name, NULL);
    if(unit) {
        free(unit);
        return TRUE;
    }
    return FALSE;
}

static char *
systemd_unit_metadata(const char *name, int timeout)
{
    char *meta = NULL;
    char *desc = NULL;
    char *path = systemd_unit_by_name(name, NULL);

    if (path) {
        /* TODO: Worth a making blocking call for? Probably not. Possibly if cached. */
        desc = systemd_get_property(path, "Description", NULL, NULL, NULL,
                                    timeout);
    } else {
        desc = crm_strdup_printf("Systemd unit file for %s", name);
    }

    meta = crm_strdup_printf("<?xml version=\"1.0\"?>\n"
                           "<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"
                           "<resource-agent name=\"%s\" version=\"" PCMK_DEFAULT_AGENT_VERSION "\">\n"
                           "  <version>1.0</version>\n"
                           "  <longdesc lang=\"en\">\n"
                           "    %s\n"
                           "  </longdesc>\n"
                           "  <shortdesc lang=\"en\">systemd unit file for %s</shortdesc>\n"
                           "  <parameters>\n"
                           "  </parameters>\n"
                           "  <actions>\n"
                           "    <action name=\"start\"   timeout=\"100\" />\n"
                           "    <action name=\"stop\"    timeout=\"100\" />\n"
                           "    <action name=\"status\"  timeout=\"100\" />\n"
                           "    <action name=\"monitor\" timeout=\"100\" interval=\"60\"/>\n"
                           "    <action name=\"meta-data\"  timeout=\"5\" />\n"
                           "  </actions>\n"
                           "  <special tag=\"systemd\">\n"
                           "  </special>\n" "</resource-agent>\n", name, desc, name);
    free(desc);
    free(path);
    return meta;
}

static void
systemd_exec_result(DBusMessage *reply, svc_action_t *op)
{
    DBusError error;

    if (pcmk_dbus_find_error((void*)&error, reply, &error)) {

        /* ignore "already started" or "not running" errors */
        if (!systemd_mask_error(op, error.name)) {
            crm_err("Could not issue %s for %s: %s", op->action, op->rsc, error.message);
        }
        dbus_error_free(&error);

    } else {
        if(!pcmk_dbus_type_check(reply, NULL, DBUS_TYPE_OBJECT_PATH, __func__, __LINE__)) {
            crm_warn("Call to %s passed but return type was unexpected", op->action);
            op->rc = PCMK_OCF_OK;

        } else {
            const char *path = NULL;

            dbus_message_get_args (reply, NULL,
                                   DBUS_TYPE_OBJECT_PATH, &path,
                                   DBUS_TYPE_INVALID);
            crm_info("Call to %s passed: %s", op->action, path);
            op->rc = PCMK_OCF_OK;
        }
    }
}

static void
systemd_async_dispatch(DBusPendingCall *pending, void *user_data)
{
    DBusMessage *reply = NULL;
    svc_action_t *op = user_data;

    if(pending) {
        reply = dbus_pending_call_steal_reply(pending);
    }

    crm_trace("Got result: %p for %p for %s, %s", reply, pending, op->rsc, op->action);

    CRM_LOG_ASSERT(pending == op->opaque->pending);
    services_set_op_pending(op, NULL);
    systemd_exec_result(reply, op);
    services__finalize_async_op(op);

    if(reply) {
        dbus_message_unref(reply);
    }
}

#define SYSTEMD_OVERRIDE_ROOT "/run/systemd/system/"

/* When the cluster manages a systemd resource, we create a unit file override
 * to order the service "before" pacemaker. The "before" relationship won't
 * actually be used, since systemd won't ever start the resource -- we're
 * interested in the reverse shutdown ordering it creates, to ensure that
 * systemd doesn't stop the resource at shutdown while pacemaker is still
 * running.
 *
 * @TODO Add start timeout
 */
#define SYSTEMD_OVERRIDE_TEMPLATE                           \
    "[Unit]\n"                                              \
    "Description=Cluster Controlled %s\n"                   \
    "Before=pacemaker.service pacemaker_remote.service\n"   \
    "\n"                                                    \
    "[Service]\n"                                           \
    "Restart=no\n"

// Temporarily use rwxr-xr-x umask when opening a file for writing
static FILE *
create_world_readable(const char *filename)
{
    mode_t orig_umask = umask(S_IWGRP | S_IWOTH);
    FILE *fp = fopen(filename, "w");

    umask(orig_umask);
    return fp;
}

static void
create_override_dir(const char *agent)
{
    char *override_dir = crm_strdup_printf(SYSTEMD_OVERRIDE_ROOT
                                           "/%s.service.d", agent);
    int rc = pcmk__build_path(override_dir, 0755);

    if (rc != pcmk_rc_ok) {
        crm_warn("Could not create systemd override directory %s: %s",
                 override_dir, pcmk_rc_str(rc));
    }
    free(override_dir);
}

static char *
get_override_filename(const char *agent)
{
    return crm_strdup_printf(SYSTEMD_OVERRIDE_ROOT
                             "/%s.service.d/50-pacemaker.conf", agent);
}

static void
systemd_create_override(const char *agent, int timeout)
{
    FILE *file_strm = NULL;
    char *override_file = get_override_filename(agent);

    create_override_dir(agent);

    /* Ensure the override file is world-readable. This is not strictly
     * necessary, but it avoids a systemd warning in the logs.
     */
    file_strm = create_world_readable(override_file);
    if (file_strm == NULL) {
        crm_err("Cannot open systemd override file %s for writing",
                override_file);
    } else {
        char *override = crm_strdup_printf(SYSTEMD_OVERRIDE_TEMPLATE, agent);

        int rc = fprintf(file_strm, "%s\n", override);

        free(override);
        if (rc < 0) {
            crm_perror(LOG_WARNING, "Cannot write to systemd override file %s",
                       override_file);
        }
        fflush(file_strm);
        fclose(file_strm);
        systemd_daemon_reload(timeout);
    }

    free(override_file);
}

static void
systemd_remove_override(const char *agent, int timeout)
{
    char *override_file = get_override_filename(agent);
    int rc = unlink(override_file);

    if (rc < 0) {
        // Stop may be called when already stopped, which is fine
        crm_perror(LOG_DEBUG, "Cannot remove systemd override file %s",
                   override_file);
    } else {
        systemd_daemon_reload(timeout);
    }
    free(override_file);
}

static void
systemd_unit_check(const char *name, const char *state, void *userdata)
{
    svc_action_t * op = userdata;

    crm_trace("Resource %s has %s='%s'", op->rsc, name, state);

    if(state == NULL) {
        op->rc = PCMK_OCF_NOT_RUNNING;

    } else if (g_strcmp0(state, "active") == 0) {
        op->rc = PCMK_OCF_OK;
    } else if (g_strcmp0(state, "reloading") == 0) {
        op->rc = PCMK_OCF_OK;
    } else if (g_strcmp0(state, "activating") == 0) {
        op->rc = PCMK_OCF_UNKNOWN;
        op->status = PCMK_EXEC_PENDING;
    } else if (g_strcmp0(state, "deactivating") == 0) {
        op->rc = PCMK_OCF_UNKNOWN;
        op->status = PCMK_EXEC_PENDING;
    } else {
        op->rc = PCMK_OCF_NOT_RUNNING;
    }

    if (op->synchronous == FALSE) {
        services_set_op_pending(op, NULL);
        services__finalize_async_op(op);
    }
}

gboolean
systemd_unit_exec_with_unit(svc_action_t * op, const char *unit)
{
    const char *method = op->action;
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;

    CRM_ASSERT(unit);

    if (pcmk__str_eq(op->action, "monitor", pcmk__str_casei) || pcmk__str_eq(method, "status", pcmk__str_casei)) {
        DBusPendingCall *pending = NULL;
        char *state;

        state = systemd_get_property(unit, "ActiveState",
                                     (op->synchronous? NULL : systemd_unit_check),
                                     op, (op->synchronous? NULL : &pending),
                                     op->timeout);
        if (op->synchronous) {
            systemd_unit_check("ActiveState", state, op);
            free(state);
            return op->rc == PCMK_OCF_OK;
        } else if (pending) {
            services_set_op_pending(op, pending);
            return TRUE;

        } else {
            return services__finalize_async_op(op) == pcmk_rc_ok;
        }

    } else if (g_strcmp0(method, "start") == 0) {
        method = "StartUnit";
        systemd_create_override(op->agent, op->timeout);

    } else if (g_strcmp0(method, "stop") == 0) {
        method = "StopUnit";
        systemd_remove_override(op->agent, op->timeout);

    } else if (g_strcmp0(method, "restart") == 0) {
        method = "RestartUnit";

    } else {
        op->rc = PCMK_OCF_UNIMPLEMENT_FEATURE;
        goto cleanup;
    }

    crm_debug("Calling %s for %s: %s", method, op->rsc, unit);

    msg = systemd_new_method(method);
    CRM_ASSERT(msg != NULL);

    /* (ss) */
    {
        const char *replace_s = "replace";
        char *name = systemd_service_name(op->agent);

        CRM_LOG_ASSERT(dbus_message_append_args(msg, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID));
        CRM_LOG_ASSERT(dbus_message_append_args(msg, DBUS_TYPE_STRING, &replace_s, DBUS_TYPE_INVALID));

        free(name);
    }

    if (op->synchronous == FALSE) {
        DBusPendingCall *pending = systemd_send(msg, systemd_async_dispatch,
                                                op, op->timeout);

        dbus_message_unref(msg);
        if(pending) {
            services_set_op_pending(op, pending);
            return TRUE;

        } else {
            return services__finalize_async_op(op) == pcmk_rc_ok;
        }

    } else {
        reply = systemd_send_recv(msg, NULL, op->timeout);
        dbus_message_unref(msg);
        systemd_exec_result(reply, op);

        if(reply) {
            dbus_message_unref(reply);
        }
        return FALSE;
    }

  cleanup:
    if (op->synchronous == FALSE) {
        return services__finalize_async_op(op) == pcmk_rc_ok;
    }

    return op->rc == PCMK_OCF_OK;
}

static gboolean
systemd_timeout_callback(gpointer p)
{
    svc_action_t * op = p;

    op->opaque->timerid = 0;
    crm_warn("%s operation on systemd unit %s named '%s' timed out", op->action, op->agent, op->rsc);
    services__finalize_async_op(op);
    return FALSE;
}

/* For an asynchronous 'op', returns FALSE if 'op' should be free'd by the caller */
/* For a synchronous 'op', returns FALSE if 'op' fails */
gboolean
systemd_unit_exec(svc_action_t * op)
{
    char *unit = NULL;

    CRM_ASSERT(op);
    CRM_ASSERT(systemd_init());
    op->rc = PCMK_OCF_UNKNOWN_ERROR;
    crm_debug("Performing %ssynchronous %s op on systemd unit %s named '%s'",
              op->synchronous ? "" : "a", op->action, op->agent, op->rsc);

    if (pcmk__str_eq(op->action, "meta-data", pcmk__str_casei)) {
        // @TODO Implement an async meta-data call in executor API
        op->stdout_data = systemd_unit_metadata(op->agent, op->timeout);
        op->rc = PCMK_OCF_OK;

        if (op->synchronous == FALSE) {
            return services__finalize_async_op(op) == pcmk_rc_ok;
        }
        return TRUE;
    }

    unit = systemd_unit_by_name(op->agent, op);
    free(unit);

    if (op->synchronous == FALSE) {
        if (op->opaque->pending) {
            op->opaque->timerid = g_timeout_add(op->timeout + 5000, systemd_timeout_callback, op);
            services_add_inflight_op(op);
            return TRUE;

        } else {
            return services__finalize_async_op(op) == pcmk_rc_ok;
        }
    }

    return op->rc == PCMK_OCF_OK;
}
