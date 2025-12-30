/*
 * Copyright 2012-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/services.h>
#include <crm/services_internal.h>
#include <crm/common/mainloop.h>

#include <dbus/dbus.h>
#include <inttypes.h>               // PRIu32
#include <stdbool.h>
#include <stdint.h>                 // uint32_t
#include <stdio.h>                  // fopen(), NULL, etc.
#include <sys/stat.h>

#include <gio/gio.h>
#include <glib.h>                   // g_str_has_suffix()

#include <services_private.h>
#include <systemd.h>
#include <pcmk-dbus.h>

static void invoke_unit_by_path(svc_action_t *op, const char *unit);

/* Systemd D-Bus interface
 * https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html
 */
#define BUS_NAME         "org.freedesktop.systemd1"
#define BUS_NAME_MANAGER BUS_NAME ".Manager"
#define BUS_NAME_UNIT    BUS_NAME ".Unit"
#define BUS_PATH         "/org/freedesktop/systemd1"

/*!
 * \internal
 * \brief Prepare a systemd action
 *
 * \param[in,out] op  Action to prepare
 *
 * \return Standard Pacemaker return code
 */
int
services__systemd_prepare(svc_action_t *op)
{
    op->opaque->exec = strdup("systemd-dbus");
    if (op->opaque->exec == NULL) {
        return ENOMEM;
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Map a systemd result to a standard OCF result
 *
 * \param[in] exit_status  Systemd result
 *
 * \return Standard OCF result
 */
enum ocf_exitcode
services__systemd2ocf(int exit_status)
{
    // This library uses OCF codes for systemd actions
    return (enum ocf_exitcode) exit_status;
}

static inline DBusMessage *
systemd_new_method(const char *method)
{
    pcmk__trace("Calling: %s on " BUS_NAME_MANAGER, method);
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
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;
    DBusError error;

    /* Don't call systemd_init() here, because that calls this */
    CRM_CHECK(systemd_proxy, return NULL);

    msg = systemd_new_method(method);

    if (msg == NULL) {
        pcmk__err("Could not create message to send %s to systemd", method);
        return NULL;
    }

    dbus_error_init(&error);
    reply = systemd_send_recv(msg, &error, DBUS_TIMEOUT_USE_DEFAULT);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&error)) {
        pcmk__err("Could not send %s to systemd: %s (%s)", method,
                  error.message, error.name);
        dbus_error_free(&error);
        return NULL;

    } else if (reply == NULL) {
        pcmk__err("Could not send %s to systemd: no reply received", method);
        return NULL;
    }

    return reply;
}

/*!
 * \internal
 * \brief Subscribe to D-Bus signals from systemd
 *
 * Systemd does not broadcast signal messages unless at least one client has
 * called the \c Subscribe() method. Also, a D-Bus client ignores broadcast
 * messages unless an appropriate match rule is set, so we set one here.
 *
 * \return Standard Pacemaker return code
 */
static int
subscribe_to_signals(void)
{
    const char *match_rule = "type='signal',"
                             "sender='" BUS_NAME "',"
                             "interface='" BUS_NAME_MANAGER "',"
                             "path='" BUS_PATH "'";
    DBusMessage *reply = NULL;
    DBusError error;

    /* Tell D-Bus to accept signal messages from systemd.
     * https://dbus.freedesktop.org/doc/dbus-specification.html#message-bus-routing-match-rules
     */
    dbus_error_init(&error);
    dbus_bus_add_match(systemd_proxy, match_rule, &error);

    if (dbus_error_is_set(&error)) {
        pcmk__err("Could not listen for systemd DBus signals: %s "
                  QB_XS " (%s)",
                  error.message, error.name);
        dbus_error_free(&error);
        return ECOMM;
    }

    // Tell systemd to broadcast signals
    reply = systemd_call_simple_method("Subscribe");
    if (reply == NULL) {
        dbus_bus_remove_match(systemd_proxy, match_rule, &error);
        return ECOMM;
    }

    dbus_message_unref(reply);
    return pcmk_rc_ok;
}

static bool
systemd_init(void)
{
    static int need_init = 1;
    // https://dbus.freedesktop.org/doc/api/html/group__DBusConnection.html

    if (systemd_proxy
        && dbus_connection_get_is_connected(systemd_proxy) == FALSE) {
        pcmk__warn("Connection to System DBus is closed. Reconnecting...");
        pcmk_dbus_disconnect(systemd_proxy);
        systemd_proxy = NULL;
        need_init = 1;
    }

    if (need_init) {
        need_init = 0;
        systemd_proxy = pcmk_dbus_connect();

        if (subscribe_to_signals() != pcmk_rc_ok) {
            pcmk_dbus_disconnect(systemd_proxy);
            systemd_proxy = NULL;
        }
    }

    return (systemd_proxy != NULL);
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
systemd_unit_name(const char *name, bool add_instance_name)
{
    const char *dot = NULL;

    if (pcmk__str_empty(name)) {
        return NULL;
    }

    /* Services that end with an @ sign are systemd templates.  They expect an
     * instance name to follow the service name.  If no instance name was
     * provided, just add "pacemaker" to the string as the instance name.  It
     * doesn't seem to matter for purposes of looking up whether a service
     * exists or not.
     *
     * A template can be specified either with or without the unit extension,
     * so this block handles both cases.
     */
    dot = systemd_unit_extension(name);

    if (dot) {
        if (dot != name && *(dot-1) == '@') {
            return pcmk__assert_asprintf("%.*spacemaker%s",
                                         (int) (dot - name), name, dot);
        } else {
            return pcmk__str_copy(name);
        }

    } else if (add_instance_name && *(name+strlen(name)-1) == '@') {
        return pcmk__assert_asprintf("%spacemaker.service", name);

    } else {
        return pcmk__assert_asprintf("%s.service", name);
    }
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
        pcmk__warn("Could not issue systemd reload %d: %s", reload_count,
                   error.message);
        dbus_error_free(&error);

    } else {
        pcmk__trace("Reload %d complete", reload_count);
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
    pcmk__assert(msg != NULL);
    systemd_send(msg, systemd_daemon_reload_complete,
                 GUINT_TO_POINTER(reload_count), timeout);
    dbus_message_unref(msg);

    return TRUE;
}

/*!
 * \internal
 * \brief Set an action result based on a method error
 *
 * \param[in,out] op     Action to set result for
 * \param[in]     error  Method error
 */
static void
set_result_from_method_error(svc_action_t *op, const DBusError *error)
{
    services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                         "Unable to invoke systemd DBus method");

    if (dbus_error_has_name(error, "org.freedesktop.systemd1.InvalidName")
        || dbus_error_has_name(error, "org.freedesktop.systemd1.LoadFailed")
        || dbus_error_has_name(error, "org.freedesktop.systemd1.NoSuchUnit")) {

        if (pcmk__str_eq(op->action, PCMK_ACTION_STOP, pcmk__str_casei)) {
            pcmk__trace("Masking systemd stop failure (%s) for %s "
                        "because unknown service can be considered stopped",
                        error->name, pcmk__s(op->rsc, "unknown resource"));
            services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
            return;
        }

        services__format_result(op, PCMK_OCF_NOT_INSTALLED,
                               PCMK_EXEC_NOT_INSTALLED,
                               "systemd unit %s not found", op->agent);

    /* If systemd happens to be re-executing by `systemctl daemon-reexec` at the
     * same time, dbus gives an error with the name
     * `org.freedesktop.DBus.Error.NoReply` and the message "Message recipient
     * disconnected from message bus without replying".
     * Consider the monitor pending rather than return an error yet, so that it
     * can retry with another iteration.
     */
    } else if (pcmk__str_any_of(op->action, PCMK_ACTION_MONITOR,
                                PCMK_ACTION_STATUS, NULL)
               && dbus_error_has_name(error, DBUS_ERROR_NO_REPLY)
               && (strstr(error->message, "disconnected") != NULL)) {
        services__set_result(op, PCMK_OCF_UNKNOWN, PCMK_EXEC_PENDING, NULL);
    }

    pcmk__info("DBus request for %s of systemd unit %s%s%s failed: %s",
               op->action, op->agent,
               ((op->rsc != NULL)? " for resource " : ""), pcmk__s(op->rsc, ""),
               error->message);
}

/*!
 * \internal
 * \brief Extract unit path from LoadUnit reply, and execute action
 *
 * \param[in]     reply  LoadUnit reply
 * \param[in,out] op     Action to execute (or NULL to just return path)
 *
 * \return DBus object path for specified unit if successful (only valid for
 *         lifetime of \p reply), otherwise NULL
 */
static const char *
execute_after_loadunit(DBusMessage *reply, svc_action_t *op)
{
    const char *path = NULL;
    DBusError error;

    /* path here is not used other than as a non-NULL flag to indicate that a
     * request was indeed sent
     */
    if (pcmk_dbus_find_error((void *) &path, reply, &error)) {
        if (op != NULL) {
            set_result_from_method_error(op, &error);
        }
        dbus_error_free(&error);

    } else if (!pcmk_dbus_type_check(reply, NULL, DBUS_TYPE_OBJECT_PATH,
                                     __func__, __LINE__)) {
        if (op != NULL) {
            services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                                 "systemd DBus method had unexpected reply");
            pcmk__info("Could not load systemd unit %s for %s: DBus reply has "
                       "unexpected type",
                       op->agent, op->id);
        } else {
            pcmk__info("Could not load systemd unit: DBus reply has unexpected "
                       "type");
        }

    } else {
        dbus_message_get_args (reply, NULL,
                               DBUS_TYPE_OBJECT_PATH, &path,
                               DBUS_TYPE_INVALID);
    }

    if (op != NULL) {
        if (path != NULL) {
            invoke_unit_by_path(op, path);

        } else if (!(op->synchronous)) {
            if (!pcmk__str_any_of(op->action, PCMK_ACTION_MONITOR,
                                  PCMK_ACTION_STATUS, NULL)
                || op->status != PCMK_EXEC_PENDING) {
                services__format_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                                        "No DBus object found for systemd unit %s",
                                        op->agent);
            }
            services__finalize_async_op(op);
        }
    }

    return path;
}

/*!
 * \internal
 * \brief Execute a systemd action after its LoadUnit completes
 *
 * \param[in,out] pending    If not NULL, DBus call associated with LoadUnit
 * \param[in,out] user_data  Action to execute
 */
static void
loadunit_completed(DBusPendingCall *pending, void *user_data)
{
    DBusMessage *reply = NULL;
    svc_action_t *op = user_data;

    pcmk__trace("LoadUnit result for %s arrived", op->id);

    // Grab the reply
    if (pending != NULL) {
        reply = dbus_pending_call_steal_reply(pending);
    }

    // The call is no longer pending
    CRM_LOG_ASSERT(pending == op->opaque->pending);
    services_set_op_pending(op, NULL);

    // Execute the desired action based on the reply
    execute_after_loadunit(reply, user_data);
    if (reply != NULL) {
        dbus_message_unref(reply);
    }
}

/*!
 * \internal
 * \brief Execute a systemd action, given the unit name
 *
 * \param[in]     arg_name  Unit name (possibly without ".service" extension)
 * \param[in,out] op        Action to execute (if NULL, just get object path)
 * \param[out]    path      If non-NULL and \p op is NULL or synchronous, where
 *                          to store DBus object path for specified unit
 *
 * \return Standard Pacemaker return code (for NULL \p op, pcmk_rc_ok means unit
 *         was found; for synchronous actions, pcmk_rc_ok means unit was
 *         executed, with the actual result stored in \p op; for asynchronous
 *         actions, pcmk_rc_ok means action was initiated)
 * \note It is the caller's responsibility to free the path.
 */
static int
invoke_unit_by_name(const char *arg_name, svc_action_t *op, char **path)
{
    DBusMessage *msg;
    DBusMessage *reply = NULL;
    DBusPendingCall *pending = NULL;
    char *name = NULL;

    if (pcmk__str_empty(arg_name)) {
        return EINVAL;
    }

    if (!systemd_init()) {
        if (op != NULL) {
            services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                                 "No DBus connection");
        }
        return ENOTCONN;
    }

    /* Create a LoadUnit DBus method (equivalent to GetUnit if already loaded),
     * which makes the unit usable via further DBus methods.
     *
     * <method name="LoadUnit">
     *  <arg name="name" type="s" direction="in"/>
     *  <arg name="unit" type="o" direction="out"/>
     * </method>
     */
    msg = systemd_new_method("LoadUnit");
    pcmk__assert(msg != NULL);

    // Add the (expanded) unit name as the argument
    name = systemd_unit_name(arg_name,
                             (op == NULL)
                             || pcmk__str_eq(op->action, PCMK_ACTION_META_DATA,
                                             pcmk__str_none));
    CRM_LOG_ASSERT(dbus_message_append_args(msg, DBUS_TYPE_STRING, &name,
                                            DBUS_TYPE_INVALID));
    free(name);

    if ((op == NULL) || op->synchronous) {
        // For synchronous ops, wait for a reply and extract the result
        const char *unit = NULL;
        int rc = pcmk_rc_ok;

        reply = systemd_send_recv(msg, NULL,
                                  (op? op->timeout : DBUS_TIMEOUT_USE_DEFAULT));
        dbus_message_unref(msg);

        unit = execute_after_loadunit(reply, op);
        if (unit == NULL) {
            rc = ENOENT;
            if (path != NULL) {
                *path = NULL;
            }
        } else if (path != NULL) {
            *path = strdup(unit);
            if (*path == NULL) {
                rc = ENOMEM;
            }
        }

        if (reply != NULL) {
            dbus_message_unref(reply);
        }
        return rc;
    }

    // For asynchronous ops, initiate the LoadUnit call and return
    pending = systemd_send(msg, loadunit_completed, op, op->timeout);
    if (pending == NULL) {
        services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                             "Unable to send DBus message");
        dbus_message_unref(msg);
        return ECOMM;
    }

    // LoadUnit was successfully initiated
    services__set_result(op, PCMK_OCF_UNKNOWN, PCMK_EXEC_PENDING, NULL);
    services_set_op_pending(op, pending);
    dbus_message_unref(msg);
    return pcmk_rc_ok;
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

    if (!systemd_init()) {
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
        pcmk__err("Could not list systemd unit files: systemd reply has no "
                  "arguments");
        dbus_message_unref(reply);
        return NULL;
    }
    if (!pcmk_dbus_type_check(reply, &args, DBUS_TYPE_ARRAY,
                              __func__, __LINE__)) {
        pcmk__err("Could not list systemd unit files: systemd reply has "
                  "invalid arguments");
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
            pcmk__warn("Skipping systemd reply argument with unexpected type");
            continue;
        }

        dbus_message_iter_recurse(&unit, &elem);
        if(!pcmk_dbus_type_check(reply, &elem, DBUS_TYPE_STRING, __func__, __LINE__)) {
            pcmk__warn("Skipping systemd reply argument with no string");
            continue;
        }

        dbus_message_iter_get_basic(&elem, &value);
        if (value.str == NULL) {
            pcmk__debug("ListUnitFiles reply did not provide a string");
            continue;
        }
        pcmk__trace("DBus ListUnitFiles listed: %s", value.str);

        match = systemd_unit_extension(value.str);
        if (match == NULL) {
            // This is not a unit file type we know how to manage
            pcmk__debug("ListUnitFiles entry '%s' is not supported as resource",
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

    pcmk__trace("Found %d manageable systemd unit files", nfiles);
    units = g_list_sort(units, sort_str);
    return units;
}

bool
systemd_unit_exists(const char *name)
{
    char *path = NULL;
    char *state = NULL;
    int rc = false;

    /* Note: Makes a blocking dbus calls
     * Used by resources_find_service_class() when resource class=service
     */
    if ((invoke_unit_by_name(name, NULL, &path) != pcmk_rc_ok)
        || (path == NULL)) {
        goto done;
    }

    /* A successful LoadUnit is not sufficient to determine the unit's
     * existence; it merely means the LoadUnit request received a reply.
     * We must make another blocking call to check the LoadState property.
     */
    state = systemd_get_property(path, "LoadState", NULL, NULL, NULL,
                                 DBUS_TIMEOUT_USE_DEFAULT);
    rc = pcmk__str_any_of(state, "loaded", "masked", NULL);

done:
    free(path);
    free(state);
    return rc;
}

// @TODO Use XML string constants and maybe a real XML object
#define METADATA_FORMAT                                                        \
    "<?xml " PCMK_XA_VERSION "=\"1.0\"?>\n"                                    \
    "<" PCMK_XE_RESOURCE_AGENT " "                                             \
        PCMK_XA_NAME "=\"%s\" "                                                \
        PCMK_XA_VERSION "=\"" PCMK_DEFAULT_AGENT_VERSION "\">\n"               \
    "  <" PCMK_XE_VERSION ">1.1</" PCMK_XE_VERSION ">\n"                       \
    "  <" PCMK_XE_LONGDESC " " PCMK_XA_LANG "=\"" PCMK__VALUE_EN "\">\n"       \
    "    %s\n"                                                                 \
    "  </" PCMK_XE_LONGDESC ">\n"                                              \
    "  <" PCMK_XE_SHORTDESC " " PCMK_XA_LANG "=\"" PCMK__VALUE_EN "\">"        \
        "systemd unit file for %s"                                             \
      "</" PCMK_XE_SHORTDESC ">\n"                                             \
    "  <" PCMK_XE_PARAMETERS "/>\n"                                            \
    "  <" PCMK_XE_ACTIONS ">\n"                                                \
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "=\"" PCMK_ACTION_START "\""       \
                           " " PCMK_META_TIMEOUT "=\"100s\" />\n"              \
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "=\"" PCMK_ACTION_STOP "\""        \
                           " " PCMK_META_TIMEOUT "=\"100s\" />\n"              \
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "=\"" PCMK_ACTION_STATUS "\""      \
                           " " PCMK_META_TIMEOUT "=\"100s\" />\n"              \
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "=\"" PCMK_ACTION_MONITOR "\""     \
                           " " PCMK_META_TIMEOUT "=\"100s\""                   \
                           " " PCMK_META_INTERVAL "=\"60s\" />\n"              \
    "    <" PCMK_XE_ACTION " " PCMK_XA_NAME "=\"" PCMK_ACTION_META_DATA "\""   \
                           " " PCMK_META_TIMEOUT "=\"5s\" />\n"                \
    "  </" PCMK_XE_ACTIONS ">\n"                                               \
    "  <" PCMK_XE_SPECIAL " " PCMK_XA_TAG "=\"systemd\"/>\n"                   \
    "</" PCMK_XE_RESOURCE_AGENT ">\n"

static char *
systemd_unit_metadata(const char *name, int timeout)
{
    char *meta = NULL;
    char *desc = NULL;
    char *path = NULL;
    gchar *desc_esc = NULL;

    if (invoke_unit_by_name(name, NULL, &path) == pcmk_rc_ok) {
        /* TODO: Worth a making blocking call for? Probably not. Possibly if cached. */
        desc = systemd_get_property(path, "Description", NULL, NULL, NULL,
                                    timeout);
    } else {
        desc = pcmk__assert_asprintf("Systemd unit file for %s", name);
    }

    desc_esc = pcmk__xml_escape(desc, pcmk__xml_escape_text);
    meta = pcmk__assert_asprintf(METADATA_FORMAT, name, desc_esc, name);

    free(desc);
    free(path);
    g_free(desc_esc);
    return meta;
}

/*!
 * \internal
 * \brief Determine result of method from reply
 *
 * \param[in]     reply  Reply to start, stop, or restart request
 * \param[in,out] op     Action that was executed
 */
static void
process_unit_method_reply(DBusMessage *reply, svc_action_t *op)
{
    bool start_stop = pcmk__strcase_any_of(op->action, PCMK_ACTION_START,
                                           PCMK_ACTION_STOP, NULL);
    DBusError error;

    dbus_error_init(&error);

    /* The first use of error here is not used other than as a non-NULL flag to
     * indicate that a request was indeed sent
     */
    if (pcmk_dbus_find_error((void *) &error, reply, &error)) {
        set_result_from_method_error(op, &error);
        dbus_error_free(&error);

    } else if (!pcmk_dbus_type_check(reply, NULL, DBUS_TYPE_OBJECT_PATH,
                                     __func__, __LINE__)) {
        const char *reason = "systemd D-Bus method had unexpected reply";

        pcmk__info("DBus request for %s of %s succeeded but return type was "
                   "unexpected",
                   op->action, pcmk__s(op->rsc, "unknown resource"));

        if (!op->synchronous && start_stop) {
            /* The start or stop job is enqueued but is not complete. We need a
             * job path to detect completion in job_removed_filter().
             */
            services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                                 reason);

        } else {
            /* Something weird happened, but the action is finished and there
             * was no D-Bus error. So call it a success.
             */
            services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, reason);
        }

    } else {
        const char *path = NULL;

        dbus_message_get_args(reply, NULL,
                              DBUS_TYPE_OBJECT_PATH, &path,
                              DBUS_TYPE_INVALID);

        pcmk__debug("DBus request for %s of %s using %s succeeded",
                    op->action, pcmk__s(op->rsc, "unknown resource"), path);

        if (!op->synchronous && start_stop) {
            // Should be set to unknown/pending already
            services__set_result(op, PCMK_OCF_UNKNOWN, PCMK_EXEC_PENDING, NULL);
            pcmk__str_update(&(op->opaque->job_path), path);

        } else {
            services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
        }
    }
}

/*!
 * \internal
 * \brief Process a systemd \c JobRemoved signal for a given service action
 *
 * This filter is expected to be added with \c finalize_async_action_dbus() as
 * the \c free_data_function. Then if \p message is a \c JobRemoved signal for
 * the action specified by \p user_data, the action's result is set, the filter
 * is removed, and the action is finalized.
 *
 * \param[in,out] connection  D-Bus connection
 * \param[in]     message     D-Bus message
 * \param[in,out] user_data   Service action (\c svc_action_t)
 *
 * \retval \c DBUS_HANDLER_RESULT_HANDLED if \p message is a \c JobRemoved
 *         signal for \p user_data
 * \retval \c DBUS_HANDLER_RESULT_NOT_YET_HANDLED otherwise (on error, if
 *         \p message is not a \c JobRemoved signal, or if the signal is for
 *         some other action's job)
 */
static DBusHandlerResult
job_removed_filter(DBusConnection *connection, DBusMessage *message,
                   void *user_data)
{
    svc_action_t *action = user_data;
    const char *action_name = NULL;
    uint32_t job_id = 0;
    const char *bus_path = NULL;
    const char *unit_name = NULL;
    const char *result = NULL;
    DBusError error;

    CRM_CHECK((connection != NULL) && (message != NULL),
              return DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

    // action should always be set when the filter is added
    if ((action == NULL)
        || !dbus_message_is_signal(message, BUS_NAME_MANAGER, "JobRemoved")) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    dbus_error_init(&error);
    if (!dbus_message_get_args(message, &error,
                               DBUS_TYPE_UINT32, &job_id,
                               DBUS_TYPE_OBJECT_PATH, &bus_path,
                               DBUS_TYPE_STRING, &unit_name,
                               DBUS_TYPE_STRING, &result,
                               DBUS_TYPE_INVALID)) {
        pcmk__err("Could not interpret systemd DBus signal: %s " QB_XS " (%s)",
                  error.message, error.name);
        dbus_error_free(&error);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    if (!pcmk__str_eq(bus_path, action->opaque->job_path, pcmk__str_none)) {
        // This filter is not for this job
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    action_name = pcmk__s(action->action, "(unknown)");

    pcmk__trace("Setting %s result for %s (JobRemoved id=%" PRIu32
                ", result=%s",
                action_name, unit_name, job_id, result);

    if (pcmk__str_eq(result, "done", pcmk__str_none)) {
        services__set_result(action, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);

    } else if (pcmk__str_eq(result, "timeout", pcmk__str_none)) {
        services__format_result(action, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_TIMEOUT,
                                "systemd %s job for %s timed out",
                                action_name, unit_name);

    } else {
        services__format_result(action, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                                "systemd %s job for %s failed with result '%s'",
                                action_name, unit_name, result);
    }

    /* This instance of the filter was specifically for the given action.
     *
     * The action gets finalized by services__finalize_async_op() via the
     * filter's free_data_function.
     */
    dbus_connection_remove_filter(systemd_proxy, job_removed_filter, action);
    return DBUS_HANDLER_RESULT_HANDLED;
}

/*!
 * \internal
 * \brief \c DBusFreeFunction wrapper for \c services__finalize_async_op()
 *
 * \param[in,out] action  Asynchronous service action to finalize
 */
static void
finalize_async_action_dbus(void *action)
{
    services__finalize_async_op((svc_action_t *) action);
}

/*!
 * \internal
 * \brief Process the completion of an asynchronous unit start, stop, or restart
 *
 * \param[in,out] pending    If not NULL, DBus call associated with request
 * \param[in,out] user_data  Action that was executed
 */
static void
unit_method_complete(DBusPendingCall *pending, void *user_data)
{
    DBusMessage *reply = NULL;
    svc_action_t *op = user_data;

    pcmk__trace("Result for %s arrived", op->id);

    // Grab the reply
    if (pending != NULL) {
        reply = dbus_pending_call_steal_reply(pending);
    }

    // The call is no longer pending
    CRM_LOG_ASSERT(pending == op->opaque->pending);
    services_set_op_pending(op, NULL);

    process_unit_method_reply(reply, op);

    if (reply != NULL) {
        dbus_message_unref(reply);
    }

    if ((op->status == PCMK_EXEC_PENDING)
        && pcmk__strcase_any_of(op->action, PCMK_ACTION_START, PCMK_ACTION_STOP,
                                NULL)) {
        /* Start and stop method calls return when the job is enqueued, not when
         * it's complete. Start and stop actions must be finalized after the job
         * is complete, because the action callback function may use it. We add
         * a message filter to process the JobRemoved signal, which indicates
         * completion.
         *
         * The filter takes ownership of op, which will be finalized when the
         * filter is later removed.
         */
        if (dbus_connection_add_filter(systemd_proxy, job_removed_filter, op,
                                       finalize_async_action_dbus)) {
            return;
        }
        pcmk__err("Could not add D-Bus filter for systemd JobRemoved signals");
        services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                             "Failed to add D-Bus filter for systemd "
                             "JobRemoved signal");
    }
    services__finalize_async_op(op);
}

/* When the cluster manages a systemd resource, we create a unit file override
 * to order the service "before" pacemaker. The "before" relationship won't
 * actually be used, since systemd won't ever start the resource -- we're
 * interested in the reverse shutdown ordering it creates, to ensure that
 * systemd doesn't stop the resource at shutdown while pacemaker is still
 * running.
 *
 * @TODO Add start timeout
 */
#define SYSTEMD_UNIT_OVERRIDE_TEMPLATE                      \
    "[Unit]\n"                                              \
    "Description=Cluster Controlled %s\n"                   \
    "Before=pacemaker.service pacemaker_remote.service\n"

#define SYSTEMD_SERVICE_OVERRIDE                            \
    "\n"                                                    \
    "[Service]\n"                                           \
    "Restart=no\n"

/*!
 * \internal
 * \brief Get runtime drop-in directory path for a systemd unit
 *
 * \param[in] unit_name  Systemd unit (with extension)
 *
 * \return Drop-in directory path
 */
static GString *
get_override_dir(const char *unit_name)
{
    GString *buf = g_string_sized_new(128);

    pcmk__g_strcat(buf, "/run/systemd/system/", unit_name, ".d", NULL);
    return buf;
}

/*!
 * \internal
 * \brief Append systemd override filename to a directory path
 *
 * \param[in,out] buf  Buffer containing directory path to append to
 */
static inline void
append_override_basename(GString *buf)
{
    g_string_append(buf, "/50-pacemaker.conf");
}

/*!
 * \internal
 * \brief Create a runtime override file for a systemd unit
 *
 * The systemd daemon is then reloaded. This file does not survive a reboot.
 *
 * \param[in] agent    Systemd resource agent
 * \param[in] timeout  Timeout for systemd daemon reload
 *
 * \return Standard Pacemaker return code
 *
 * \note Any configuration in \c /etc takes precedence over our drop-in.
 * \todo Document this in Pacemaker Explained or Administration?
 */
static int
systemd_create_override(const char *agent, int timeout)
{
    char *unit_name = NULL;
    GString *filename = NULL;
    GString *override = NULL;
    FILE *fp = NULL;
    int fd = 0;
    int rc = pcmk_rc_ok;

    unit_name = systemd_unit_name(agent, false);
    CRM_CHECK(!pcmk__str_empty(unit_name),
              rc = EINVAL; goto done);

    filename = get_override_dir(unit_name);
    rc = pcmk__build_path(filename->str, 0755);
    if (rc != pcmk_rc_ok) {
        pcmk__err("Could not create systemd override directory %s: %s",
                  filename->str, pcmk_rc_str(rc));
        goto done;
    }

    append_override_basename(filename);
    fp = fopen(filename->str, "w");
    if (fp == NULL) {
        rc = errno;
        pcmk__err("Cannot open systemd override file %s for writing: %s",
                  filename->str, pcmk_rc_str(rc));
        goto done;
    }

    // Ensure the override file is world-readable (avoid systemd warning in log)
    fd = fileno(fp);
    if ((fd < 0) || (fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH) < 0)) {
        rc = errno;
        pcmk__err("Failed to set permissions on systemd override file %s: %s",
                  filename->str, pcmk_rc_str(rc));
        goto done;
    }

    override = g_string_sized_new(2 * sizeof(SYSTEMD_UNIT_OVERRIDE_TEMPLATE));
    g_string_printf(override, SYSTEMD_UNIT_OVERRIDE_TEMPLATE, unit_name);
    if (g_str_has_suffix(unit_name, ".service")) {
        g_string_append(override, SYSTEMD_SERVICE_OVERRIDE);
    }

    if (fputs(override->str, fp) == EOF) {
        rc = EIO;
        pcmk__err("Cannot write to systemd override file %s", filename->str);
    }

done:
    if (fp != NULL) {
        fclose(fp);
    }

    if (rc == pcmk_rc_ok) {
        // @TODO Make sure the reload succeeds
        systemd_daemon_reload(timeout);

    } else if (fp != NULL) {
        // File was created, so remove it
        unlink(filename->str);
    }

    free(unit_name);

    // coverity[check_after_deref : FALSE]
    if (filename != NULL) {
        g_string_free(filename, TRUE);
    }
    if (override != NULL) {
        g_string_free(override, TRUE);
    }
    return rc;
}

static void
systemd_remove_override(const char *agent, int timeout)
{
    char *unit_name = systemd_unit_name(agent, false);
    GString *filename = NULL;

    CRM_CHECK(!pcmk__str_empty(unit_name), goto done);

    filename = get_override_dir(unit_name);
    append_override_basename(filename);

    if (unlink(filename->str) < 0) {
        int rc = errno;

        if (rc != ENOENT) {
            // Stop may be called when already stopped, which is fine
            pcmk__warn("Cannot remove systemd override file %s: %s",
                       filename->str, pcmk_rc_str(rc));
        }

    } else {
        systemd_daemon_reload(timeout);
    }

done:
    free(unit_name);

    // coverity[check_after_deref : FALSE]
    if (filename != NULL) {
        g_string_free(filename, TRUE);
    }
}

/*!
 * \internal
 * \brief Parse result of systemd status check
 *
 * Set a status action's exit status and execution status based on a DBus
 * property check result, and finalize the action if asynchronous.
 *
 * \param[in]     name      DBus interface name for property that was checked
 * \param[in]     state     Property value
 * \param[in,out] userdata  Status action that check was done for
 */
static void
parse_status_result(const char *name, const char *state, void *userdata)
{
    svc_action_t *op = userdata;

    pcmk__trace("Resource %s has %s='%s'", pcmk__s(op->rsc, "(unspecified)"),
                name, pcmk__s(state, "<null>"));

    if (pcmk__str_eq(state, "active", pcmk__str_none)) {
        services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);

    } else if (pcmk__str_eq(state, "reloading", pcmk__str_none)) {
        services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);

    } else if (pcmk__str_eq(state, "activating", pcmk__str_none)) {
        services__set_result(op, PCMK_OCF_UNKNOWN, PCMK_EXEC_PENDING, NULL);

    } else if (pcmk__str_eq(state, "deactivating", pcmk__str_none)) {
        services__set_result(op, PCMK_OCF_UNKNOWN, PCMK_EXEC_PENDING, NULL);

    } else {
        services__set_result(op, PCMK_OCF_NOT_RUNNING, PCMK_EXEC_DONE, state);
    }

    if (!(op->synchronous)) {
        services_set_op_pending(op, NULL);
        services__finalize_async_op(op);
    }
}

/*!
 * \internal
 * \brief Invoke a systemd unit, given its DBus object path
 *
 * \param[in,out] op    Action to execute
 * \param[in]     unit  DBus object path of systemd unit to invoke
 */
static void
invoke_unit_by_path(svc_action_t *op, const char *unit)
{
    const char *method = NULL;
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;

    if (pcmk__str_any_of(op->action, PCMK_ACTION_MONITOR, PCMK_ACTION_STATUS,
                         NULL)) {
        DBusPendingCall *pending = NULL;
        char *state;

        state = systemd_get_property(unit, "ActiveState",
                                     (op->synchronous? NULL : parse_status_result),
                                     op, (op->synchronous? NULL : &pending),
                                     op->timeout);
        if (op->synchronous) {
            parse_status_result("ActiveState", state, op);
            free(state);

        } else if (pending == NULL) { // Could not get ActiveState property
            services__format_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                                    "Could not get state for unit %s from DBus",
                                    op->agent);
            services__finalize_async_op(op);

        } else {
            services_set_op_pending(op, pending);
        }
        return;

    } else if (pcmk__str_eq(op->action, PCMK_ACTION_START, pcmk__str_none)) {
        int rc = pcmk_rc_ok;

        method = "StartUnit";
        rc = systemd_create_override(op->agent, op->timeout);
        if (rc != pcmk_rc_ok) {
            services__format_result(op, pcmk_rc2ocf(rc), PCMK_EXEC_ERROR,
                                    "Failed to create systemd override file "
                                    "for %s",
                                    pcmk__s(op->agent, "(unspecified)"));
            if (!(op->synchronous)) {
                services__finalize_async_op(op);
            }
            return;
        }

    } else if (pcmk__str_eq(op->action, PCMK_ACTION_STOP, pcmk__str_none)) {
        method = "StopUnit";
        systemd_remove_override(op->agent, op->timeout);

    } else if (pcmk__str_eq(op->action, "restart", pcmk__str_none)) {
        method = "RestartUnit";

    } else {
        services__format_result(op, PCMK_OCF_UNIMPLEMENT_FEATURE,
                                PCMK_EXEC_ERROR,
                                "Action %s not implemented "
                                "for systemd resources",
                                pcmk__s(op->action, "(unspecified)"));
        if (!(op->synchronous)) {
            services__finalize_async_op(op);
        }
        return;
    }

    pcmk__trace("Calling %s for unit path %s%s%s", method, unit,
                ((op->rsc != NULL)? " for resource " : ""),
                pcmk__s(op->rsc, ""));

    msg = systemd_new_method(method);
    pcmk__assert(msg != NULL);

    /* (ss) */
    {
        const char *replace_s = "replace";
        char *name = systemd_unit_name(op->agent,
                                       pcmk__str_eq(op->action,
                                                    PCMK_ACTION_META_DATA,
                                                    pcmk__str_none));

        CRM_LOG_ASSERT(dbus_message_append_args(msg, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID));
        CRM_LOG_ASSERT(dbus_message_append_args(msg, DBUS_TYPE_STRING, &replace_s, DBUS_TYPE_INVALID));

        free(name);
    }

    if (op->synchronous) {
        reply = systemd_send_recv(msg, NULL, op->timeout);
        dbus_message_unref(msg);
        process_unit_method_reply(reply, op);
        if (reply != NULL) {
            dbus_message_unref(reply);
        }

    } else {
        DBusPendingCall *pending = systemd_send(msg, unit_method_complete, op,
                                                op->timeout);

        dbus_message_unref(msg);
        if (pending == NULL) {
            services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                                 "Unable to send DBus message");
            services__finalize_async_op(op);

        } else {
            services_set_op_pending(op, pending);
        }
    }
}

static gboolean
systemd_timeout_callback(gpointer p)
{
    svc_action_t * op = p;

    op->opaque->timerid = 0;
    pcmk__info("%s action for systemd unit %s named '%s' timed out", op->action,
               op->agent, op->rsc);
    services__format_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_TIMEOUT,
                            "%s action for systemd unit %s "
                            "did not complete in time", op->action, op->agent);

    if (op->opaque->job_path != NULL) {
        // A filter owns this op
        dbus_connection_remove_filter(systemd_proxy, job_removed_filter, op);

    } else {
        services__finalize_async_op(op);
    }
    return FALSE;
}

/*!
 * \internal
 * \brief Execute a systemd action
 *
 * \param[in,out] op  Action to execute
 *
 * \return Standard Pacemaker return code
 * \retval EBUSY          Recurring operation could not be initiated
 * \retval pcmk_rc_error  Synchronous action failed
 * \retval pcmk_rc_ok     Synchronous action succeeded, or asynchronous action
 *                        should not be freed (because it's pending or because
 *                        it failed to execute and was already freed)
 *
 * \note If the return value for an asynchronous action is not pcmk_rc_ok, the
 *       caller is responsible for freeing the action.
 */
int
services__execute_systemd(svc_action_t *op)
{
    pcmk__assert(op != NULL);

    if (pcmk__str_empty(op->action) || pcmk__str_empty(op->agent)) {
        services__set_result(op, PCMK_OCF_NOT_CONFIGURED, PCMK_EXEC_ERROR_FATAL,
                             "Bug in action caller");
        goto done;
    }

    if (!systemd_init()) {
        services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                             "No DBus connection");
        goto done;
    }

    pcmk__debug("Performing %ssynchronous %s op on systemd unit %s%s%s",
                (op->synchronous? "" : "a"), op->action, op->agent,
                ((op->rsc != NULL)? " for resource " : ""),
                pcmk__s(op->rsc, ""));

    if (pcmk__str_eq(op->action, PCMK_ACTION_META_DATA, pcmk__str_casei)) {
        op->stdout_data = systemd_unit_metadata(op->agent, op->timeout);
        services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
        goto done;
    }

    /* invoke_unit_by_name() should always override these values, which are here
     * just as a fail-safe in case there are any code paths that neglect to
     */
    services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                         "Bug in service library");

    if (invoke_unit_by_name(op->agent, op, NULL) == pcmk_rc_ok) {
        // @TODO Why plus 5000? No explanation in fccd046.
        op->opaque->timerid = pcmk__create_timer(op->timeout + 5000,
                                                 systemd_timeout_callback, op);
        services_add_inflight_op(op);
        return pcmk_rc_ok;
    }

done:
    if (op->synchronous) {
        return (op->rc == PCMK_OCF_OK)? pcmk_rc_ok : pcmk_rc_error;
    } else {
        return services__finalize_async_op(op);
    }
}
