/*
 * Copyright 2014-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <dbus/dbus.h>
#include <pcmk-dbus.h>

/*
 * DBus message dispatch
 */

// List of DBus connections (DBusConnection*) with messages available
static GList *conn_dispatches = NULL;

/*!
 * \internal
 * \brief Save an indication that DBus messages need dispatching
 *
 * \param[in] connection  DBus connection with messages to dispatch
 * \param[in] new_status  Dispatch status as reported by DBus library
 * \param[in] data        Ignored
 *
 * \note This is suitable to be used as a DBus status dispatch function.
 *       As mentioned in the DBus documentation, dbus_connection_dispatch() must
 *       not be called from within this function, and any re-entrancy is a bad
 *       idea. Instead, this should just flag the main loop that messages need
 *       to be dispatched.
 */
static void
update_dispatch_status(DBusConnection *connection,
                       DBusDispatchStatus new_status, void *data)
{
    if (new_status == DBUS_DISPATCH_DATA_REMAINS) {
        crm_trace("DBus connection has messages available for dispatch");
        conn_dispatches = g_list_prepend(conn_dispatches, connection);
    } else {
        crm_trace("DBus connection has no messages available for dispatch "
                  "(status %d)", new_status);
    }
}

/*!
 * \internal
 * \brief Dispatch available messages on all DBus connections
 */
static void
dispatch_messages(void)
{
    for (GList *gIter = conn_dispatches; gIter != NULL; gIter = gIter->next) {
        DBusConnection *connection = gIter->data;

        while (dbus_connection_get_dispatch_status(connection)
               == DBUS_DISPATCH_DATA_REMAINS) {
            crm_trace("Dispatching available messages on DBus connection");
            dbus_connection_dispatch(connection);
        }
    }
    g_list_free(conn_dispatches);
    conn_dispatches = NULL;
}


/*
 * DBus file descriptor watches
 *
 * The DBus library allows the caller to register functions for the library to
 * use for file descriptor notifications via a main loop.
 */

/* Copied from dbus-watch.c */
static const char*
dbus_watch_flags_to_string(int flags)
{
    const char *watch_type;

    if ((flags & DBUS_WATCH_READABLE) && (flags & DBUS_WATCH_WRITABLE)) {
        watch_type = "read/write";
    } else if (flags & DBUS_WATCH_READABLE) {
        watch_type = "read";
    } else if (flags & DBUS_WATCH_WRITABLE) {
        watch_type = "write";
    } else {
        watch_type = "neither read nor write";
    }
    return watch_type;
}

/*!
 * \internal
 * \brief Dispatch data available on a DBus file descriptor watch
 *
 * \param[in] userdata  Pointer to the DBus watch
 *
 * \return Always 0
 * \note This is suitable for use as a dispatch function in
 *       struct mainloop_fd_callbacks (which means that a negative return value
 *       would indicate the file descriptor is no longer required).
 */
static int
dispatch_fd_data(gpointer userdata)
{
    bool oom = FALSE;
    DBusWatch *watch = userdata;
    int flags = dbus_watch_get_flags(watch);
    bool enabled = dbus_watch_get_enabled (watch);

    crm_trace("Dispatching DBus watch for file descriptor %d "
              "with flags %#x (%s)",
              dbus_watch_get_unix_fd(watch), flags,
              dbus_watch_flags_to_string(flags));

    if (enabled && (flags & (DBUS_WATCH_READABLE|DBUS_WATCH_WRITABLE))) {
        oom = !dbus_watch_handle(watch, flags);

    } else if (enabled) {
        oom = !dbus_watch_handle(watch, DBUS_WATCH_ERROR);
    }

    if (flags != dbus_watch_get_flags(watch)) {
        flags = dbus_watch_get_flags(watch);
        crm_trace("Dispatched DBus file descriptor watch: now %#x (%s)",
                  flags, dbus_watch_flags_to_string(flags));
    }

    if (oom) {
        crm_crit("Could not dispatch DBus file descriptor data: Out of memory");
    } else {
        dispatch_messages();
    }
    return 0;
}

static void
watch_fd_closed(gpointer userdata)
{
    crm_trace("DBus watch for file descriptor %d is now closed",
              dbus_watch_get_unix_fd((DBusWatch *) userdata));
}

static struct mainloop_fd_callbacks pcmk_dbus_cb = {
    .dispatch = dispatch_fd_data,
    .destroy = watch_fd_closed,
};

static dbus_bool_t
add_dbus_watch(DBusWatch *watch, void *data)
{
    int fd = dbus_watch_get_unix_fd(watch);

    mainloop_io_t *client = mainloop_add_fd("dbus", G_PRIORITY_DEFAULT, fd,
                                            watch, &pcmk_dbus_cb);

    crm_trace("Added DBus watch for file descriptor %d", fd);
    dbus_watch_set_data(watch, client, NULL);
    return TRUE;
}

static void
toggle_dbus_watch(DBusWatch *watch, void *data)
{
    // @TODO Should this do something more?
    crm_debug("DBus watch for file descriptor %d is now %s",
              dbus_watch_get_unix_fd(watch),
              (dbus_watch_get_enabled(watch)? "enabled" : "disabled"));
}

static void
remove_dbus_watch(DBusWatch *watch, void *data)
{
    crm_trace("Removed DBus watch for file descriptor %d",
              dbus_watch_get_unix_fd(watch));
    mainloop_del_fd((mainloop_io_t *) dbus_watch_get_data(watch));
}

static void
register_watch_functions(DBusConnection *connection)
{
    dbus_connection_set_watch_functions(connection, add_dbus_watch,
                                        remove_dbus_watch,
                                        toggle_dbus_watch, NULL, NULL);
}

/*
 * DBus main loop timeouts
 *
 * The DBus library allows the caller to register functions for the library to
 * use for managing timers via a main loop.
 */

static gboolean
timer_popped(gpointer data)
{
    crm_debug("%dms DBus timer expired",
              dbus_timeout_get_interval((DBusTimeout *) data));
    dbus_timeout_handle(data);
    return FALSE;
}

static dbus_bool_t
add_dbus_timer(DBusTimeout *timeout, void *data)
{
    int interval_ms = dbus_timeout_get_interval(timeout);
    guint id = g_timeout_add(interval_ms, timer_popped, timeout);

    if (id) {
        dbus_timeout_set_data(timeout, GUINT_TO_POINTER(id), NULL);
    }
    crm_trace("Added %dms DBus timer", interval_ms);
    return TRUE;
}

static void
remove_dbus_timer(DBusTimeout *timeout, void *data)
{
    void *vid = dbus_timeout_get_data(timeout);
    guint id = GPOINTER_TO_UINT(vid);

    crm_trace("Removing %dms DBus timer", dbus_timeout_get_interval(timeout));
    if (id) {
        g_source_remove(id);
        dbus_timeout_set_data(timeout, 0, NULL);
    }
}

static void
toggle_dbus_timer(DBusTimeout *timeout, void *data)
{
    bool enabled = dbus_timeout_get_enabled(timeout);

    crm_trace("Toggling %dms DBus timer %s",
              dbus_timeout_get_interval(timeout), (enabled? "off": "on"));
    if (enabled) {
        add_dbus_timer(timeout, data);
    } else {
        remove_dbus_timer(timeout, data);
    }
}

static void
register_timer_functions(DBusConnection *connection)
{
    dbus_connection_set_timeout_functions(connection, add_dbus_timer,
                                          remove_dbus_timer,
                                          toggle_dbus_timer, NULL, NULL);
}

/*
 * General DBus utilities
 */

DBusConnection *
pcmk_dbus_connect(void)
{
    DBusError err;
    DBusConnection *connection;

    dbus_error_init(&err);
    connection = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (dbus_error_is_set(&err)) {
        crm_err("Could not connect to DBus: %s", err.message);
        dbus_error_free(&err);
        return NULL;
    }
    if (connection == NULL) {
        return NULL;
    }

    /* Tell libdbus not to exit the process when a disconnect happens. This
     * defaults to FALSE but is toggled on by the dbus_bus_get() call above.
     */
    dbus_connection_set_exit_on_disconnect(connection, FALSE);

    // Set custom handlers for various situations
    register_timer_functions(connection);
    register_watch_functions(connection);
    dbus_connection_set_dispatch_status_function(connection,
                                                 update_dispatch_status,
                                                 NULL, NULL);

    // Call the dispatch function to check for any messages waiting already
    update_dispatch_status(connection,
                           dbus_connection_get_dispatch_status(connection),
                           NULL);
    return connection;
}

void
pcmk_dbus_disconnect(DBusConnection *connection)
{
    /* Per the DBus documentation, connections created with
     * dbus_connection_open() are owned by libdbus and should never be closed.
     *
     * @TODO Should we call dbus_connection_unref() here?
     */
    return;
}

// Custom DBus error names to use
#define ERR_NO_REQUEST           "org.clusterlabs.pacemaker.NoRequest"
#define ERR_NO_REPLY             "org.clusterlabs.pacemaker.NoReply"
#define ERR_INVALID_REPLY        "org.clusterlabs.pacemaker.InvalidReply"
#define ERR_INVALID_REPLY_METHOD "org.clusterlabs.pacemaker.InvalidReply.Method"
#define ERR_INVALID_REPLY_SIGNAL "org.clusterlabs.pacemaker.InvalidReply.Signal"
#define ERR_INVALID_REPLY_TYPE   "org.clusterlabs.pacemaker.InvalidReply.Type"
#define ERR_SEND_FAILED          "org.clusterlabs.pacemaker.SendFailed"

/*!
 * \internal
 * \brief Check whether a DBus reply indicates an error occurred
 *
 * \param[in]  pending If non-NULL, indicates that a DBus request was sent
 * \param[in]  reply   Reply received from DBus
 * \param[out] ret     If non-NULL, will be set to DBus error, if any
 *
 * \return TRUE if an error was found, FALSE otherwise
 *
 * \note Following the DBus API convention, a TRUE return is exactly equivalent
 *       to ret being set. If ret is provided and this function returns TRUE,
 *       the caller is responsible for calling dbus_error_free() on ret when
 *       done using it.
 */
bool
pcmk_dbus_find_error(DBusPendingCall *pending, DBusMessage *reply,
                     DBusError *ret)
{
    DBusError error;

    dbus_error_init(&error);

    if (pending == NULL) {
        dbus_set_error_const(&error, ERR_NO_REQUEST, "No request sent");

    } else if (reply == NULL) {
        dbus_set_error_const(&error, ERR_NO_REPLY, "No reply");

    } else {
        DBusMessageIter args;
        int dtype = dbus_message_get_type(reply);

        switch (dtype) {
            case DBUS_MESSAGE_TYPE_METHOD_RETURN:
                {
                    char *sig = NULL;

                    dbus_message_iter_init(reply, &args);
                    crm_trace("Received DBus reply with argument type '%s'",
                              (sig = dbus_message_iter_get_signature(&args)));
                    if (sig != NULL) {
                        dbus_free(sig);
                    }
                }
                break;
            case DBUS_MESSAGE_TYPE_INVALID:
                dbus_set_error_const(&error, ERR_INVALID_REPLY,
                                     "Invalid reply");
                break;
            case DBUS_MESSAGE_TYPE_METHOD_CALL:
                dbus_set_error_const(&error, ERR_INVALID_REPLY_METHOD,
                                     "Invalid reply (method call)");
                break;
            case DBUS_MESSAGE_TYPE_SIGNAL:
                dbus_set_error_const(&error, ERR_INVALID_REPLY_SIGNAL,
                                     "Invalid reply (signal)");
                break;
            case DBUS_MESSAGE_TYPE_ERROR:
                dbus_set_error_from_message(&error, reply);
                break;
            default:
                dbus_set_error(&error, ERR_INVALID_REPLY_TYPE,
                               "Unknown reply type %d", dtype);
        }
    }

    if (dbus_error_is_set(&error)) {
        crm_trace("DBus reply indicated error '%s' (%s)",
                  error.name, error.message);
        if (ret) {
            dbus_error_init(ret);
            dbus_move_error(&error, ret);
        } else {
            dbus_error_free(&error);
        }
        return TRUE;
    }

    return FALSE;
}

/*!
 * \internal
 * \brief Send a DBus request and wait for the reply
 *
 * \param[in]  msg         DBus request to send
 * \param[in]  connection  DBus connection to use
 * \param[out] error       If non-NULL, will be set to error, if any
 * \param[in]  timeout     Timeout to use for request
 *
 * \return DBus reply
 *
 * \note If error is non-NULL, it is initialized, so the caller may always use
 *       dbus_error_is_set() to determine whether an error occurred; the caller
 *       is responsible for calling dbus_error_free() in this case.
 */
DBusMessage *
pcmk_dbus_send_recv(DBusMessage *msg, DBusConnection *connection,
                    DBusError *error, int timeout)
{
    const char *method = NULL;
    DBusMessage *reply = NULL;
    DBusPendingCall* pending = NULL;

    CRM_ASSERT(dbus_message_get_type (msg) == DBUS_MESSAGE_TYPE_METHOD_CALL);
    method = dbus_message_get_member (msg);

    /* Ensure caller can reliably check whether error is set */
    if (error) {
        dbus_error_init(error);
    }

    if (timeout <= 0) {
        /* DBUS_TIMEOUT_USE_DEFAULT (-1) tells DBus to use a sane default */
        timeout = DBUS_TIMEOUT_USE_DEFAULT;
    }

    // send message and get a handle for a reply
    if (!dbus_connection_send_with_reply(connection, msg, &pending, timeout)) {
        if (error) {
            dbus_set_error(error, ERR_SEND_FAILED,
                           "Could not queue DBus '%s' request", method);
        }
        return NULL;
    }

    dbus_connection_flush(connection);

    if (pending) {
        /* block until we receive a reply */
        dbus_pending_call_block(pending);

        /* get the reply message */
        reply = dbus_pending_call_steal_reply(pending);
    }

    (void) pcmk_dbus_find_error(pending, reply, error);

    if (pending) {
        /* free the pending message handle */
        dbus_pending_call_unref(pending);
    }

    return reply;
}

/*!
 * \internal
 * \brief Send a DBus message with a callback for the reply
 *
 * \param[in]     msg         DBus message to send
 * \param[in,out] connection  DBus connection to send on
 * \param[in]     done        Function to call when pending call completes
 * \param[in]     user_data   Data to pass to done callback
 *
 * \return Handle for reply on success, NULL on error
 * \note The caller can assume that the done callback is called always and
 *       only when the return value is non-NULL. (This allows the caller to
 *       know where it should free dynamically allocated user_data.)
 */
DBusPendingCall *
pcmk_dbus_send(DBusMessage *msg, DBusConnection *connection,
               void (*done)(DBusPendingCall *pending, void *user_data),
               void *user_data, int timeout)
{
    const char *method = NULL;
    DBusPendingCall* pending = NULL;

    CRM_ASSERT(done);
    CRM_ASSERT(dbus_message_get_type(msg) == DBUS_MESSAGE_TYPE_METHOD_CALL);
    method = dbus_message_get_member(msg);

    if (timeout <= 0) {
        /* DBUS_TIMEOUT_USE_DEFAULT (-1) tells DBus to use a sane default */
        timeout = DBUS_TIMEOUT_USE_DEFAULT;
    }

    // send message and get a handle for a reply
    if (!dbus_connection_send_with_reply(connection, msg, &pending, timeout)) {
        crm_err("Could not send DBus %s message: failed", method);
        return NULL;

    } else if (pending == NULL) {
        crm_err("Could not send DBus %s message: connection may be closed",
                method);
        return NULL;
    }

    if (dbus_pending_call_get_completed(pending)) {
        crm_info("DBus %s message completed too soon", method);
        /* Calling done() directly in this case instead of setting notify below
         * breaks things
         */
    }
    if (!dbus_pending_call_set_notify(pending, done, user_data, NULL)) {
        return NULL;
    }
    return pending;
}

bool
pcmk_dbus_type_check(DBusMessage *msg, DBusMessageIter *field, int expected,
                     const char *function, int line)
{
    int dtype = 0;
    DBusMessageIter lfield;

    if (field == NULL) {
        if (dbus_message_iter_init(msg, &lfield)) {
            field = &lfield;
        }
    }

    if (field == NULL) {
        do_crm_log_alias(LOG_INFO, __FILE__, function, line,
                         "DBus reply has empty parameter list (expected '%c')",
                         expected);
        return FALSE;
    }

    dtype = dbus_message_iter_get_arg_type(field);

    if (dtype != expected) {
        DBusMessageIter args;
        char *sig;

        dbus_message_iter_init(msg, &args);
        sig = dbus_message_iter_get_signature(&args);
        do_crm_log_alias(LOG_INFO, __FILE__, function, line,
                         "DBus reply has unexpected type "
                         "(expected '%c' not '%c' in '%s')",
                         expected, dtype, sig);
        dbus_free(sig);
        return FALSE;
    }

    return TRUE;
}


/*
 * Property queries
 */

/* DBus APIs often provide queryable properties that use this standard
 * interface. See:
 * https://dbus.freedesktop.org/doc/dbus-specification.html#standard-interfaces-properties
 */
#define BUS_PROPERTY_IFACE "org.freedesktop.DBus.Properties"

// Callback prototype for when a DBus property query result is received
typedef void (*property_callback_func)(const char *name,  // Property name
                                       const char *value, // Property value
                                       void *userdata);   // Caller-provided data

// Data needed by DBus property queries
struct property_query {
    char *name;         // Property name being queried
    char *target;       // Name of DBus bus that query should be sent to
    char *object;       // DBus object path for object with the property
    void *userdata;     // Caller-provided data to supply to callback
    property_callback_func callback; // Function to call when result is received
};

static void
free_property_query(struct property_query *data)
{
    free(data->target);
    free(data->object);
    free(data->name);
    free(data);
}

static char *
handle_query_result(DBusMessage *reply, struct property_query *data)
{
    DBusError error;
    char *output = NULL;
    DBusMessageIter args;
    DBusMessageIter variant_iter;
    DBusBasicValue value;

    // First, check if the reply contains an error
    if (pcmk_dbus_find_error((void*)&error, reply, &error)) {
        crm_err("DBus query for %s property '%s' failed: %s",
                data->object, data->name, error.message);
        dbus_error_free(&error);
        goto cleanup;
    }

    // The lone output argument should be a DBus variant type
    dbus_message_iter_init(reply, &args);
    if (!pcmk_dbus_type_check(reply, &args, DBUS_TYPE_VARIANT,
                              __func__, __LINE__)) {
        crm_err("DBus query for %s property '%s' failed: Unexpected reply type",
                data->object, data->name);
        goto cleanup;
    }

    // The variant should be a string
    dbus_message_iter_recurse(&args, &variant_iter);
    if (!pcmk_dbus_type_check(reply, &variant_iter, DBUS_TYPE_STRING,
                              __func__, __LINE__)) {
        crm_err("DBus query for %s property '%s' failed: "
                "Unexpected variant type", data->object, data->name);
        goto cleanup;
    }
    dbus_message_iter_get_basic(&variant_iter, &value);

    // There should be no more arguments (in variant or reply)
    dbus_message_iter_next(&variant_iter);
    if (dbus_message_iter_get_arg_type(&variant_iter) != DBUS_TYPE_INVALID) {
        crm_err("DBus query for %s property '%s' failed: "
                "Too many arguments in reply",
                data->object, data->name);
        goto cleanup;
    }
    dbus_message_iter_next(&args);
    if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_INVALID) {
        crm_err("DBus query for %s property '%s' failed: "
                "Too many arguments in reply", data->object, data->name);
        goto cleanup;
    }

    crm_trace("DBus query result for %s: %s='%s'",
              data->object, data->name, (value.str? value.str : ""));

    if (data->callback) {   // Query was asynchronous
        data->callback(data->name, (value.str? value.str : ""), data->userdata);

    } else {                // Query was synchronous
        output = strdup(value.str? value.str : "");
    }

  cleanup:
    free_property_query(data);
    return output;
}

static void
async_query_result_cb(DBusPendingCall *pending, void *user_data)
{
    DBusMessage *reply = NULL;
    char *value = NULL;

    if (pending) {
        reply = dbus_pending_call_steal_reply(pending);
    }

    value = handle_query_result(reply, user_data);
    free(value);

    if (reply) {
        dbus_message_unref(reply);
    }
}

/*!
 * \internal
 * \brief Query a property on a DBus object
 *
 * \param[in]  connection  An active connection to DBus
 * \param[in]  target      DBus name that the query should be sent to
 * \param[in]  obj         DBus object path for object with the property
 * \param[in]  iface       DBus interface for property to query
 * \param[in]  name        Name of property to query
 * \param[in]  callback    If not NULL, perform query asynchronously, and call
 *                         this function when query completes
 * \param[in]  userdata    Caller-provided data to provide to \p callback
 * \param[out] pending     If \p callback is not NULL, this will be set to the
 *                         handle for the reply (or NULL on error)
 * \param[in]  timeout     Abort query if it takes longer than this (ms)
 *
 * \return NULL if \p callback is non-NULL (i.e. asynchronous), otherwise a
 *         newly allocated string with property value
 * \note It is the caller's responsibility to free the result with free().
 */
char *
pcmk_dbus_get_property(DBusConnection *connection, const char *target,
                       const char *obj, const gchar * iface, const char *name,
                       property_callback_func callback, void *userdata,
                       DBusPendingCall **pending, int timeout)
{
    DBusMessage *msg;
    char *output = NULL;
    struct property_query *query_data = NULL;

    CRM_CHECK((connection != NULL) && (target != NULL) && (obj != NULL)
              && (iface != NULL) && (name != NULL), return NULL);

    crm_trace("Querying DBus %s for %s property '%s'",
              target, obj, name);

    // Create a new message to use to invoke method
    msg = dbus_message_new_method_call(target, obj, BUS_PROPERTY_IFACE, "Get");
    if (msg == NULL) {
        crm_err("DBus query for %s property '%s' failed: "
                "Unable to create message", obj, name);
        return NULL;
    }

    // Add the interface name and property name as message arguments
    if (!dbus_message_append_args(msg,
                                  DBUS_TYPE_STRING, &iface,
                                  DBUS_TYPE_STRING, &name,
                                  DBUS_TYPE_INVALID)) {
        crm_err("DBus query for %s property '%s' failed: "
                "Could not append arguments", obj, name);
        dbus_message_unref(msg);
        return NULL;
    }

    query_data = malloc(sizeof(struct property_query));
    if (query_data == NULL) {
        crm_crit("DBus query for %s property '%s' failed: Out of memory",
                 obj, name);
        dbus_message_unref(msg);
        return NULL;
    }

    query_data->target = strdup(target);
    query_data->object = strdup(obj);
    query_data->callback = callback;
    query_data->userdata = userdata;
    query_data->name = strdup(name);
    CRM_CHECK((query_data->target != NULL)
                  && (query_data->object != NULL)
                  && (query_data->name != NULL),
              free_property_query(query_data);
              dbus_message_unref(msg);
              return NULL);

    if (query_data->callback) { // Asynchronous
        DBusPendingCall *local_pending;

        local_pending = pcmk_dbus_send(msg, connection, async_query_result_cb,
                                       query_data, timeout);
        if (local_pending == NULL) {
            // async_query_result_cb() was not called in this case
            free_property_query(query_data);
            query_data = NULL;
        }

        if (pending) {
            *pending = local_pending;
        }

    } else { // Synchronous
        DBusMessage *reply = pcmk_dbus_send_recv(msg, connection, NULL,
                                                 timeout);

        output = handle_query_result(reply, query_data);

        if (reply) {
            dbus_message_unref(reply);
        }
    }

    dbus_message_unref(msg);

    return output;
}
