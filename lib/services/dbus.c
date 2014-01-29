#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/services.h>
#include <dbus/dbus.h>
#include <pcmk-dbus.h>

static bool pcmk_dbus_error_check(DBusError *err, const char *prefix, const char *function, int line) 
{
    if (err && dbus_error_is_set(err)) {
        do_crm_log_alias(LOG_ERR, __FILE__, function, line, "%s: DBus error '%s'", prefix, err->message);
        dbus_error_free(err);
        return TRUE;
    }
    return FALSE;
}

DBusConnection *pcmk_dbus_connect(void)
{
    DBusError err;
    DBusConnection *connection;

    dbus_error_init(&err);
    connection = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    pcmk_dbus_error_check(&err, "Could not connect to System DBus", __FUNCTION__, __LINE__);

    return connection;
}

void pcmk_dbus_disconnect(DBusConnection *connection)
{
}

bool pcmk_dbus_append_arg(DBusMessage *msg, int dtype, const void *value)
{
    DBusMessageIter args;

    dbus_message_iter_init_append(msg, &args);
    if (!dbus_message_iter_append_basic(&args, dtype, value)) {
        crm_err("dbus_message_iter_append_basic(%c) failed", dtype);
        return FALSE;
    }

    return TRUE;
}

DBusMessage *pcmk_dbus_send_recv(DBusMessage *msg, DBusConnection *connection, char **e)
{
    DBusError error;
    const char *method = NULL;
    DBusMessage *reply = NULL;
    DBusPendingCall* pending = NULL;

    dbus_error_init(&error);

    CRM_ASSERT(dbus_message_get_type (msg) == DBUS_MESSAGE_TYPE_METHOD_CALL);
    method = dbus_message_get_member (msg);

    // send message and get a handle for a reply
    if (!dbus_connection_send_with_reply (connection, msg, &pending, -1)) { // -1 is default timeout
        crm_err("Send with reply failed");
        return NULL;
    }
    if (NULL == pending) {
        crm_err("No pending call found");
        return NULL;
    }

    dbus_connection_flush(connection);

    /* block until we receive a reply */
    dbus_pending_call_block(pending);

    /* get the reply message */
    reply = dbus_pending_call_steal_reply(pending);
    if(reply == NULL) {
        error.name = "org.clusterlabs.pacemaker.NoReply";
        error.message = "No reply";

    } else {
        DBusMessageIter args;
        int dtype = dbus_message_get_type(reply);


        switch(dtype) {
            case DBUS_MESSAGE_TYPE_METHOD_RETURN:
                dbus_message_iter_init(reply, &args);
                crm_trace("Call to %s returned '%s'", method, dbus_message_iter_get_signature(&args));
                break;
            case DBUS_MESSAGE_TYPE_INVALID:
                error.message = "Invalid reply";
                error.name = "org.clusterlabs.pacemaker.InvalidReply";
                crm_err("Error processing %s response: %s", method, error.message);
                break;
            case DBUS_MESSAGE_TYPE_METHOD_CALL:
                error.message = "Invalid reply (method call)";
                error.name = "org.clusterlabs.pacemaker.InvalidReply.Method";
                crm_err("Error processing %s response: %s", method, error.message);
                break;
            case DBUS_MESSAGE_TYPE_SIGNAL:
                error.message = "Invalid reply (signal)";
                error.name = "org.clusterlabs.pacemaker.InvalidReply.Signal";
                crm_err("Error processing %s response: %s", method, error.message);
                break;

            case DBUS_MESSAGE_TYPE_ERROR:
                dbus_set_error_from_message (&error, reply);
                crm_err("%s error '%s': %s", method, error.name, error.message);
                break;
            default:
                error.message = "Unknown reply type";
                error.name = "org.clusterlabs.pacemaker.InvalidReply.Type";
                crm_err("Error processing %s response: %s (%d)", method, error.message, dtype);
        }
    }

    if(error.name) {
        if(e) {
            *e = strdup(error.name);
        }
        if(reply) {
            dbus_message_unref(reply);
            reply = NULL;
        }
    } else if(e) {
        *e = NULL;
    }

    /* free the pending message handle */
    dbus_pending_call_unref(pending);
    return reply;
}

bool pcmk_dbus_type_check(DBusMessage *msg, DBusMessageIter *field, int expected, const char *function, int line)
{
    int dtype = dbus_message_iter_get_arg_type(field);

    if(dtype != expected) {
        DBusMessageIter args;

        dbus_message_iter_init(msg, &args);
        do_crm_log_alias(LOG_ERR, __FILE__, function, line,
                         "Unexepcted DBus type, expected %c instead of %c in '%s'",
                         expected, dtype, dbus_message_iter_get_signature(&args));
        return FALSE;
    }

    return TRUE;
}

#define BUS_PROPERTY_IFACE "org.freedesktop.DBus.Properties"

char *
pcmk_dbus_get_property(
    DBusConnection *connection, const char *target, const char *obj, const gchar * iface, const char *name)
{
    DBusMessage *msg;
    DBusMessageIter args;
    DBusMessageIter dict;
    DBusMessage *reply = NULL;
    /* DBusBasicValue value; */
    const char *method = "GetAll";
    char *output = NULL;
    char *error = NULL;

        /* desc = systemd_unit_property(path, BUS_NAME ".Unit", "Description"); */

    crm_info("Calling: %s on %s", method, target);
    msg = dbus_message_new_method_call(target, // target for the method call
                                       obj, // object to call on
                                       BUS_PROPERTY_IFACE, // interface to call on
                                       method); // method name

    if (NULL == msg) {
        crm_err("Call to %s failed: No message", method);
        return NULL;
    }

    pcmk_dbus_append_arg(msg, DBUS_TYPE_STRING, &iface);

    reply = pcmk_dbus_send_recv(msg, connection, &error);
    dbus_message_unref(msg);

    if(reply == NULL) {
        crm_err("Call to %s for %s failed: No reply", method, iface);
        return NULL;

    } else if (!dbus_message_iter_init(reply, &args)) {
        crm_err("Cannot get properties for %s from %s", obj, iface);
        return NULL;
    }

    if(!pcmk_dbus_type_check(reply, &args, DBUS_TYPE_ARRAY, __FUNCTION__, __LINE__)) {
        crm_err("Call to %s failed: Message has invalid arguments", method);
        dbus_message_unref(reply);
        return NULL;
    }

    dbus_message_iter_recurse(&args, &dict);
    while (dbus_message_iter_get_arg_type (&dict) != DBUS_TYPE_INVALID) {
        DBusMessageIter sv;
        DBusMessageIter v;
        DBusBasicValue value;

        if(!pcmk_dbus_type_check(reply, &dict, DBUS_TYPE_DICT_ENTRY, __FUNCTION__, __LINE__)) {
            dbus_message_iter_next (&dict);
            continue;
        }

        dbus_message_iter_recurse(&dict, &sv);
        while (dbus_message_iter_get_arg_type (&sv) != DBUS_TYPE_INVALID) {
            int dtype = dbus_message_iter_get_arg_type(&sv);

            switch(dtype) {
                case DBUS_TYPE_STRING:
                    dbus_message_iter_get_basic(&sv, &value);

                    crm_trace("Got: %s", value.str);
                    if(strcmp(value.str, name) != 0) {
                        dbus_message_iter_next (&sv); /* Skip the value */
                    }
                    break;
                case DBUS_TYPE_VARIANT:
                    dbus_message_iter_recurse(&sv, &v);
                    if(pcmk_dbus_type_check(reply, &v, DBUS_TYPE_STRING, __FUNCTION__, __LINE__)) {
                        dbus_message_iter_get_basic(&v, &value);

                        crm_trace("Result: %s", value.str);
                        output = strdup(value.str);
                    }
                    break;
                default:
                    pcmk_dbus_type_check(reply, &sv, DBUS_TYPE_STRING, __FUNCTION__, __LINE__);
            }
            dbus_message_iter_next (&sv);
        }

        dbus_message_iter_next (&dict);
    }


    crm_trace("Property %s[%s] is '%s'", obj, name, output);
    return output;
}





int dbus_watch_get_unix_fd	(	DBusWatch * 	watch	);


/* http://dbus.freedesktop.org/doc/api/html/group__DBusConnection.html#gaebf031eb444b4f847606aa27daa3d8e6 */
    
DBUS_EXPORT dbus_bool_t dbus_connection_set_watch_functions(
    DBusConnection * 	connection,
    DBusAddWatchFunction 	add_function,
    DBusRemoveWatchFunction 	remove_function,
    DBusWatchToggledFunction 	toggled_function,
    void * 	data,
    DBusFreeFunction 	free_data_function 
    );
