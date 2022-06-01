/*
 * Original copyright 2010 Senko Rasic <senko.rasic@dobarkod.hr>
 *                         and Ante Karamatic <ivoks@init.hr>
 * Later changes copyright 2012-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>

#include <crm/crm.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>

#include <services_private.h>
#include <upstart.h>
#include <dbus/dbus.h>
#include <pcmk-dbus.h>

#include <glib.h>
#include <gio/gio.h>

#define BUS_NAME "com.ubuntu.Upstart"
#define BUS_PATH "/com/ubuntu/Upstart"

#define UPSTART_06_API     BUS_NAME"0_6"
#define UPSTART_JOB_IFACE  UPSTART_06_API".Job"
#define BUS_PROPERTY_IFACE "org.freedesktop.DBus.Properties"

/*
  http://upstart.ubuntu.com/wiki/DBusInterface
*/
static DBusConnection *upstart_proxy = NULL;

/*!
 * \internal
 * \brief Prepare an Upstart action
 *
 * \param[in] op  Action to prepare
 *
 * \return Standard Pacemaker return code
 */
int
services__upstart_prepare(svc_action_t *op)
{
    op->opaque->exec = strdup("upstart-dbus");
    if (op->opaque->exec == NULL) {
        return ENOMEM;
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Map a Upstart result to a standard OCF result
 *
 * \param[in] exit_status  Upstart result
 *
 * \return Standard OCF result
 */
enum ocf_exitcode
services__upstart2ocf(int exit_status)
{
    // This library uses OCF codes for Upstart actions
    return (enum ocf_exitcode) exit_status;
}

static gboolean
upstart_init(void)
{
    static int need_init = 1;

    if (need_init) {
        need_init = 0;
        upstart_proxy = pcmk_dbus_connect();
    }
    if (upstart_proxy == NULL) {
        return FALSE;
    }
    return TRUE;
}

void
upstart_cleanup(void)
{
    if (upstart_proxy) {
        pcmk_dbus_disconnect(upstart_proxy);
        upstart_proxy = NULL;
    }
}

/*!
 * \internal
 * \brief Get the DBus object path corresponding to a job name
 *
 * \param[in]  arg_name  Name of job to get path for
 * \param[out] path      If not NULL, where to store DBus object path
 * \param[in]  timeout   Give up after this many seconds
 *
 * \return true if object path was found, false otherwise
 * \note The caller is responsible for freeing *path if it is non-NULL.
 */
static bool
object_path_for_job(const gchar *arg_name, char **path, int timeout)
{
    /*
        com.ubuntu.Upstart0_6.GetJobByName (in String name, out ObjectPath job)
    */
    DBusError error;
    DBusMessage *msg;
    DBusMessage *reply = NULL;
    bool rc = false;

    if (path != NULL) {
        *path = NULL;
    }

    if (!upstart_init()) {
        return false;
    }
    msg = dbus_message_new_method_call(BUS_NAME, // target for the method call
                                       BUS_PATH, // object to call on
                                       UPSTART_06_API,  // interface to call on
                                       "GetJobByName"); // method name

    dbus_error_init(&error);
    CRM_LOG_ASSERT(dbus_message_append_args(msg, DBUS_TYPE_STRING, &arg_name,
                                            DBUS_TYPE_INVALID));
    reply = pcmk_dbus_send_recv(msg, upstart_proxy, &error, timeout);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&error)) {
        crm_err("Could not get DBus object path for %s: %s",
                arg_name, error.message);
        dbus_error_free(&error);

    } else if (!pcmk_dbus_type_check(reply, NULL, DBUS_TYPE_OBJECT_PATH,
                                     __func__, __LINE__)) {
        crm_err("Could not get DBus object path for %s: Invalid return type",
                arg_name);

    } else {
        if (path != NULL) {
            dbus_message_get_args(reply, NULL, DBUS_TYPE_OBJECT_PATH, path,
                                  DBUS_TYPE_INVALID);
            if (*path != NULL) {
                *path = strdup(*path);
            }
        }
        rc = true;
    }

    if (reply != NULL) {
        dbus_message_unref(reply);
    }
    return rc;
}

static void
fix(char *input, const char *search, char replace)
{
    char *match = NULL;
    int shuffle = strlen(search) - 1;

    while (TRUE) {
        int len, lpc;

        match = strstr(input, search);
        if (match == NULL) {
            break;
        }
        crm_trace("Found: %s", match);
        match[0] = replace;
        len = strlen(match) - shuffle;
        for (lpc = 1; lpc <= len; lpc++) {
            match[lpc] = match[lpc + shuffle];
        }
    }
}

static char *
fix_upstart_name(const char *input)
{
    char *output = strdup(input);

    fix(output, "_2b", '+');
    fix(output, "_2c", ',');
    fix(output, "_2d", '-');
    fix(output, "_2e", '.');
    fix(output, "_40", '@');
    fix(output, "_5f", '_');
    return output;
}

GList *
upstart_job_listall(void)
{
    GList *units = NULL;
    DBusMessageIter args;
    DBusMessageIter unit;
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;
    const char *method = "GetAllJobs";
    DBusError error;
    int lpc = 0;

    if (upstart_init() == FALSE) {
        return NULL;
    }

/*
  com.ubuntu.Upstart0_6.GetAllJobs (out <Array of ObjectPath> jobs)
*/

    dbus_error_init(&error);
    msg = dbus_message_new_method_call(BUS_NAME, // target for the method call
                                       BUS_PATH, // object to call on
                                       UPSTART_06_API, // interface to call on
                                       method); // method name
    CRM_ASSERT(msg != NULL);

    reply = pcmk_dbus_send_recv(msg, upstart_proxy, &error, DBUS_TIMEOUT_USE_DEFAULT);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&error)) {
        crm_err("Call to %s failed: %s", method, error.message);
        dbus_error_free(&error);
        return NULL;

    } else if (!dbus_message_iter_init(reply, &args)) {
        crm_err("Call to %s failed: Message has no arguments", method);
        dbus_message_unref(reply);
        return NULL;
    }

    if(!pcmk_dbus_type_check(reply, &args, DBUS_TYPE_ARRAY, __func__, __LINE__)) {
        crm_err("Call to %s failed: Message has invalid arguments", method);
        dbus_message_unref(reply);
        return NULL;
    }

    dbus_message_iter_recurse(&args, &unit);
    while (dbus_message_iter_get_arg_type (&unit) != DBUS_TYPE_INVALID) {
        DBusBasicValue value;
        const char *job = NULL;
        char *path = NULL;

        if(!pcmk_dbus_type_check(reply, &unit, DBUS_TYPE_OBJECT_PATH, __func__, __LINE__)) {
            crm_warn("Skipping Upstart reply argument with unexpected type");
            continue;
        }

        dbus_message_iter_get_basic(&unit, &value);

        if(value.str) {
            int llpc = 0;
            path = value.str;
            job = value.str;
            while (path[llpc] != 0) {
                if (path[llpc] == '/') {
                    job = path + llpc + 1;
                }
                llpc++;
            }
            lpc++;
            crm_trace("%s -> %s", path, job);
            units = g_list_append(units, fix_upstart_name(job));
        }
        dbus_message_iter_next (&unit);
    }

    dbus_message_unref(reply);
    crm_trace("Found %d upstart jobs", lpc);
    return units;
}

gboolean
upstart_job_exists(const char *name)
{
    return object_path_for_job(name, NULL, DBUS_TIMEOUT_USE_DEFAULT);
}

static char *
get_first_instance(const gchar * job, int timeout)
{
    char *instance = NULL;
    const char *method = "GetAllInstances";
    DBusError error;
    DBusMessage *msg;
    DBusMessage *reply;
    DBusMessageIter args;
    DBusMessageIter unit;

    dbus_error_init(&error);
    msg = dbus_message_new_method_call(BUS_NAME, // target for the method call
                                       job, // object to call on
                                       UPSTART_JOB_IFACE, // interface to call on
                                       method); // method name
    CRM_ASSERT(msg != NULL);

    dbus_message_append_args(msg, DBUS_TYPE_INVALID);
    reply = pcmk_dbus_send_recv(msg, upstart_proxy, &error, timeout);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&error)) {
        crm_info("Call to %s failed: %s", method, error.message);
        dbus_error_free(&error);
        goto done;

    } else if(reply == NULL) {
        crm_info("Call to %s failed: no reply", method);
        goto done;

    } else if (!dbus_message_iter_init(reply, &args)) {
        crm_info("Call to %s failed: Message has no arguments", method);
        goto done;
    }

    if(!pcmk_dbus_type_check(reply, &args, DBUS_TYPE_ARRAY, __func__, __LINE__)) {
        crm_info("Call to %s failed: Message has invalid arguments", method);
        goto done;
    }

    dbus_message_iter_recurse(&args, &unit);
    if(pcmk_dbus_type_check(reply, &unit, DBUS_TYPE_OBJECT_PATH, __func__, __LINE__)) {
        DBusBasicValue value;

        dbus_message_iter_get_basic(&unit, &value);

        if(value.str) {
            instance = strdup(value.str);
            crm_trace("Result: %s", instance);
        }
    }

  done:
    if(reply) {
        dbus_message_unref(reply);
    }
    return instance;
}

/*!
 * \internal
 * \brief Parse result of Upstart status check
 *
 * \param[in] name      DBus interface name for property that was checked
 * \param[in] state     Property value
 * \param[in] userdata  Status action that check was done for
 */
static void
parse_status_result(const char *name, const char *state, void *userdata)
{
    svc_action_t *op = userdata;

    if (pcmk__str_eq(state, "running", pcmk__str_none)) {
        services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
    } else {
        services__set_result(op, PCMK_OCF_NOT_RUNNING, PCMK_EXEC_DONE, state);
    }

    if (!(op->synchronous)) {
        services_set_op_pending(op, NULL);
        services__finalize_async_op(op);
    }
}

#define METADATA_FORMAT                                                     \
    "<?xml version=\"1.0\"?>\n"                                             \
    "<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"                   \
    "<resource-agent name=\"%s\" version=\"" PCMK_DEFAULT_AGENT_VERSION "\">\n" \
    "  <version>1.1</version>\n"                                            \
    "  <longdesc lang=\"en\">\n"                                            \
    "    Upstart agent for controlling the system %s service\n"             \
    "  </longdesc>\n"                                                       \
    "  <shortdesc lang=\"en\">Upstart job for %s</shortdesc>\n"             \
    "  <parameters/>\n"                                                     \
    "  <actions>\n"                                                         \
    "    <action name=\"start\"     timeout=\"15\" />\n"                    \
    "    <action name=\"stop\"      timeout=\"15\" />\n"                    \
    "    <action name=\"status\"    timeout=\"15\" />\n"                    \
    "    <action name=\"restart\"   timeout=\"15\" />\n"                    \
    "    <action name=\"monitor\"   timeout=\"15\" interval=\"15\" start-delay=\"15\" />\n" \
    "    <action name=\"meta-data\" timeout=\"5\" />\n"                     \
    "  </actions>\n"                                                        \
    "  <special tag=\"upstart\"/>\n"                                        \
    "</resource-agent>\n"

static char *
upstart_job_metadata(const char *name)
{
    return crm_strdup_printf(METADATA_FORMAT, name, name, name);
}

/*!
 * \internal
 * \brief Set an action result based on a method error
 *
 * \param[in] op     Action to set result for
 * \param[in] error  Method error
 */
static void
set_result_from_method_error(svc_action_t *op, const DBusError *error)
{
    services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                         "Unable to invoke Upstart DBus method");

    if (strstr(error->name, UPSTART_06_API ".Error.UnknownInstance")) {

        if (pcmk__str_eq(op->action, "stop", pcmk__str_casei)) {
            crm_trace("Masking stop failure (%s) for %s "
                      "because unknown service can be considered stopped",
                      error->name, pcmk__s(op->rsc, "unknown resource"));
            services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
            return;
        }

        services__set_result(op, PCMK_OCF_NOT_INSTALLED,
                             PCMK_EXEC_NOT_INSTALLED, "Upstart job not found");

    } else if (pcmk__str_eq(op->action, "start", pcmk__str_casei)
               && strstr(error->name, UPSTART_06_API ".Error.AlreadyStarted")) {
        crm_trace("Masking start failure (%s) for %s "
                  "because already started resource is OK",
                  error->name, pcmk__s(op->rsc, "unknown resource"));
        services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
        return;
    }

    crm_info("DBus request for %s of Upstart job %s for resource %s failed: %s",
             op->action, op->agent, pcmk__s(op->rsc, "with unknown name"),
             error->message);
}

/*!
 * \internal
 * \brief Process the completion of an asynchronous job start, stop, or restart
 *
 * \param[in] pending    If not NULL, DBus call associated with request
 * \param[in] user_data  Action that was executed
 */
static void
job_method_complete(DBusPendingCall *pending, void *user_data)
{
    DBusError error;
    DBusMessage *reply = NULL;
    svc_action_t *op = user_data;

    // Grab the reply
    if (pending != NULL) {
        reply = dbus_pending_call_steal_reply(pending);
    }

    // Determine result
    dbus_error_init(&error);
    if (pcmk_dbus_find_error(pending, reply, &error)) {
        set_result_from_method_error(op, &error);
        dbus_error_free(&error);

    } else if (pcmk__str_eq(op->action, "stop", pcmk__str_none)) {
        // Call has no return value
        crm_debug("DBus request for stop of %s succeeded",
                  pcmk__s(op->rsc, "unknown resource"));
        services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);

    } else if (!pcmk_dbus_type_check(reply, NULL, DBUS_TYPE_OBJECT_PATH,
                                     __func__, __LINE__)) {
        crm_info("DBus request for %s of %s succeeded but "
                 "return type was unexpected", op->action,
                 pcmk__s(op->rsc, "unknown resource"));
        services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);

    } else {
        const char *path = NULL;

        dbus_message_get_args(reply, NULL, DBUS_TYPE_OBJECT_PATH, &path,
                              DBUS_TYPE_INVALID);
        crm_debug("DBus request for %s of %s using %s succeeded",
                  op->action, pcmk__s(op->rsc, "unknown resource"), path);
        services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
    }

    // The call is no longer pending
    CRM_LOG_ASSERT(pending == op->opaque->pending);
    services_set_op_pending(op, NULL);

    // Finalize action
    services__finalize_async_op(op);
    if (reply != NULL) {
        dbus_message_unref(reply);
    }
}

/*!
 * \internal
 * \brief Execute an Upstart action
 *
 * \param[in] op  Action to execute
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
services__execute_upstart(svc_action_t *op)
{
    char *job = NULL;
    int arg_wait = TRUE;
    const char *arg_env = "pacemaker=1";
    const char *action = op->action;

    DBusError error;
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;
    DBusMessageIter iter, array_iter;

    CRM_ASSERT(op != NULL);

    if ((op->action == NULL) || (op->agent == NULL)) {
        services__set_result(op, PCMK_OCF_NOT_CONFIGURED, PCMK_EXEC_ERROR_FATAL,
                             "Bug in action caller");
        goto cleanup;
    }

    if (!upstart_init()) {
        services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                             "No DBus connection");
        goto cleanup;
    }

    if (pcmk__str_eq(op->action, "meta-data", pcmk__str_casei)) {
        op->stdout_data = upstart_job_metadata(op->agent);
        services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
        goto cleanup;
    }

    if (!object_path_for_job(op->agent, &job, op->timeout)) {
        if (pcmk__str_eq(action, "stop", pcmk__str_none)) {
            services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
        } else {
            services__set_result(op, PCMK_OCF_NOT_INSTALLED,
                                 PCMK_EXEC_NOT_INSTALLED,
                                 "Upstart job not found");
        }
        goto cleanup;
    }

    if (job == NULL) {
        // Shouldn't normally be possible -- maybe a memory error
        op->rc = PCMK_OCF_UNKNOWN_ERROR;
        op->status = PCMK_EXEC_ERROR;
        goto cleanup;
    }

    if (pcmk__strcase_any_of(op->action, "monitor", "status", NULL)) {
        DBusPendingCall *pending = NULL;
        char *state = NULL;
        char *path = get_first_instance(job, op->timeout);

        services__set_result(op, PCMK_OCF_NOT_RUNNING, PCMK_EXEC_DONE,
                             "No Upstart job instances found");
        if (path == NULL) {
            goto cleanup;
        }
        state = pcmk_dbus_get_property(upstart_proxy, BUS_NAME, path,
                                       UPSTART_06_API ".Instance", "state",
                                       op->synchronous? NULL : parse_status_result,
                                       op,
                                       op->synchronous? NULL : &pending,
                                       op->timeout);
        free(path);

        if (op->synchronous) {
            parse_status_result("state", state, op);
            free(state);

        } else if (pending == NULL) {
            services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                                 "Could not get job state from DBus");

        } else { // Successfully initiated async op
            free(job);
            services_set_op_pending(op, pending);
            services_add_inflight_op(op);
            return pcmk_rc_ok;
        }

        goto cleanup;

    } else if (pcmk__str_eq(action, "start", pcmk__str_none)) {
        action = "Start";

    } else if (pcmk__str_eq(action, "stop", pcmk__str_none)) {
        action = "Stop";

    } else if (pcmk__str_eq(action, "restart", pcmk__str_none)) {
        action = "Restart";

    } else {
        services__set_result(op, PCMK_OCF_UNIMPLEMENT_FEATURE,
                             PCMK_EXEC_ERROR_HARD,
                             "Action not implemented for Upstart resources");
        goto cleanup;
    }

    // Initialize rc/status in case called functions don't set them
    services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_DONE,
                         "Bug in service library");

    crm_debug("Calling %s for %s on %s",
              action, pcmk__s(op->rsc, "unknown resource"), job);

    msg = dbus_message_new_method_call(BUS_NAME, // target for the method call
                                       job, // object to call on
                                       UPSTART_JOB_IFACE, // interface to call on
                                       action); // method name
    CRM_ASSERT(msg != NULL);

    dbus_message_iter_init_append (msg, &iter);
    CRM_LOG_ASSERT(dbus_message_iter_open_container(&iter,
                                                    DBUS_TYPE_ARRAY,
                                                    DBUS_TYPE_STRING_AS_STRING,
                                                    &array_iter));
    CRM_LOG_ASSERT(dbus_message_iter_append_basic(&array_iter,
                                                  DBUS_TYPE_STRING, &arg_env));
    CRM_LOG_ASSERT(dbus_message_iter_close_container(&iter, &array_iter));
    CRM_LOG_ASSERT(dbus_message_append_args(msg, DBUS_TYPE_BOOLEAN, &arg_wait,
                                            DBUS_TYPE_INVALID));

    if (!(op->synchronous)) {
        DBusPendingCall *pending = pcmk_dbus_send(msg, upstart_proxy,
                                                  job_method_complete, op,
                                                  op->timeout);

        if (pending == NULL) {
            services__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                                 "Unable to send DBus message");
            goto cleanup;

        } else { // Successfully initiated async op
            free(job);
            services_set_op_pending(op, pending);
            services_add_inflight_op(op);
            return pcmk_rc_ok;
        }
    }

    // Synchronous call

    dbus_error_init(&error);
    reply = pcmk_dbus_send_recv(msg, upstart_proxy, &error, op->timeout);

    if (dbus_error_is_set(&error)) {
        set_result_from_method_error(op, &error);
        dbus_error_free(&error);

    } else if (pcmk__str_eq(op->action, "stop", pcmk__str_none)) {
        // DBus call does not return a value
        services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);

    } else if (!pcmk_dbus_type_check(reply, NULL, DBUS_TYPE_OBJECT_PATH,
                                     __func__, __LINE__)) {
        crm_info("Call to %s passed but return type was unexpected",
                 op->action);
        services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);

    } else {
        const char *path = NULL;

        dbus_message_get_args(reply, NULL, DBUS_TYPE_OBJECT_PATH, &path,
                              DBUS_TYPE_INVALID);
        crm_debug("Call to %s passed: %s", op->action, path);
        services__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
    }

cleanup:
    free(job);
    if (msg != NULL) {
        dbus_message_unref(msg);
    }
    if (reply != NULL) {
        dbus_message_unref(reply);
    }

    if (op->synchronous) {
        return (op->rc == PCMK_OCF_OK)? pcmk_rc_ok : pcmk_rc_error;
    } else {
        return services__finalize_async_op(op);
    }
}
