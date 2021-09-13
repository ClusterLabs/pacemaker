/*
 * Original copyright 2010 Senko Rasic <senko.rasic@dobarkod.hr>
 *                         and Ante Karamatic <ivoks@init.hr>
 * Later changes copyright 2012-2021 the Pacemaker project contributors
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

static gboolean
upstart_job_by_name(const gchar * arg_name, gchar ** out_unit, int timeout)
{
/*
  com.ubuntu.Upstart0_6.GetJobByName (in String name, out ObjectPath job)
*/
    DBusError error;
    DBusMessage *msg;
    DBusMessage *reply = NULL;
    const char *method = "GetJobByName";

    if(upstart_init() == FALSE) {
        return FALSE;
    }
    msg = dbus_message_new_method_call(BUS_NAME, // target for the method call
                                       BUS_PATH, // object to call on
                                       UPSTART_06_API, // interface to call on
                                       method); // method name

    dbus_error_init(&error);
    CRM_LOG_ASSERT(dbus_message_append_args(msg, DBUS_TYPE_STRING, &arg_name, DBUS_TYPE_INVALID));
    reply = pcmk_dbus_send_recv(msg, upstart_proxy, &error, timeout);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&error)) {
        crm_err("Could not issue %s for %s: %s", method, arg_name, error.message);
        dbus_error_free(&error);

    } else if(!pcmk_dbus_type_check(reply, NULL, DBUS_TYPE_OBJECT_PATH, __func__, __LINE__)) {
        crm_err("Invalid return type for %s", method);

    } else {
        if(out_unit) {
            char *path = NULL;

            dbus_message_get_args (reply, NULL,
                                   DBUS_TYPE_OBJECT_PATH, &path,
                                   DBUS_TYPE_INVALID);

            *out_unit = strdup(path);
        }
        dbus_message_unref(reply);
        return TRUE;
    }

    if(reply) {
        dbus_message_unref(reply);
    }
    return FALSE;
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
    return upstart_job_by_name(name, NULL, DBUS_TIMEOUT_USE_DEFAULT);
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
        crm_err("Call to %s failed: %s", method, error.message);
        dbus_error_free(&error);
        goto done;

    } else if(reply == NULL) {
        crm_err("Call to %s failed: no reply", method);
        goto done;

    } else if (!dbus_message_iter_init(reply, &args)) {
        crm_err("Call to %s failed: Message has no arguments", method);
        goto done;
    }

    if(!pcmk_dbus_type_check(reply, &args, DBUS_TYPE_ARRAY, __func__, __LINE__)) {
        crm_err("Call to %s failed: Message has invalid arguments", method);
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

static void
upstart_job_check(const char *name, const char *state, void *userdata)
{
    svc_action_t * op = userdata;

    if (state && g_strcmp0(state, "running") == 0) {
        op->rc = PCMK_OCF_OK;
    } else {
        op->rc = PCMK_OCF_NOT_RUNNING;
    }

    if (op->synchronous == FALSE) {
        services_set_op_pending(op, NULL);
        services__finalize_async_op(op);
    }
}

static char *
upstart_job_metadata(const char *name)
{
    return crm_strdup_printf("<?xml version=\"1.0\"?>\n"
                           "<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"
                           "<resource-agent name=\"%s\" version=\"" PCMK_DEFAULT_AGENT_VERSION "\">\n"
                           "  <version>1.0</version>\n"
                           "  <longdesc lang=\"en\">\n"
                           "    Upstart agent for controlling the system %s service\n"
                           "  </longdesc>\n"
                           "  <shortdesc lang=\"en\">%s upstart agent</shortdesc>\n"
                           "  <parameters>\n"
                           "  </parameters>\n"
                           "  <actions>\n"
                           "    <action name=\"start\"   timeout=\"15\" />\n"
                           "    <action name=\"stop\"    timeout=\"15\" />\n"
                           "    <action name=\"status\"  timeout=\"15\" />\n"
                           "    <action name=\"restart\"  timeout=\"15\" />\n"
                           "    <action name=\"monitor\" timeout=\"15\" interval=\"15\" start-delay=\"15\" />\n"
                           "    <action name=\"meta-data\"  timeout=\"5\" />\n"
                           "  </actions>\n"
                           "  <special tag=\"upstart\">\n"
                           "  </special>\n" "</resource-agent>\n", name, name, name);
}

static bool
upstart_mask_error(svc_action_t *op, const char *error)
{
    crm_trace("Could not issue %s for %s: %s", op->action, op->rsc, error);
    if(strstr(error, UPSTART_06_API ".Error.UnknownInstance")) {
        if(pcmk__str_eq(op->action, "stop", pcmk__str_casei)) {
            crm_trace("Masking %s failure for %s: unknown services are stopped", op->action, op->rsc);
            op->rc = PCMK_OCF_OK;

        } else if(pcmk__str_eq(op->action, "start", pcmk__str_casei)) {
            crm_trace("Mapping %s failure for %s: unknown services are not installed", op->action, op->rsc);
            op->rc = PCMK_OCF_NOT_INSTALLED;
            op->status = PCMK_EXEC_NOT_INSTALLED;
        }
        return TRUE;

    } else if (pcmk__str_eq(op->action, "start", pcmk__str_casei)
               && strstr(error, UPSTART_06_API ".Error.AlreadyStarted")) {
        crm_trace("Mapping %s failure for %s: starting a started resource is allowed", op->action, op->rsc);
        op->rc = PCMK_OCF_OK;
        return TRUE;
    }

    return FALSE;
}

static void
upstart_async_dispatch(DBusPendingCall *pending, void *user_data)
{
    DBusError error;
    DBusMessage *reply = NULL;
    svc_action_t *op = user_data;

    dbus_error_init(&error);
    if(pending) {
        reply = dbus_pending_call_steal_reply(pending);
    }

    if (pcmk_dbus_find_error(pending, reply, &error)) {

        /* ignore "already started" or "not running" errors */
        if (!upstart_mask_error(op, error.name)) {
            crm_err("%s for %s: %s", op->action, op->rsc, error.message);
        }
        dbus_error_free(&error);

    } else if (!g_strcmp0(op->action, "stop")) {
        /* No return vaue */
        op->rc = PCMK_OCF_OK;

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

    CRM_LOG_ASSERT(pending == op->opaque->pending);
    services_set_op_pending(op, NULL);
    services__finalize_async_op(op);

    if(reply) {
        dbus_message_unref(reply);
    }
}

/* For an asynchronous 'op', returns FALSE if 'op' should be free'd by the caller */
/* For a synchronous 'op', returns FALSE if 'op' fails */
gboolean
upstart_job_exec(svc_action_t * op)
{
    char *job = NULL;
    int arg_wait = TRUE;
    const char *arg_env = "pacemaker=1";
    const char *action = op->action;

    DBusError error;
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;
    DBusMessageIter iter, array_iter;

    op->rc = PCMK_OCF_UNKNOWN_ERROR;
    CRM_ASSERT(upstart_init());

    if (pcmk__str_eq(op->action, "meta-data", pcmk__str_casei)) {
        op->stdout_data = upstart_job_metadata(op->agent);
        op->rc = PCMK_OCF_OK;
        goto cleanup;
    }

    if(!upstart_job_by_name(op->agent, &job, op->timeout)) {
        crm_debug("Could not obtain job named '%s' to %s", op->agent, action);
        if (!g_strcmp0(action, "stop")) {
            op->rc = PCMK_OCF_OK;

        } else {
            op->rc = PCMK_OCF_NOT_INSTALLED;
            op->status = PCMK_EXEC_NOT_INSTALLED;
        }
        goto cleanup;
    }

    if (pcmk__strcase_any_of(op->action, "monitor", "status", NULL)) {
        char *path = get_first_instance(job, op->timeout);

        op->rc = PCMK_OCF_NOT_RUNNING;
        if(path) {
            DBusPendingCall *pending = NULL;
            char *state = pcmk_dbus_get_property(
                upstart_proxy, BUS_NAME, path, UPSTART_06_API ".Instance", "state",
                op->synchronous?NULL:upstart_job_check, op,
                op->synchronous?NULL:&pending, op->timeout);

            free(job);
            free(path);

            if(op->synchronous) {
                upstart_job_check("state", state, op);
                free(state);
                return op->rc == PCMK_OCF_OK;
            } else if (pending) {
                services_set_op_pending(op, pending);
                services_add_inflight_op(op);
                return TRUE;
            }
            return FALSE;
        }
        goto cleanup;

    } else if (!g_strcmp0(action, "start")) {
        action = "Start";
    } else if (!g_strcmp0(action, "stop")) {
        action = "Stop";
    } else if (!g_strcmp0(action, "restart")) {
        action = "Restart";
    } else {
        op->rc = PCMK_OCF_UNIMPLEMENT_FEATURE;
        goto cleanup;
    }

    crm_debug("Calling %s for %s on %s", action, op->rsc, job);

    msg = dbus_message_new_method_call(BUS_NAME, // target for the method call
                                       job, // object to call on
                                       UPSTART_JOB_IFACE, // interface to call on
                                       action); // method name
    CRM_ASSERT(msg != NULL);

    dbus_message_iter_init_append (msg, &iter);

    CRM_LOG_ASSERT(dbus_message_iter_open_container (&iter,
                                                     DBUS_TYPE_ARRAY,
                                                     DBUS_TYPE_STRING_AS_STRING,
                                                     &array_iter));

    CRM_LOG_ASSERT(dbus_message_iter_append_basic (&array_iter, DBUS_TYPE_STRING, &arg_env));
    CRM_LOG_ASSERT(dbus_message_iter_close_container (&iter, &array_iter));

    CRM_LOG_ASSERT(dbus_message_append_args(msg, DBUS_TYPE_BOOLEAN, &arg_wait, DBUS_TYPE_INVALID));

    if (op->synchronous == FALSE) {
        DBusPendingCall* pending = pcmk_dbus_send(msg, upstart_proxy, upstart_async_dispatch, op, op->timeout);
        free(job);

        if(pending) {
            services_set_op_pending(op, pending);
            services_add_inflight_op(op);
            return TRUE;
        }
        return FALSE;
    }

    dbus_error_init(&error);
    reply = pcmk_dbus_send_recv(msg, upstart_proxy, &error, op->timeout);

    if (dbus_error_is_set(&error)) {
        if(!upstart_mask_error(op, error.name)) {
            crm_err("Could not issue %s for %s: %s (%s)",
                    action, op->rsc, error.message, job);
        }
        dbus_error_free(&error);

    } else if (!g_strcmp0(op->action, "stop")) {
        /* No return vaue */
        op->rc = PCMK_OCF_OK;

    } else if(!pcmk_dbus_type_check(reply, NULL, DBUS_TYPE_OBJECT_PATH, __func__, __LINE__)) {
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


  cleanup:
    free(job);
    if(msg) {
        dbus_message_unref(msg);
    }

    if(reply) {
        dbus_message_unref(reply);
    }

    if (op->synchronous == FALSE) {
        return services__finalize_async_op(op) == pcmk_rc_ok;
    }
    return op->rc == PCMK_OCF_OK;
}
