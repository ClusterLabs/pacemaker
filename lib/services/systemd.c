/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright (C) 2012 Andrew Beekhof <andrew@beekhof.net>
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>

#include <gio/gio.h>
#include <services_private.h>
#include <systemd.h>
#include <dbus/dbus.h>
#include <pcmk-dbus.h>

#define BUS_NAME "org.freedesktop.systemd1"
#define BUS_PATH "/org/freedesktop/systemd1"

#define BUS_PROPERTY_IFACE "org.freedesktop.DBus.Properties"

/*
   /usr/share/dbus-1/interfaces/org.freedesktop.systemd1.Manager.xml
*/

struct unit_info {
    const char *id;
    const char *description;
    const char *load_state;
    const char *active_state;
    const char *sub_state;
    const char *following;
    const char *unit_path;
    uint32_t job_id;
    const char *job_type;
    const char *job_path;
};

static DBusMessage *systemd_new_method(const char *iface, const char *method)
{
    crm_trace("Calling: %s on %s", method, iface);
    return dbus_message_new_method_call(BUS_NAME, // target for the method call
                                        BUS_PATH, // object to call on
                                        iface, // interface to call on
                                        method); // method name
}


static DBusConnection* systemd_proxy = NULL;
static gboolean
systemd_init(void)
{
    static int need_init = 1;
    /* http://dbus.freedesktop.org/doc/api/html/group__DBusConnection.html */

    if (need_init) {
        need_init = 0;
        systemd_proxy = pcmk_dbus_connect();
    }
    if (systemd_proxy == NULL) {
        return FALSE;
    }
    return TRUE;
}

void
systemd_cleanup(void)
{
    if (systemd_proxy) {
        pcmk_dbus_disconnect(systemd_proxy);
        systemd_proxy = NULL;
    }
}

static char *
systemd_service_name(const char *name)
{
    if (name == NULL) {
        return NULL;

    } else if (strstr(name, ".service")) {
        return strdup(name);
    }

    return g_strdup_printf("%s.service", name);
}

static bool
systemd_daemon_reload(void)
{
    const char *method = "Reload";
    DBusMessage *reply = NULL;
    DBusMessage *msg = systemd_new_method(BUS_NAME".Manager", method);

    CRM_ASSERT(msg != NULL);
    reply = pcmk_dbus_send_recv(msg, systemd_proxy, NULL);
    dbus_message_unref(msg);
    if(reply) {
        dbus_message_unref(reply);
    }
    return TRUE;
}

static gboolean
systemd_unit_by_name(const gchar * arg_name, gchar ** out_unit)
{
    DBusMessage *msg;
    DBusMessage *reply = NULL;
    const char *method = "GetUnit";
    char *name = NULL;
    DBusError error;

/*
  <method name="GetUnit">
   <arg name="name" type="s" direction="in"/>
   <arg name="unit" type="o" direction="out"/>
  </method>

  <method name="LoadUnit">
   <arg name="name" type="s" direction="in"/>
   <arg name="unit" type="o" direction="out"/>
  </method>
 */

    if (systemd_init() == FALSE) {
        return FALSE;
    }

    name = systemd_service_name(arg_name);

    while(*out_unit == NULL) {
        msg = systemd_new_method(BUS_NAME".Manager", method);
        CRM_ASSERT(msg != NULL);

        CRM_LOG_ASSERT(dbus_message_append_args(msg, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID));

        dbus_error_init(&error);
        reply = pcmk_dbus_send_recv(msg, systemd_proxy, &error);
        dbus_message_unref(msg);

        if(error.name) {
            crm_info("Call to %s failed: %s", method, error.name);

        } else if(pcmk_dbus_type_check(reply, NULL, DBUS_TYPE_OBJECT_PATH, __FUNCTION__, __LINE__)) {
            if(out_unit) {
                char *path = NULL;

                dbus_message_get_args (reply, NULL,
                                       DBUS_TYPE_OBJECT_PATH, &path,
                                       DBUS_TYPE_INVALID);

                *out_unit = strdup(path);
            }
            dbus_message_unref(reply);
            free(name);
            return TRUE;
        }

        if(strcmp(method, "LoadUnit") != 0) {
            method = "LoadUnit";
            crm_debug("Cannot find %s, reloading the systemd manager configuration", name);
            systemd_daemon_reload();
            if(reply) {
                dbus_message_unref(reply);
                reply = NULL;
            }

        } else {
            free(name);
            return FALSE;
        }
    }
    return FALSE;
}

GList *
systemd_unit_listall(void)
{
    int lpc = 0;
    GList *units = NULL;
    DBusMessageIter args;
    DBusMessageIter unit;
    DBusMessageIter elem;
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;
    const char *method = "ListUnits";
    DBusError error;

    if (systemd_init() == FALSE) {
        return NULL;
    }

/*
        "  <method name=\"ListUnits\">\n"                               \
        "   <arg name=\"units\" type=\"a(ssssssouso)\" direction=\"out\"/>\n" \
        "  </method>\n"                                                 \
*/

    dbus_error_init(&error);
    msg = systemd_new_method(BUS_NAME".Manager", method);
    CRM_ASSERT(msg != NULL);

    reply = pcmk_dbus_send_recv(msg, systemd_proxy, &error);
    dbus_message_unref(msg);

    if(error.name) {
        crm_err("Call to %s failed: %s", method, error.name);
        return NULL;

    } else if (!dbus_message_iter_init(reply, &args)) {
        crm_err("Call to %s failed: Message has no arguments", method);
        dbus_message_unref(reply);
        return NULL;
    }

    if(!pcmk_dbus_type_check(reply, &args, DBUS_TYPE_ARRAY, __FUNCTION__, __LINE__)) {
        crm_err("Call to %s failed: Message has invalid arguments", method);
        dbus_message_unref(reply);
        return NULL;
    }

    dbus_message_iter_recurse(&args, &unit);
    while (dbus_message_iter_get_arg_type (&unit) != DBUS_TYPE_INVALID) {
        DBusBasicValue value;

        if(!pcmk_dbus_type_check(reply, &unit, DBUS_TYPE_STRUCT, __FUNCTION__, __LINE__)) {
            continue;
        }

        dbus_message_iter_recurse(&unit, &elem);
        if(!pcmk_dbus_type_check(reply, &elem, DBUS_TYPE_STRING, __FUNCTION__, __LINE__)) {
            continue;
        }

        dbus_message_iter_get_basic(&elem, &value);
        crm_trace("Got: %s", value.str);
        if(value.str) {
            char *match = strstr(value.str, ".service");

            if (match) {
                lpc++;
                match[0] = 0;

                units = g_list_append(units, strdup(value.str));
            }
        }
        dbus_message_iter_next (&unit);
    }

    dbus_message_unref(reply);

    crm_trace("Found %d systemd services", lpc);
    return units;
}

gboolean
systemd_unit_exists(const char *name)
{
    return systemd_unit_by_name(name, NULL);
}

static char *
systemd_unit_metadata(const char *name)
{
    char *path = NULL;
    char *meta = NULL;
    char *desc = NULL;

    if (systemd_unit_by_name(name, &path)) {
        desc = pcmk_dbus_get_property(systemd_proxy, BUS_NAME, path, BUS_NAME ".Unit", "Description");
    } else {
        desc = g_strdup_printf("systemd unit file for %s", name);
    }

    meta = g_strdup_printf("<?xml version=\"1.0\"?>\n"
                           "<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"
                           "<resource-agent name=\"%s\" version=\"0.1\">\n"
                           "  <version>1.0</version>\n"
                           "  <longdesc lang=\"en\">\n"
                           "    %s\n"
                           "  </longdesc>\n"
                           "  <shortdesc lang=\"en\">systemd unit file for %s</shortdesc>\n"
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
                           "  <special tag=\"systemd\">\n"
                           "  </special>\n" "</resource-agent>\n", name, desc, name);
    free(desc);
    return meta;
}

static bool
systemd_mask_error(svc_action_t *op, const char *error)
{
    crm_trace("Could not issue %s for %s: %s", op->action, op->rsc, error);
    if(strstr(error, "org.freedesktop.systemd1.InvalidName")
       || strstr(error, "org.freedesktop.systemd1.LoadFailed")
       || strstr(error, "org.freedesktop.systemd1.NoSuchUnit")) {

        if (safe_str_eq(op->action, "stop")) {
            crm_trace("Masking %s failure for %s: unknown services are stopped", op->action, op->rsc);
            op->rc = PCMK_OCF_OK;

        } else {
            crm_trace("Mapping %s failure for %s: unknown services are not installed", op->action, op->rsc);
            op->rc = PCMK_OCF_NOT_INSTALLED;
            op->status = PCMK_LRM_OP_NOT_INSTALLED;
        }
        return TRUE;
    }

    return FALSE;
}

static void
systemd_async_dispatch(DBusPendingCall *pending, void *user_data)
{
    DBusError error;
    DBusMessage *reply = NULL;
    svc_action_t *op = user_data;

    dbus_error_init(&error);
    if(pending) {
        reply = dbus_pending_call_steal_reply(pending);
    }
    if(pcmk_dbus_find_error(op->action, pending, reply, &error)) {

        /* ignore "already started" or "not running" errors */
        if (!systemd_mask_error(op, error.name)) {
            crm_err("%s for %s: %s", op->action, op->rsc, error.message);
        }

    } else {
        if(!pcmk_dbus_type_check(reply, NULL, DBUS_TYPE_OBJECT_PATH, __FUNCTION__, __LINE__)) {
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

    operation_finalize(op);

    if(pending) {
        dbus_pending_call_unref(pending);
    }
    if(reply) {
        dbus_message_unref(reply);
    }
}

#define SYSTEMD_OVERRIDE_ROOT "/run/systemd/system/"

gboolean
systemd_unit_exec(svc_action_t * op, gboolean synchronous)
{
    DBusError error;
    char *unit = NULL;
    const char *replace_s = "replace";
    gboolean pass = FALSE;
    const char *method = op->action;
    char *name = systemd_service_name(op->agent);
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;

    dbus_error_init(&error);
    op->rc = PCMK_OCF_UNKNOWN_ERROR;
    CRM_ASSERT(systemd_init());

    crm_debug("Performing %ssynchronous %s op on systemd unit %s named '%s'",
              synchronous ? "" : "a", op->action, op->agent, op->rsc);

    if (safe_str_eq(op->action, "meta-data")) {
        op->stdout_data = systemd_unit_metadata(op->agent);
        op->rc = PCMK_OCF_OK;
        goto cleanup;
    }

    pass = systemd_unit_by_name(op->agent, &unit);
    if (pass == FALSE) {
        crm_debug("Could not obtain unit named '%s'", op->agent);
#if 0
        if (error && strstr(error->message, "systemd1.NoSuchUnit")) {
            op->rc = PCMK_OCF_NOT_INSTALLED;
            op->status = PCMK_LRM_OP_NOT_INSTALLED;
        }
#endif
        goto cleanup;
    }

    if (safe_str_eq(op->action, "monitor") || safe_str_eq(method, "status")) {
        char *state = pcmk_dbus_get_property(systemd_proxy, BUS_NAME, unit, BUS_NAME ".Unit", "ActiveState");

        if (g_strcmp0(state, "active") == 0) {
            op->rc = PCMK_OCF_OK;
        } else {
            op->rc = PCMK_OCF_NOT_RUNNING;
        }

        free(state);
        goto cleanup;

    } else if (g_strcmp0(method, "start") == 0) {
        FILE *file_strm = NULL;
        char *override_dir = g_strdup_printf("%s/%s", SYSTEMD_OVERRIDE_ROOT, unit);
        char *override_file = g_strdup_printf("%s/50-pacemaker.conf", override_dir);

        method = "StartUnit";
        crm_build_path(override_dir, 0755);

        file_strm = fopen(override_file, "w");
        if (file_strm != NULL) {
            int rc = fprintf(file_strm, "[Service]\nRestart=no");
            if (rc < 0) {
                crm_perror(LOG_ERR, "Cannot write to systemd override file %s: %s (%d)", override_file, pcmk_strerror(errno), errno);
            }

        } else {
            crm_err("Cannot open systemd override file %s for writing: %s (%d)", override_file, pcmk_strerror(errno), errno);
        }

        if (file_strm != NULL) {
            fflush(file_strm);
            fclose(file_strm);
        }
        systemd_daemon_reload();
        free(override_file);
        free(override_dir);

    } else if (g_strcmp0(method, "stop") == 0) {
        char *override_file = g_strdup_printf("%s/%s/50-pacemaker.conf", SYSTEMD_OVERRIDE_ROOT, unit);

        method = "StopUnit";
        unlink(override_file);
        free(override_file);
        systemd_daemon_reload();

    } else if (g_strcmp0(method, "restart") == 0) {
        method = "RestartUnit";
    } else {
        op->rc = PCMK_OCF_UNIMPLEMENT_FEATURE;
        goto cleanup;
    }

    crm_debug("Calling %s for %s: %s", method, op->rsc, unit);

    msg = systemd_new_method(BUS_NAME".Manager", method);
    CRM_ASSERT(msg != NULL);

    /* (ss) */
    CRM_LOG_ASSERT(dbus_message_append_args(msg, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID));
    CRM_LOG_ASSERT(dbus_message_append_args(msg, DBUS_TYPE_STRING, &replace_s, DBUS_TYPE_INVALID));

    if (synchronous == FALSE) {
        free(unit);
        free(name);
        return pcmk_dbus_send(msg, systemd_proxy, systemd_async_dispatch, op);
    }

    dbus_error_init(&error);
    reply = pcmk_dbus_send_recv(msg, systemd_proxy, &error);

    if(error.name) {
        /* ignore "already started" or "not running" errors */
        if(!systemd_mask_error(op, error.name)) {
            crm_err("Could not issue %s for %s: %s (%s)", method, op->rsc, error.name, unit);
        }
        goto cleanup;

    } else if(!pcmk_dbus_type_check(reply, NULL, DBUS_TYPE_OBJECT_PATH, __FUNCTION__, __LINE__)) {
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
    free(unit);
    free(name);

    if(msg) {
        dbus_message_unref(msg);
    }

    if(reply) {
        dbus_message_unref(reply);
    }

    if (synchronous == FALSE) {
        operation_finalize(op);
        return TRUE;
    }
    return op->rc == PCMK_OCF_OK;
}
