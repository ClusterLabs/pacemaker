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

static GDBusProxy *systemd_proxy = NULL;

static GDBusProxy *
get_proxy(const char *path, const char *interface)
{
    GError *error = NULL;
    GDBusProxy *proxy = NULL;

#ifndef GLIB_DEPRECATED_IN_2_36
    g_type_init();
#endif

    if (path == NULL) {
        path = BUS_PATH;
    }

    proxy = g_dbus_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE, NULL,     /* GDBusInterfaceInfo */
                                          BUS_NAME, path, interface,
                                          NULL, /* GCancellable */ &error);

    if (error) {
        crm_err("Can't connect obtain proxy to %s interface: %s", interface, error->message);
        g_error_free(error);
        proxy = NULL;
    }
    return proxy;
}

static gboolean
systemd_init(void)
{
    static int need_init = 1;

    if (need_init) {
        need_init = 0;
        systemd_proxy = get_proxy(NULL, BUS_NAME ".Manager");
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
        g_object_unref(systemd_proxy);
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

static void
systemd_daemon_reload(GDBusProxy * proxy, GError ** error)
{
    GVariant *_ret = g_dbus_proxy_call_sync(proxy, "Reload", g_variant_new("()"),
                                            G_DBUS_CALL_FLAGS_NONE, -1, NULL, error);

    if (_ret) {
        g_variant_unref(_ret);
    }
}

static gboolean
systemd_unit_by_name(GDBusProxy * proxy,
                     const gchar * arg_name,
                     gchar ** out_unit, GCancellable * cancellable, GError ** error)
{
    GError *reload_error = NULL;
    GVariant *_ret = NULL;
    char *name = NULL;
    int retry = 0;

/*
  "  <method name=\"GetUnit\">\n"                                 \
  "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
  "   <arg name=\"unit\" type=\"o\" direction=\"out\"/>\n"        \
  "  </method>\n"                                                 \
*/

    name = systemd_service_name(arg_name);
    crm_debug("Calling GetUnit");
    _ret = g_dbus_proxy_call_sync(proxy, "GetUnit", g_variant_new("(s)", name),
                                  G_DBUS_CALL_FLAGS_NONE, -1, cancellable, error);

    if (_ret) {
        crm_debug("Checking output");
        g_variant_get(_ret, "(o)", out_unit);
        crm_debug("%s = %s", arg_name, *out_unit);
        g_variant_unref(_ret);
        goto done;
    }

    crm_debug("Reloading the systemd manager configuration");
    systemd_daemon_reload(proxy, &reload_error);
    retry++;

    if (reload_error) {
        crm_err("Cannot reload the systemd manager configuration: %s", reload_error->message);
        g_error_free(reload_error);
        goto done;
    }

    if (*error) {
        crm_debug("Cannot find %s: %s", name, (*error)->message);
        g_error_free(*error);
        *error = NULL;
    }

/*
  <method name="LoadUnit">
   <arg name="name" type="s" direction="in"/>
   <arg name="unit" type="o" direction="out"/>
  </method>
 */
    crm_debug("Calling LoadUnit");
    _ret = g_dbus_proxy_call_sync(proxy, "LoadUnit", g_variant_new("(s)", name),
                                  G_DBUS_CALL_FLAGS_NONE, -1, cancellable, error);

    if (_ret) {
        crm_debug("Checking output");
        g_variant_get(_ret, "(o)", out_unit);
        crm_debug("%s = %s", arg_name, *out_unit);
        g_variant_unref(_ret);
    }

  done:
    free(name);
    return _ret != NULL;
}

static char *
systemd_unit_property(const char *obj, const gchar * iface, const char *name)
{
    GError *error = NULL;
    GDBusProxy *proxy;
    GVariant *asv = NULL;
    GVariant *value = NULL;
    GVariant *_ret = NULL;
    char *output = NULL;

    crm_trace("Calling GetAll on %s", obj);
    proxy = get_proxy(obj, BUS_PROPERTY_IFACE);

    if (!proxy) {
        return NULL;
    }

    _ret = g_dbus_proxy_call_sync(proxy, "GetAll", g_variant_new("(s)", iface),
                                  G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

    if (error) {
        crm_err("Cannot get properties for %s: %s", g_dbus_proxy_get_object_path(proxy),
                error->message);
        g_error_free(error);
        g_object_unref(proxy);
        return NULL;
    }
    crm_debug("Call to GetAll passed: type '%s' %d\n", g_variant_get_type_string(_ret),
             g_variant_n_children(_ret));

    asv = g_variant_get_child_value(_ret, 0);
    crm_trace("asv type '%s' %d\n", g_variant_get_type_string(asv), g_variant_n_children(asv));

    value = g_variant_lookup_value(asv, name, NULL);
    if (value && g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
        crm_info("Got value '%s' for %s[%s]", g_variant_get_string(value, NULL), obj, name);
        output = g_variant_dup_string(value, NULL);

    } else {
        crm_info("No value for %s[%s]", obj, name);
    }

    g_object_unref(proxy);
    g_variant_unref(_ret);
    return output;
}

GList *
systemd_unit_listall(void)
{
    int lpc = 0;
    GList *units = NULL;
    GError *error = NULL;
    GVariant *out_units = NULL;
    GVariantIter iter;
    struct unit_info u;
    GVariant *_ret = NULL;

    if (systemd_init() == FALSE) {
        return NULL;
    }

/*
        "  <method name=\"ListUnits\">\n"                               \
        "   <arg name=\"units\" type=\"a(ssssssouso)\" direction=\"out\"/>\n" \
        "  </method>\n"                                                 \
*/

    _ret = g_dbus_proxy_call_sync(systemd_proxy, "ListUnits", g_variant_new("()"),
                                  G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

    if (error || _ret == NULL) {
        crm_info("Call to ListUnits failed: %s", error ? error->message : "unknown");
        if(error) {
            g_error_free(error);
        }
        return NULL;
    }

    g_variant_get(_ret, "(@a(ssssssouso))", &out_units);

    g_variant_iter_init(&iter, out_units);
    while (g_variant_iter_loop(&iter, "(ssssssouso)",
                               &u.id,
                               &u.description,
                               &u.load_state,
                               &u.active_state,
                               &u.sub_state,
                               &u.following, &u.unit_path, &u.job_id, &u.job_type, &u.job_path)) {
        char *match = strstr(u.id, ".service");

        if (match) {
            lpc++;
            match[0] = 0;
            crm_trace("Got %s[%s] = %s", u.id, u.active_state, u.description);
            units = g_list_append(units, strdup(u.id));
        }
    }

    crm_info("Call to ListUnits passed: type '%s' count %d", g_variant_get_type_string(out_units),
             lpc);
    g_variant_unref(_ret);
    return units;
}

gboolean
systemd_unit_exists(const char *name)
{
    char *path = NULL;
    GError *error = NULL;
    gboolean pass = FALSE;

    if (systemd_init() == FALSE) {
        return FALSE;
    }

    pass = systemd_unit_by_name(systemd_proxy, name, &path, NULL, &error);

    if (error || pass == FALSE) {
        pass = FALSE;
        crm_err("Call to ListUnits failed: %s", error ? error->message : "unknown");
        if(error) {
            g_error_free(error);
        }

    } else {
        crm_trace("Got %s", path);
    }
    /* free(path) */
    return pass;
}

static char *
systemd_unit_metadata(const char *name)
{
    char *path = NULL;
    char *meta = NULL;
    char *desc = NULL;
    GError *error = NULL;

    CRM_ASSERT(systemd_init());
    if (systemd_unit_by_name(systemd_proxy, name, &path, NULL, &error)) {
        desc = systemd_unit_property(path, BUS_NAME ".Unit", "Description");
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

static void
systemd_unit_exec_done(GObject * source_object, GAsyncResult * res, gpointer user_data)
{
    GError *error = NULL;
    GVariant *_ret = NULL;
    svc_action_t *op = user_data;
    GDBusProxy *proxy = G_DBUS_PROXY(source_object);

    /* Obtain rc and stderr/out */
    _ret = g_dbus_proxy_call_finish(proxy, res, &error);

    if (error) {
        /* ignore "already started" or "not running" errors */
        crm_trace("Could not issue %s for %s: %s", op->action, op->rsc, error->message);
        if (strstr(error->message, "systemd1.LoadFailed")
            || strstr(error->message, "systemd1.InvalidName")) {

            if (safe_str_eq(op->action, "stop")) {
                crm_trace("Masking Stop failure for %s: unknown services are stopped", op->rsc);
                op->rc = PCMK_OCF_OK;

            } else {
                op->rc = PCMK_OCF_NOT_INSTALLED;
                op->status = PCMK_LRM_OP_NOT_INSTALLED;
            }

        } else {
            crm_err("Could not issue %s for %s: %s", op->action, op->rsc, error->message);
        }
        g_error_free(error);

    } else if(g_variant_is_of_type (_ret, G_VARIANT_TYPE("(o)"))) {
        char *path = NULL;

        g_variant_get(_ret, "(o)", &path);
        crm_info("Call to %s passed: type '%s' %s", op->action, g_variant_get_type_string(_ret),
                 path);
        op->rc = PCMK_OCF_OK;

    } else {
        crm_err("Call to %s passed but return type was '%s' not '(o)'", op->action, g_variant_get_type_string(_ret));
        op->rc = PCMK_OCF_OK;
    }

    operation_finalize(op);
    if (_ret) {
        g_variant_unref(_ret);
    }
}

#define SYSTEMD_OVERRIDE_ROOT "/run/systemd/system/"

gboolean
systemd_unit_exec(svc_action_t * op, gboolean synchronous)
{
    char *unit = NULL;
    GError *error = NULL;
    gboolean pass = FALSE;
    GVariant *_ret = NULL;
    const char *action = op->action;
    char *name = systemd_service_name(op->agent);

    op->rc = PCMK_OCF_UNKNOWN_ERROR;
    CRM_ASSERT(systemd_init());

    crm_debug("Performing %ssynchronous %s op on systemd unit %s named '%s'",
              synchronous ? "" : "a", op->action, op->agent, op->rsc);

    if (safe_str_eq(op->action, "meta-data")) {
        op->stdout_data = systemd_unit_metadata(op->agent);
        op->rc = PCMK_OCF_OK;
        goto cleanup;
    }

    pass = systemd_unit_by_name(systemd_proxy, op->agent, &unit, NULL, &error);
    if (error || pass == FALSE) {
        crm_debug("Could not obtain unit named '%s': %s", op->agent,
                  error ? error->message : "unknown");
        if (error && strstr(error->message, "systemd1.NoSuchUnit")) {
            op->rc = PCMK_OCF_NOT_INSTALLED;
            op->status = PCMK_LRM_OP_NOT_INSTALLED;
        }
        if(error) {
            g_error_free(error);
        }
        goto cleanup;
    }

    if (safe_str_eq(op->action, "monitor") || safe_str_eq(action, "status")) {
        char *state = systemd_unit_property(unit, BUS_NAME ".Unit", "ActiveState");

        if (g_strcmp0(state, "active") == 0) {
            op->rc = PCMK_OCF_OK;
        } else {
            op->rc = PCMK_OCF_NOT_RUNNING;
        }

        free(state);
        goto cleanup;

    } else if (g_strcmp0(action, "start") == 0) {
        FILE *file_strm = NULL;
        char *override_dir = g_strdup_printf("%s/%s", SYSTEMD_OVERRIDE_ROOT, unit);
        char *override_file = g_strdup_printf("%s/50-pacemaker.conf", override_dir);

        action = "StartUnit";
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
        systemd_daemon_reload(systemd_proxy, &error);
        if(error) {
            g_error_free(error);
        }
        free(override_file);
        free(override_dir);

    } else if (g_strcmp0(action, "stop") == 0) {
        char *override_file = g_strdup_printf("%s/%s/50-pacemaker.conf", SYSTEMD_OVERRIDE_ROOT, unit);

        action = "StopUnit";
        unlink(override_file);
        free(override_file);
        systemd_daemon_reload(systemd_proxy, &error);
        if(error) {
            g_error_free(error);
        }

    } else if (g_strcmp0(action, "restart") == 0) {
        action = "RestartUnit";
    } else {
        op->rc = PCMK_OCF_UNIMPLEMENT_FEATURE;
        goto cleanup;
    }

    crm_debug("Calling %s for %s: %s", action, op->rsc, unit);
    if (synchronous == FALSE) {
        g_dbus_proxy_call(systemd_proxy, action, g_variant_new("(ss)", name, "replace"),
                          G_DBUS_CALL_FLAGS_NONE, op->timeout, NULL, systemd_unit_exec_done, op);
        free(unit);
        free(name);
        return TRUE;
    }

    _ret = g_dbus_proxy_call_sync(systemd_proxy, action, g_variant_new("(ss)", name, "replace"),
                                  G_DBUS_CALL_FLAGS_NONE, op->timeout, NULL, &error);

    if (error) {
        /* ignore "already started" or "not running" errors */
        if (safe_str_eq(op->action, "stop")
            && strstr(error->message, "systemd1.InvalidName")) {
            crm_trace("Masking Stop failure for %s: unknown services are stopped", op->rsc);
            op->rc = PCMK_OCF_OK;
        } else {
            crm_err("Could not issue %s for %s: %s (%s)", action, op->rsc, error->message, unit);
        }
        g_error_free(error);

    } else if(g_variant_is_of_type (_ret, G_VARIANT_TYPE("(o)"))) {
        char *path = NULL;

        g_variant_get(_ret, "(o)", &path);
        crm_info("Call to %s passed: type '%s' %s", op->action, g_variant_get_type_string(_ret),
                 path);
        op->rc = PCMK_OCF_OK;

    } else {
        crm_err("Call to %s passed but return type was '%s' not '(o)'", op->action, g_variant_get_type_string(_ret));
        op->rc = PCMK_OCF_OK;
    }

  cleanup:
    free(unit);
    free(name);

    if (_ret) {
        g_variant_unref(_ret);
    }
    if (synchronous == FALSE) {
        operation_finalize(op);
        return TRUE;
    }
    return op->rc == PCMK_OCF_OK;
}
