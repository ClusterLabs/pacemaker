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

#include <systemd.h>
#include <gio/gio.h>

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
    
    g_type_init();

    if(path == NULL) {
        path = BUS_PATH;
    }

    proxy = g_dbus_proxy_new_for_bus_sync (
        G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE, NULL, /* GDBusInterfaceInfo */
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
    if(systemd_proxy == NULL) {
        systemd_proxy = get_proxy(NULL, BUS_NAME".Manager");
    }
    if(systemd_proxy == NULL) {
        return FALSE;
    }
    return TRUE;
}

void systemd_cleanup(void)
{
    g_object_unref(systemd_proxy);
    systemd_proxy = NULL;
}

static char *
systemd_service_name(const char *name)
{
    if(name == NULL) {
        return NULL;

    } else if(strstr(name, ".service")) {
        return strdup(name);
    }
    
    return g_strdup_printf("%s.service", name);
}

static gboolean
systemd_unit_by_name (
    GDBusProxy *proxy,
    const gchar *arg_name,
    gchar **out_unit,
    GCancellable *cancellable,
    GError **error)
{
    GVariant *_ret = NULL;
    char *name = NULL;
/*
  "  <method name=\"GetUnit\">\n"                                 \
  "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
  "   <arg name=\"unit\" type=\"o\" direction=\"out\"/>\n"        \
  "  </method>\n"                                                 \
*/  

    name = systemd_service_name(arg_name);
    _ret = g_dbus_proxy_call_sync (
        proxy, "GetUnit", g_variant_new ("(s)", name),
        G_DBUS_CALL_FLAGS_NONE, -1, cancellable, error);

    if (_ret) {
        g_variant_get (_ret, "(o)", out_unit);
        crm_info("%s = %s", arg_name, *out_unit);
        g_variant_unref (_ret);
    }

    free(name);
    return _ret != NULL;
}

static char *
systemd_unit_property(const char *obj, const gchar *iface, const char *name)
{
    GError *error = NULL;
    GDBusProxy *proxy;
    GVariant *asv = NULL;
    GVariant *value = NULL;
    GVariant *_ret = NULL;
    char *output = NULL;

    crm_info("Calling GetAll on %s", obj);
    proxy = get_proxy(obj, BUS_PROPERTY_IFACE);
    
    _ret = g_dbus_proxy_call_sync (
        proxy, "GetAll", g_variant_new ("(s)", iface),
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

    if (error) {
        crm_err("Cannot get properties for %s: %s", g_dbus_proxy_get_object_path(proxy), error->message);
        g_error_free(error);
        g_object_unref(proxy);
        return NULL;
    }
    crm_info("Call to GetAll passed: type '%s' %d\n", g_variant_get_type_string (_ret), g_variant_n_children (_ret));

    asv = g_variant_get_child_value(_ret, 0);
    crm_trace("asv type '%s' %d\n", g_variant_get_type_string (asv), g_variant_n_children (asv));
    
    value = g_variant_lookup_value(asv, name, NULL);
    if(value && g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
        crm_info("Got value '%s' for %s[%s]", g_variant_get_string(value, NULL), obj, name);
        output = g_variant_dup_string(value, NULL);

    } else {
        crm_info("No value for %s[%s]", obj, name);
    }

    g_object_unref(proxy);
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
    
    CRM_ASSERT(systemd_init());

/*
        "  <method name=\"ListUnits\">\n"                               \
        "   <arg name=\"units\" type=\"a(ssssssouso)\" direction=\"out\"/>\n" \
        "  </method>\n"                                                 \
*/  

    _ret = g_dbus_proxy_call_sync (
        systemd_proxy, "ListUnits", g_variant_new ("()"),
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

    if (error || _ret == NULL) {
        crm_err("Call to ListUnits failed: %s", error->message);
        g_error_free(error);
        return NULL;
    }
    
    g_variant_get (_ret, "(@a(ssssssouso))", &out_units);

    g_variant_iter_init (&iter, out_units);
    while (g_variant_iter_loop (&iter, "(ssssssouso)",
                                &u.id,
                                &u.description,
                                &u.load_state,
                                &u.active_state,
                                &u.sub_state,
                                &u.following,
                                &u.unit_path,
                                &u.job_id,
                                &u.job_type,
                                &u.job_path))
    {
        char *match = strstr(u.id, ".service");
        if(match) {
            lpc++;
            match[0] = 0;
            crm_trace("Got %s = %s", u.id, u.description);
            units = g_list_append(units, strdup(u.id));
        }
    }

    crm_info("Call to ListUnits passed: type '%s' count %d", g_variant_get_type_string (out_units), lpc);
    g_variant_unref (_ret);
    return units;
}

gboolean
systemd_unit_exists(const char *name)
{
    char *path = NULL;
    GError *error = NULL;
    gboolean pass = FALSE;

    CRM_ASSERT(systemd_init());

    pass = systemd_unit_by_name(systemd_proxy, name, &path, NULL, &error);

    if (error || pass == FALSE) {
        crm_err("Call to ListUnits failed: %s", error->message);
        g_error_free(error);
        pass = FALSE;

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
    GError *error = NULL;
    
    CRM_ASSERT(systemd_init());
    if(systemd_unit_by_name(systemd_proxy, name, &path, NULL, &error)) {
        char *desc = systemd_unit_property(path, BUS_NAME".Unit", "Description");
        meta = g_strdup_printf(
            "<?xml version=\"1.0\"?>\n"
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
            "  <special tag=\"upstart\">\n"
            "  </special>\n"
            "</resource-agent>\n",
            name, desc, name);
        free(desc);
    }
    return meta;
}

gboolean
systemd_unit_exec(svc_action_t* op, gboolean synchronous)
{
    char *unit = NULL;
    GError *error = NULL;
    gboolean pass = FALSE;
    GVariant *_ret = NULL;
    const char *action = op->action;
    char *name = systemd_service_name(op->rsc);
    
    op->rc = PCMK_EXECRA_UNKNOWN_ERROR;
    CRM_ASSERT(systemd_init());

    pass = systemd_unit_by_name (systemd_proxy, op->rsc, &unit, NULL, &error);
    if (error || pass == FALSE) {
        crm_err("Call to ListUnits failed: %s", error->message);
        g_error_free(error);
        op->rc = PCMK_EXECRA_NOT_INSTALLED;
        return FALSE;
    }
    
    if (safe_str_eq(op->action, "meta-data")) {
        op->stdout_data = systemd_unit_metadata(op->rsc);
        op->rc = PCMK_EXECRA_OK;
        goto cleanup;
    }

    if (safe_str_eq(op->action, "monitor") || safe_str_eq(action, "status")) {
        char *state = systemd_unit_property(unit, BUS_NAME".Unit", "ActiveState");
        gboolean running =  !g_strcmp0(state, "active");
        crm_info("%s %s", state, running ? "running" : "stopped");
		
        if (running) {
            op->rc = PCMK_EXECRA_OK;
            goto cleanup;
        }
        op->rc = PCMK_EXECRA_NOT_RUNNING;
        goto cleanup;

    } else if (!g_strcmp0(action, "start")) {
        action = "StartUnit";
    } else if (!g_strcmp0(action, "stop")) {
        action = "StopUnit";
    } else if (!g_strcmp0(action, "restart")) {
        action = "RestartUnit";
    } else {
        return PCMK_EXECRA_UNIMPLEMENT_FEATURE;
    }

    crm_info("Calling %s for %s: %s", action, op->rsc, unit);
    _ret = g_dbus_proxy_call_sync (
        systemd_proxy, action, g_variant_new ("(ss)", name, "replace"),
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
    
    if (error) {
        /* ignore "already started" or "not running" errors */
        if (safe_str_eq(action, "Start")
            && strstr(error->message, "Error.AlreadyStarted")) {
            crm_trace("Masking Start failure for %s: already started", op->rsc);
            op->rc = PCMK_EXECRA_OK;
        } else if (safe_str_eq(action, "Stop")
                   && strstr(error->message, "systemd1.InvalidName")) {
            crm_trace("Masking Stop failure for %s: unknown services are stopped", op->rsc);
            op->rc = PCMK_EXECRA_OK;
        } else {
            crm_err("Could not issue %s for %s: %s (%s)", action, op->rsc, error->message, unit);
        }
        g_error_free(error);

    } else {
        char *path = NULL;
        g_variant_get(_ret, "(o)", &path);
        crm_info("Call to %s passed: type '%s' %s", action, g_variant_get_type_string (_ret), path);
        op->rc = PCMK_EXECRA_OK;
    }

  cleanup:
    free(unit);
    free(name);

    return op->rc == PCMK_EXECRA_OK;
}
