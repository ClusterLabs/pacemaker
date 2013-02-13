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
 * File: upstart-dbus.c
 * Copyright (C) 2010 Senko Rasic <senko.rasic@dobarkod.hr>
 * Copyright (c) 2010 Ante Karamatic <ivoks@init.hr>
 *
 *
 * Each exported function is standalone, and creates a new connection to
 * the upstart daemon. This is because lrmd plugins fork off for exec,
 * and if we try and share the connection, the whole thing blocks
 * indefinitely.
 */

#include <crm_internal.h>

#include <stdio.h>

#include <crm/crm.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>

#include <services_private.h>
#include <upstart.h>

#include <glib.h>
#include <gio/gio.h>

#define BUS_NAME "com.ubuntu.Upstart"
#define BUS_PATH "/com/ubuntu/Upstart"

#define BUS_MANAGER_IFACE BUS_NAME"0_6"
#define BUS_PROPERTY_IFACE "org.freedesktop.DBus.Properties"

/*
  http://upstart.ubuntu.com/wiki/DBusInterface
*/
static GDBusProxy *upstart_proxy = NULL;

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
upstart_init(void)
{
    static int need_init = 1;

    if (need_init) {
        need_init = 0;
        upstart_proxy = get_proxy(NULL, BUS_MANAGER_IFACE);
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
        g_object_unref(upstart_proxy);
        upstart_proxy = NULL;
    }
}

static gboolean
upstart_job_by_name(GDBusProxy * proxy,
                    const gchar * arg_name,
                    gchar ** out_unit, GCancellable * cancellable, GError ** error)
{
/*
  com.ubuntu.Upstart0_6.GetJobByName (in String name, out ObjectPath job)
*/
    GVariant *_ret = g_dbus_proxy_call_sync(proxy, "GetJobByName", g_variant_new("(s)", arg_name),
                                            G_DBUS_CALL_FLAGS_NONE, -1, cancellable, error);

    if (_ret) {
        g_variant_get(_ret, "(o)", out_unit);
        g_variant_unref(_ret);
    }

    return _ret != NULL;
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
        crm_err("Found: %s", match);
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
    GError *error = NULL;
    GVariantIter *iter;
    char *path = NULL;
    GVariant *_ret = NULL;
    int lpc = 0;

    if (upstart_init() == FALSE) {
        return NULL;
    }

/*
  com.ubuntu.Upstart0_6.GetAllJobs (out <Array of ObjectPath> jobs)
*/
    _ret = g_dbus_proxy_call_sync(upstart_proxy, "GetAllJobs", g_variant_new("()"),
                                  G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

    if (error) {
        crm_info("Call to GetAllJobs failed: %s", error->message);
        g_error_free(error);
        return NULL;
    }

    g_variant_get(_ret, "(ao)", &iter);
    while (g_variant_iter_loop(iter, "o", &path)) {
        int llpc = 0;
        const char *job = path;

        while (path[llpc] != 0) {
            if (path[llpc] == '/') {
                job = path + llpc + 1;
            }
            llpc++;
        }
        lpc++;
        crm_trace("%s\n", path);
        units = g_list_append(units, fix_upstart_name(job));
    }
    crm_info("Call to GetAllJobs passed: type '%s', count %d", g_variant_get_type_string(_ret),
             lpc);

    g_variant_iter_free(iter);
    g_variant_unref(_ret);
    return units;
}

gboolean
upstart_job_exists(const char *name)
{
    char *path = NULL;
    GError *error = NULL;
    gboolean pass = FALSE;

    if (upstart_init() == FALSE) {
        return FALSE;
    }

    pass = upstart_job_by_name(upstart_proxy, name, &path, NULL, &error);

    if (error) {
        crm_trace("Call to ListUnits failed: %s", error->message);
        g_error_free(error);
        pass = FALSE;

    } else if (pass) {
        crm_trace("Got %s", path);
    }
    /* free(path) */
    return pass;
}

static char *
upstart_job_property(const char *obj, const gchar * iface, const char *name)
{
    GError *error = NULL;
    GDBusProxy *proxy;
    GVariant *asv = NULL;
    GVariant *value = NULL;
    GVariant *_ret = NULL;
    char *output = NULL;

    crm_info("Calling GetAll on %s", obj);
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
    crm_info("Call to GetAll passed: type '%s' %d\n", g_variant_get_type_string(_ret),
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

static char *
get_first_instance(const gchar * job)
{
    char *instance = NULL;
    GError *error = NULL;
    GDBusProxy *proxy = get_proxy(job, BUS_MANAGER_IFACE ".Job");
    GVariant *_ret = g_dbus_proxy_call_sync(proxy, "GetAllInstances", g_variant_new("()"),
                                            G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

    if (error) {
        crm_err("Cannot call GetAllInstances for %s: %s", job, error->message);
        g_error_free(error);
        return NULL;
    }

    crm_trace("Call to GetAllInstances passed: type '%s' %d\n", g_variant_get_type_string(_ret),
              g_variant_n_children(_ret));
    if (g_variant_n_children(_ret)) {
        GVariant *tmp1 = g_variant_get_child_value(_ret, 0);

        if (g_variant_n_children(tmp1)) {
            GVariant *tmp2 = g_variant_get_child_value(tmp1, 0);

            instance = g_variant_dup_string(tmp2, NULL);
        }
    }

    crm_info("Result: %s", instance);
    g_variant_unref(_ret);
    return instance;
}

gboolean
upstart_job_running(const gchar * name)
{
    char *job = NULL;
    GError *error = NULL;
    gboolean pass = FALSE;

    pass = upstart_job_by_name(upstart_proxy, name, &job, NULL, &error);
    if (error || pass == FALSE) {
        crm_err("Call to ListUnits failed: %s", error ? error->message : "unknown");
        g_error_free(error);

    } else {
        char *instance = get_first_instance(job);

        pass = FALSE;
        if (instance) {
            if (instance) {
                char *state =
                    upstart_job_property(instance, BUS_MANAGER_IFACE ".Instance", "state");
                crm_info("State of %s: %s", name, state);
                if (state) {
                    pass = !g_strcmp0(state, "running");
                }
                free(state);
            }
        }
        free(instance);
    }

    crm_info("%s is%s running", name, pass ? "" : " not");
    return pass;
}

static char *
upstart_job_metadata(const char *name)
{
    return g_strdup_printf("<?xml version=\"1.0\"?>\n"
                           "<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"
                           "<resource-agent name=\"%s\" version=\"0.1\">\n"
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

static void
upstart_job_exec_done(GObject * source_object, GAsyncResult * res, gpointer user_data)
{
    GError *error = NULL;
    GVariant *_ret = NULL;
    svc_action_t *op = user_data;
    GDBusProxy *proxy = G_DBUS_PROXY(source_object);

    /* Obtain rc and stderr/out */
    _ret = g_dbus_proxy_call_finish(proxy, res, &error);

    if (error) {
        /* ignore "already started" or "not running" errors */
        if (safe_str_eq(op->action, "start")
            && strstr(error->message, BUS_MANAGER_IFACE ".Error.AlreadyStarted")) {
            crm_trace("Masking Start failure for %s: already started", op->rsc);
            op->rc = PCMK_EXECRA_OK;

        } else if (safe_str_eq(op->action, "stop")
                   && strstr(error->message, BUS_MANAGER_IFACE ".Error.UnknownInstance")) {
            crm_trace("Masking Stop failure for %s: unknown services are stopped", op->rsc);
            op->rc = PCMK_EXECRA_OK;
        } else {
            crm_err("Could not issue %s for %s: %s", op->action, op->rsc, error->message);
        }
        g_error_free(error);

    } else {
        char *path = NULL;

        g_variant_get(_ret, "(o)", &path);
        crm_info("Call to %s passed: type '%s' %s", op->action, g_variant_get_type_string(_ret),
                 path);
        op->rc = PCMK_EXECRA_OK;
    }

    operation_finalize(op);
    g_object_unref(proxy);
    if (_ret) {
        g_variant_unref(_ret);
    }
}

gboolean
upstart_job_exec(svc_action_t * op, gboolean synchronous)
{
    char *job = NULL;
    GError *error = NULL;
    gboolean pass = FALSE;
    gchar *no_args[] = { NULL };
    const char *action = op->action;

    GVariant *_ret = NULL;
    GDBusProxy *job_proxy = NULL;

    op->rc = PCMK_EXECRA_UNKNOWN_ERROR;
    CRM_ASSERT(upstart_init());

    if (safe_str_eq(op->action, "meta-data")) {
        op->stdout_data = upstart_job_metadata(op->agent);
        op->rc = PCMK_EXECRA_OK;
        goto cleanup;
    }

    pass = upstart_job_by_name(upstart_proxy, op->agent, &job, NULL, &error);
    if (error) {
        crm_debug("Could not obtain job named '%s': %s", op->agent, error->message);
        pass = FALSE;
    }
    if (pass == FALSE) {
        if (!g_strcmp0(action, "stop")) {
            op->rc = PCMK_EXECRA_OK;
        } else {
            op->rc = PCMK_EXECRA_NOT_INSTALLED;
        }
        goto cleanup;
    }

    if (safe_str_eq(op->action, "monitor") || safe_str_eq(action, "status")) {
        if (upstart_job_running(op->agent)) {
            op->rc = PCMK_EXECRA_OK;
        } else {
            op->rc = PCMK_EXECRA_NOT_RUNNING;
        }
        goto cleanup;

    } else if (!g_strcmp0(action, "start")) {
        action = "Start";
    } else if (!g_strcmp0(action, "stop")) {
        action = "Stop";
    } else if (!g_strcmp0(action, "restart")) {
        action = "Restart";
    } else {
        op->rc = PCMK_EXECRA_UNIMPLEMENT_FEATURE;
        goto cleanup;
    }

    job_proxy = get_proxy(job, BUS_MANAGER_IFACE ".Job");

    crm_debug("Calling %s for %s: %s", action, op->rsc, job);
    if (synchronous == FALSE) {
        g_dbus_proxy_call(job_proxy, action, g_variant_new("(^asb)", no_args, TRUE),
                          G_DBUS_CALL_FLAGS_NONE, op->timeout, NULL, upstart_job_exec_done, op);
        free(job);
        return TRUE;
    }

    _ret = g_dbus_proxy_call_sync(job_proxy, action, g_variant_new("(^asb)", no_args, TRUE),
                                  G_DBUS_CALL_FLAGS_NONE, op->timeout, NULL, &error);

    if (error) {
        /* ignore "already started" or "not running" errors */
        if (safe_str_eq(action, "Start")
            && strstr(error->message, BUS_MANAGER_IFACE ".Error.AlreadyStarted")) {
            crm_trace("Masking Start failure for %s: already started", op->rsc);
            op->rc = PCMK_EXECRA_OK;
        } else if (safe_str_eq(action, "Stop")
                   && strstr(error->message, BUS_MANAGER_IFACE ".Error.UnknownInstance")) {
            crm_trace("Masking Stop failure for %s: unknown services are stopped", op->rsc);
            op->rc = PCMK_EXECRA_OK;
        } else {
            crm_err("Could not issue %s for %s: %s (%s)", action, op->rsc, error->message, job);
        }

    } else {
        char *path = NULL;

        g_variant_get(_ret, "(o)", &path);
        crm_info("Call to %s passed: type '%s' %s", action, g_variant_get_type_string(_ret), path);
        op->rc = PCMK_EXECRA_OK;
    }

  cleanup:
    free(job);
    if (error) {
        g_error_free(error);
    }
    if (job_proxy) {
        g_object_unref(job_proxy);
    }
    if (_ret) {
        g_variant_unref(_ret);
    }
    if (synchronous == FALSE) {
        operation_finalize(op);
        return TRUE;
    }
    return op->rc == PCMK_EXECRA_OK;
}
