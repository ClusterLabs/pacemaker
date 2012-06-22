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
#include <crm/crm.h>
#include <upstart.h>

#include <glib.h>
#include <dbus/dbus-glib.h>

/* #include "dbus/Upstart.h" */
/* #include "dbus/Upstart_Job.h" */
/* #include "dbus/Upstart_Instance.h" */

#include <stdio.h>

#define SYSTEM_BUS_ADDRESS "unix:path=/var/run/dbus/system_bus_socket"
#define UPSTART_BUS_ADDRESS "unix:abstract=/com/ubuntu/upstart"
#define UPSTART_SERVICE_NAME "com.ubuntu.Upstart"
#define UPSTART_MANAGER_PATH "/com/ubuntu/Upstart"
#define UPSTART_IFACE "com.ubuntu.Upstart0_6"
#define UPSTART_JOB_IFACE UPSTART_IFACE ".Job"
#define UPSTART_INSTANCE_IFACE UPSTART_IFACE ".Instance"
#define UPSTART_ERROR_ALREADY_STARTED UPSTART_IFACE ".Error.AlreadyStarted"
#define UPSTART_ERROR_UNKNOWN_INSTANCE UPSTART_IFACE ".Error.UnknownInstance"

static DBusGConnection *upstart_conn = NULL;

static DBusGConnection *
get_connection(void)
{
    GError *error = NULL;
    if(upstart_conn) {
        return upstart_conn;
    }
    
    upstart_conn = dbus_g_bus_get_private(DBUS_BUS_SYSTEM, NULL, &error);
    if (error) {
        g_error_free(error);
        error = NULL;

        upstart_conn = dbus_g_connection_open(UPSTART_BUS_ADDRESS, &error);

        if (error) {
            crm_err("Can't connect to either system or Upstart DBus bus.");
            g_error_free(error);
            upstart_conn = NULL;
        }
    }

    return upstart_conn;
}

static DBusGProxy *
new_proxy(DBusGConnection *conn, const gchar *object_path, const gchar *iface)
{
    return dbus_g_proxy_new_for_name(conn,
                                     UPSTART_SERVICE_NAME,
                                     object_path,
                                     iface);
}

static char *
get_object_property(DBusGProxy *obj, const gchar *iface, const char *name)
{
    GError *error = NULL;
    DBusGProxy *proxy;
    GHashTable *asv;
    GValue *value;

    proxy = dbus_g_proxy_new_from_proxy(obj, DBUS_INTERFACE_PROPERTIES, NULL);

    dbus_g_proxy_call(proxy, "GetAll", &error, G_TYPE_STRING,
                      iface, G_TYPE_INVALID,
                      dbus_g_type_get_map("GHashTable",
                                          G_TYPE_STRING,
                                          G_TYPE_VALUE),
                      &asv, G_TYPE_INVALID);

    if (error) {
        crm_err("Cannot get properties for %s: %s", iface, error->message);
        g_error_free(error);
        g_object_unref(proxy);
        return NULL;
    }

    value = g_hash_table_lookup(asv, name);
    if(value && G_VALUE_TYPE(value) == G_TYPE_STRING) {
        return g_value_dup_string(value);
    }
    g_hash_table_destroy(asv);
    return NULL;
}

GList *
upstart_get_all_jobs(void)
{
    DBusGConnection *conn;
    DBusGProxy *manager;
    GError *error = NULL;
    GPtrArray *array;
    GList *list = NULL;
    gint i, j;

    conn = get_connection();
    if (!conn)
        return NULL;

    manager = new_proxy(conn, UPSTART_MANAGER_PATH, UPSTART_IFACE);

    dbus_g_proxy_call(manager, "GetAllJobs", &error,
                      G_TYPE_INVALID,
                      dbus_g_type_get_collection("GPtrArray", DBUS_TYPE_G_OBJECT_PATH), &array,
                      G_TYPE_INVALID);

    if (error) {
        crm_err("Can't call GetAllJobs: %s", error->message);
        g_error_free(error);
        g_object_unref(manager);
        return NULL;
    }

    for (i = 0, j = 0; i < array->len; i++) {
        DBusGProxy *job = new_proxy(conn, g_ptr_array_index(array, i),
                                    UPSTART_JOB_IFACE);

        if (job) {
            char *name = get_object_property(job, UPSTART_JOB_IFACE, "name");
            if (name) {
                list = g_list_append(list, name);
            }

            g_object_unref(job);
        }
    }

    g_ptr_array_free(array, TRUE);
    g_object_unref(manager);
    return list;
}

static DBusGProxy *
upstart_get_job_by_name(DBusGConnection *conn, DBusGProxy *manager, const gchar *name)
{
    GError *error = NULL;
    gchar *object_path;
    DBusGProxy *retval;

    dbus_g_proxy_call(manager, "GetJobByName", &error, G_TYPE_STRING,
                      name, G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH, &object_path,
                      G_TYPE_INVALID);

    if (error)
    {
        g_warning("Error calling GetJobByName: %s", error->message);
        g_error_free(error);
        return NULL;
    }

    retval = new_proxy(conn, object_path, UPSTART_JOB_IFACE);

    g_free(object_path);

    return retval;
}

static gchar **
get_job_instances(DBusGProxy *job)
{
    GError *error = NULL;
    GPtrArray *array;
    gchar **retval;
    gint i;

    dbus_g_proxy_call(job, "GetAllInstances", &error, G_TYPE_INVALID,
                      dbus_g_type_get_collection("GPtrArray", DBUS_TYPE_G_OBJECT_PATH),
                      &array, G_TYPE_INVALID);

    if (error) {
        crm_err("Can't call GetAllInstances: %s", error->message);
        g_error_free(error);
        return NULL;
    }

    retval = g_new0(gchar *, array->len + 1);
    for (i = 0; i < array->len; i++) {
        retval[i] = g_ptr_array_index(array, i);
    }
    g_ptr_array_free(array, TRUE);
    return retval;
}

static DBusGProxy *
get_first_instance(DBusGConnection *conn, DBusGProxy *job)
{
    gchar **instances;
    DBusGProxy *instance = NULL;

    instances = get_job_instances(job);

    if (!instances)
        return NULL;

    if (*instances)
    {
        instance = new_proxy(conn, instances[0],
                             UPSTART_INSTANCE_IFACE);
    }

    g_strfreev(instances);
    return instance;
}

gboolean
upstart_job_exists(const gchar *name)
{
    DBusGConnection *conn;
    DBusGProxy *manager;
    DBusGProxy *job;

    conn = get_connection();
    if (!conn)
        return FALSE;

    manager = new_proxy(conn, UPSTART_MANAGER_PATH, UPSTART_IFACE);

    job = upstart_get_job_by_name(conn, manager, name);
    if (job) {
        return TRUE;
    }

    g_object_unref(job);
    g_object_unref(manager);
    return FALSE;
}

gboolean
upstart_job_is_running(const gchar *name)
{
    DBusGConnection *conn;
    DBusGProxy *manager;
    DBusGProxy *job;
    gboolean retval = FALSE;

    conn = get_connection();
    if (!conn)
        return FALSE;

    manager = new_proxy(conn, UPSTART_MANAGER_PATH, UPSTART_IFACE);

    job = upstart_get_job_by_name(conn, manager, name);
    if (job) {
        DBusGProxy *instance = get_first_instance(conn, job);

        if (instance) {
            char *state = get_object_property(instance, UPSTART_INSTANCE_IFACE, "state");
            retval = !g_strcmp0(state, "running");
            free(state);

            g_object_unref(instance);
        }

        g_object_unref(job);
    }

    g_object_unref(manager);
    return retval;
}

static char *
upstart_job_metadata(const char *name) 
{
    return g_strdup_printf(
        "<?xml version=\"1.0\"?>\n"
        "<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"
        "<resource-agent name=\"%s\" version=\"0.1\">\n"
        "  <version>1.0</version>\n"
        "  <longdesc lang=\"en\">\n"
        "    Upstart agent for controlling the system %s service"
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
        "  </special>\n"
        "</resource-agent>\n",
        name, name, name);
}

gboolean
upstart_job_do(svc_action_t* op, gboolean synchronous)
{
    DBusGProxy *job;
    DBusGProxy *manager;
    DBusGConnection *conn = get_connection();


    GError *error = NULL;
    gchar *instance_path = NULL;
    gchar *no_args[] = { NULL };
    const char *action = op->action;

    op->rc = PCMK_EXECRA_UNKNOWN_ERROR;
    
    if (!conn)
        return FALSE;

    manager = new_proxy(conn, UPSTART_MANAGER_PATH, UPSTART_IFACE);

    job = upstart_get_job_by_name(conn, manager, op->rsc);
    if (job == NULL) {
        goto cleanup;
    }

    if (safe_str_eq(op->action, "meta-data")) {
        op->stdout_data = upstart_job_metadata(op->rsc);
        op->rc = PCMK_EXECRA_OK;
        goto cleanup;
    }

    if (safe_str_eq(op->action, "monitor") || safe_str_eq(action, "status")) {
        gboolean running = upstart_job_is_running (op->rsc);
        crm_trace("%s", running ? "running" : "stopped");
		
        if (running) {
            op->rc = PCMK_EXECRA_OK;
            goto cleanup;
        }
        op->rc = PCMK_EXECRA_NOT_RUNNING;
        goto cleanup;

    } else if (!g_strcmp0(action, "start")) {
        action = "Start";
    } else if (!g_strcmp0(action, "stop")) {
        action = "Stop";
    } else if (!g_strcmp0(action, "restart")) {
        action = "Restart";
    } else {
        return PCMK_EXECRA_UNIMPLEMENT_FEATURE;
    }

    dbus_g_proxy_call (job, action, &error,
                       G_TYPE_STRV, no_args,
                       G_TYPE_BOOLEAN, TRUE,
                       G_TYPE_INVALID,
                       DBUS_TYPE_G_OBJECT_PATH, &instance_path,
                       G_TYPE_INVALID);
    g_free (instance_path);
    
    if (error) {
        /* ignore "already started" or "not running" errors */
        if (safe_str_eq(action, "Start") && dbus_g_error_has_name(error, UPSTART_ERROR_ALREADY_STARTED)) {
            crm_trace("Masking Start failure for %s: already started", op->rsc);
            op->rc = PCMK_EXECRA_OK;
        } else if (safe_str_eq(action, "Start") && dbus_g_error_has_name(error, UPSTART_ERROR_UNKNOWN_INSTANCE)) {
            crm_trace("Masking Stop failure for %s: unknown services are stopped", op->rsc);
            op->rc = PCMK_EXECRA_OK;
        } else {
            crm_err("Could not issue %s for %s: %s", action, op->rsc, error->message);
        }
        g_error_free(error);
    }

  cleanup:
    if(job) {
        g_object_unref(job);
    }
    g_object_unref(manager);
    return op->rc == PCMK_EXECRA_OK;
}

void upstart_cleanup(void)
{
    dbus_g_connection_unref(upstart_conn);
    upstart_conn = NULL;
}


