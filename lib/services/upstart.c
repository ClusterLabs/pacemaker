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

#include "upstart-dbus.h"

#include <glib.h>
#include <dbus/dbus-glib.h>

#include <dbus/dbus.h>

#include "dbus/Upstart.h"
#include "dbus/Upstart_Job.h"
#include "dbus/Upstart_Instance.h"

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

static DBusGConnection *
get_connection(void)
{
	GError *error = NULL;
	DBusGConnection *conn;

	conn = dbus_g_bus_get_private(DBUS_BUS_SYSTEM, NULL, &error);

	if (error)
	{
		g_error_free(error);
		error = NULL;

		conn = dbus_g_connection_open("unix:abstract=/com/ubuntu/upstart",
			&error);

		if (error)
		{
			g_warning("Can't connect to either system or Upstart "
				"DBus bus.");
			g_error_free(error);

			return NULL;
		}
	}

	return conn;
}

static DBusGProxy *
new_proxy(DBusGConnection *conn, const gchar *object_path,
	const gchar *iface)
{
	return dbus_g_proxy_new_for_name(conn,
		UPSTART_SERVICE_NAME,
		object_path,
		iface);
}

static GHashTable *
get_object_properties(DBusGProxy *obj, const gchar *iface)
{
	GError *error = NULL;
	DBusGProxy *proxy;
	GHashTable *asv;
	GHashTable *retval;
	GHashTableIter iter;
	gpointer k, v;

	proxy = dbus_g_proxy_new_from_proxy(obj,
		DBUS_INTERFACE_PROPERTIES, NULL);

	dbus_g_proxy_call(proxy, "GetAll", &error, G_TYPE_STRING,
		iface, G_TYPE_INVALID,
		dbus_g_type_get_map("GHashTable",
			G_TYPE_STRING,
			G_TYPE_VALUE),
		&asv, G_TYPE_INVALID);

	if (error) {
		g_warning("Error getting %s properties: %s", iface, error->message);
		g_error_free(error);
		g_object_unref(proxy);
		return NULL;
	}

	retval = g_hash_table_new_full(g_str_hash, g_str_equal,
		g_free, g_free);

	g_hash_table_iter_init(&iter, asv);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		gchar *key = k;
		GValue *val = v;

		/* all known properties are strings */
		if (G_VALUE_TYPE(val) == G_TYPE_STRING) {
			g_hash_table_insert(retval, g_strdup(key),
				g_value_dup_string(val));
		}
	}

	g_hash_table_destroy(asv);

	return retval;
}

gchar **
upstart_get_all_jobs(void)
{
	DBusGConnection *conn;
	DBusGProxy *manager;
	GError *error = NULL;
	GPtrArray *array;
	gchar **retval = NULL;
	gint i, j;

	conn = get_connection();
	if (!conn)
		return NULL;

	manager = new_proxy(conn, UPSTART_MANAGER_PATH, UPSTART_IFACE);

	dbus_g_proxy_call(manager, "GetAllJobs", &error, G_TYPE_INVALID,
		dbus_g_type_get_collection("GPtrArray", DBUS_TYPE_G_OBJECT_PATH),
		&array, G_TYPE_INVALID);

	if (error)
	{
		g_warning("Can't call GetAllJobs: %s", error->message);
		g_error_free(error);
		g_object_unref(manager);
		dbus_g_connection_unref(conn);
		return NULL;
	}

	retval = g_new0(gchar *, array->len + 1);

	for (i = 0, j = 0; i < array->len; i++)
	{
		DBusGProxy *job;
		
		job = new_proxy(conn, g_ptr_array_index(array, i),
			UPSTART_JOB_IFACE);

		if (job) {
			GHashTable *props = get_object_properties(job,
				UPSTART_JOB_IFACE);

			if (props) {
				gchar *name = g_hash_table_lookup(props,
					"name");

				if (name)
					retval[j++] = g_strdup(name);

				g_hash_table_destroy(props);
			}

			g_object_unref(job);
		}
	}

	g_ptr_array_free(array, TRUE);

	g_object_unref(manager);
	dbus_g_connection_unref(conn);

	return retval;
}

static DBusGProxy *
upstart_get_job_by_name(DBusGConnection *conn, DBusGProxy *manager,
	const gchar *name)
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

	if (error)
	{
		g_warning("Can't call GetAllInstances: %s", error->message);
		g_error_free(error);
		return NULL;
	}

	retval = g_new0(gchar *, array->len + 1);

	for (i = 0; i < array->len; i++)
	{
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
			GHashTable *props = get_object_properties(instance,
				UPSTART_INSTANCE_IFACE);

			if (props) {
				const gchar *state = g_hash_table_lookup(props,
					"state");

				retval = !g_strcmp0(state, "running");

				g_hash_table_destroy(props);
			}
			
			g_object_unref(instance);
		}

		g_object_unref(job);
	}

	g_object_unref(manager);
	dbus_g_connection_unref(conn);

	return retval;
}

gboolean
upstart_job_do(const gchar *name, UpstartJobCommand cmd)
{
	DBusGConnection *conn;
	DBusGProxy *manager;
	DBusGProxy *job;
	gboolean retval;

	conn = get_connection();
	if (!conn)
		return FALSE;

	manager = new_proxy(conn, UPSTART_MANAGER_PATH, UPSTART_IFACE);

	job = upstart_get_job_by_name(conn, manager, name);
	if (job) {
		GError *error = NULL;
		const gchar *cmd_name = NULL;
		gchar *instance_path = NULL;
		gchar *no_args[] = { NULL };

		switch (cmd) {
		case UPSTART_JOB_START:
			cmd_name = "Start";
			dbus_g_proxy_call (job, cmd_name, &error,
				G_TYPE_STRV, no_args,
				G_TYPE_BOOLEAN, TRUE,
				G_TYPE_INVALID,
				DBUS_TYPE_G_OBJECT_PATH, &instance_path,
				G_TYPE_INVALID);
			g_free (instance_path);
			break;
		case UPSTART_JOB_STOP:
			cmd_name = "Stop";
			dbus_g_proxy_call(job, cmd_name, &error,
				G_TYPE_STRV, no_args,
				G_TYPE_BOOLEAN, TRUE,
				G_TYPE_INVALID,
				G_TYPE_INVALID);
			break;
		case UPSTART_JOB_RESTART:
			cmd_name = "Restart";
			dbus_g_proxy_call (job, cmd_name, &error,
				G_TYPE_STRV, no_args,
				G_TYPE_BOOLEAN, TRUE,
				G_TYPE_INVALID,
				DBUS_TYPE_G_OBJECT_PATH, &instance_path,
				G_TYPE_INVALID);
			g_free (instance_path);
			break;
		default:
			g_assert_not_reached();
		}

		if (error) {
			g_warning("Could not issue %s: %s", cmd_name,
				error->message);

			/* ignore "already started" or "not running" errors */
			if (dbus_g_error_has_name(error,
					UPSTART_ERROR_ALREADY_STARTED) ||
				dbus_g_error_has_name(error,
					UPSTART_ERROR_UNKNOWN_INSTANCE)) {
				retval = TRUE;
			} else {
				retval = FALSE;
			}
			g_error_free(error);
		} else {
			retval = TRUE;
		}

		g_object_unref(job);
	} else {
		retval = FALSE;
	}

	g_object_unref(manager);
	dbus_g_connection_unref(conn);
	return retval;
}


