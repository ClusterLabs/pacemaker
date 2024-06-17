/*
 * Copyright 2014-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__SERVICES_PCMK_DBUS__H
#define PCMK__SERVICES_PCMK_DBUS__H

#include <stdbool.h>    // bool

#include <dbus/dbus.h>  // DBUS_TIMEOUT_USE_DEFAULT, DBusConnection, etc.
#include <glib.h>       // G_GNUC_INTERNAL, gchar

#ifndef DBUS_TIMEOUT_USE_DEFAULT
#define DBUS_TIMEOUT_USE_DEFAULT -1
#endif

#ifdef __cplusplus
extern "C" {
#endif

G_GNUC_INTERNAL
DBusConnection *pcmk_dbus_connect(void);

G_GNUC_INTERNAL
void pcmk_dbus_disconnect(DBusConnection *connection);

G_GNUC_INTERNAL
DBusPendingCall *pcmk_dbus_send(DBusMessage *msg, DBusConnection *connection,
                    void(*done)(DBusPendingCall *pending, void *user_data), void *user_data, int timeout);

G_GNUC_INTERNAL
DBusMessage *pcmk_dbus_send_recv(DBusMessage *msg, DBusConnection *connection, DBusError *error, int timeout);

G_GNUC_INTERNAL
bool pcmk_dbus_type_check(DBusMessage *msg, DBusMessageIter *field, int expected, const char *function, int line);

G_GNUC_INTERNAL
char *pcmk_dbus_get_property(
    DBusConnection *connection, const char *target, const char *obj, const gchar * iface, const char *name,
    void (*callback)(const char *name, const char *value, void *userdata), void *userdata,
    DBusPendingCall **pending, int timeout);

G_GNUC_INTERNAL
bool pcmk_dbus_find_error(const DBusPendingCall *pending, DBusMessage *reply,
                          DBusError *error);

#ifdef __cplusplus
}
#endif

#endif // PCMK__SERVICES_PCMK_DBUS__H
