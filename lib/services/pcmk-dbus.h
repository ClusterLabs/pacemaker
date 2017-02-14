/*
 * Copyright (C) 2014-2016 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef PCMKINT_CRMSERVICE_PCMK_DBUS__H
#  define PCMKINT_CRMSERVICE_PCMK_DBUS__H

#  include <dbus/dbus.h>

#  ifndef DBUS_TIMEOUT_USE_DEFAULT
#    define DBUS_TIMEOUT_USE_DEFAULT -1
#  endif

G_GNUC_INTERNAL
DBusConnection *pcmk_dbus_connect(void);

G_GNUC_INTERNAL
void pcmk_dbus_connection_setup_with_select(DBusConnection *c);

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
bool pcmk_dbus_find_error(DBusPendingCall *pending, DBusMessage *reply,
                          DBusError *error);

#endif  /* PCMKINT_CRMSERVICE_PCMK_DBUS__H */
