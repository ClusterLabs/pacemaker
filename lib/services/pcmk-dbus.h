DBusConnection *pcmk_dbus_connect(void);
void pcmk_dbus_disconnect(DBusConnection *connection);

DBusMessage *pcmk_dbus_send_recv(DBusMessage *msg, DBusConnection *connection, char **error);
bool pcmk_dbus_append_arg(DBusMessage *msg, int dtype, const void *value);
bool pcmk_dbus_type_check(DBusMessage *msg, DBusMessageIter *field, int expected, const char *function, int line);
char *pcmk_dbus_get_property(DBusConnection *connection, const char *target, const char *obj, const gchar * iface, const char *name);
