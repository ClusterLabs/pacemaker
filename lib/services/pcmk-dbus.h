DBusConnection *pcmk_dbus_connect(void);
void pcmk_dbus_connection_setup_with_select(DBusConnection *c);
void pcmk_dbus_disconnect(DBusConnection *connection);

bool pcmk_dbus_send(DBusMessage *msg, DBusConnection *connection,
                    void(*done)(DBusPendingCall *pending, void *user_data), void *user_data);
DBusMessage *pcmk_dbus_send_recv(DBusMessage *msg, DBusConnection *connection, DBusError *error);
bool pcmk_dbus_type_check(DBusMessage *msg, DBusMessageIter *field, int expected, const char *function, int line);
char *pcmk_dbus_get_property(DBusConnection *connection, const char *target, const char *obj, const gchar * iface, const char *name);

bool pcmk_dbus_find_error(const char *method, DBusPendingCall* pending, DBusMessage *reply, DBusError *error);

