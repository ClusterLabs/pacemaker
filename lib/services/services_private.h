/*
 * Copyright 2010-2011 Red Hat, Inc.
 * Later changes copyright 2012-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef SERVICES_PRIVATE__H
#  define SERVICES_PRIVATE__H

#  include <glib.h>
#  include "crm/services.h"

#if HAVE_DBUS
#  include <dbus/dbus.h>
#endif

#define MAX_ARGC        255
struct svc_action_private_s {
    char *exec;
    char *exit_reason;
    char *args[MAX_ARGC];

    uid_t uid;
    gid_t gid;

    guint repeat_timer;
    void (*callback) (svc_action_t * op);
    void (*fork_callback) (svc_action_t * op);

    int stderr_fd;
    mainloop_io_t *stderr_gsource;

    int stdout_fd;
    mainloop_io_t *stdout_gsource;

    int stdin_fd;
#if HAVE_DBUS
    DBusPendingCall* pending;
    unsigned timerid;
#endif
};

G_GNUC_INTERNAL
const char *services__action_kind(const svc_action_t *action);

G_GNUC_INTERNAL
GList *services_os_get_single_directory_list(const char *root, gboolean files,
                                             gboolean executable);

G_GNUC_INTERNAL
GList *services_os_get_directory_list(const char *root, gboolean files, gboolean executable);

G_GNUC_INTERNAL
int services__execute_file(svc_action_t *op);

G_GNUC_INTERNAL
gboolean cancel_recurring_action(svc_action_t * op);

G_GNUC_INTERNAL
gboolean recurring_action_timer(gpointer data);

G_GNUC_INTERNAL
int services__finalize_async_op(svc_action_t *op);

G_GNUC_INTERNAL
int services__generic_error(const svc_action_t *op);

G_GNUC_INTERNAL
int services__not_installed_error(const svc_action_t *op);

G_GNUC_INTERNAL
int services__authorization_error(const svc_action_t *op);

G_GNUC_INTERNAL
int services__configuration_error(const svc_action_t *op, bool is_fatal);

G_GNUC_INTERNAL
void services__handle_exec_error(svc_action_t * op, int error);

G_GNUC_INTERNAL
void services__set_cancelled(svc_action_t *action);

G_GNUC_INTERNAL
void services_add_inflight_op(svc_action_t *op);

G_GNUC_INTERNAL
void services_untrack_op(const svc_action_t *op);

G_GNUC_INTERNAL
gboolean is_op_blocked(const char *rsc);

#if HAVE_DBUS
G_GNUC_INTERNAL
void services_set_op_pending(svc_action_t *op, DBusPendingCall *pending);
#endif

#endif  /* SERVICES_PRIVATE__H */
