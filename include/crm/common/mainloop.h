/*
 * Copyright (C) 2009 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CRM_COMMON_MAINLOOP__H
#  define CRM_COMMON_MAINLOOP__H

/**
 * \file
 * \brief Wrappers for and extensions to glib mainloop
 * \ingroup core
 */

#  include <glib.h>

typedef struct trigger_s crm_trigger_t;
typedef struct mainloop_io_s mainloop_io_t;
typedef struct mainloop_child_s mainloop_child_t;

crm_trigger_t *mainloop_add_trigger(int priority, int(*dispatch) (gpointer user_data),
                                           gpointer userdata);

void mainloop_set_trigger(crm_trigger_t * source);

void mainloop_trigger_complete(crm_trigger_t *trig);

gboolean mainloop_destroy_trigger(crm_trigger_t * source);

gboolean crm_signal(int sig, void (*dispatch) (int sig));

gboolean mainloop_add_signal(int sig, void (*dispatch) (int sig));

gboolean mainloop_destroy_signal(int sig);

#include <crm/common/ipc.h>
#include <qb/qbipcs.h>

struct ipc_client_callbacks
{
        int (*dispatch)(const char *buffer, ssize_t length, gpointer userdata);
        void (*destroy) (gpointer);
};

qb_ipcs_service_t *mainloop_add_ipc_server(
    const char *name, enum qb_ipc_type type, struct qb_ipcs_service_handlers *callbacks);

void mainloop_del_ipc_server(qb_ipcs_service_t *server);

mainloop_io_t *mainloop_add_ipc_client(
    const char *name, int priority, size_t max_size, void *userdata, struct ipc_client_callbacks *callbacks);

void mainloop_del_ipc_client(mainloop_io_t *client);

crm_ipc_t *mainloop_get_ipc_client(mainloop_io_t *client);


struct mainloop_fd_callbacks
{
        int (*dispatch)(gpointer userdata);
        void (*destroy)(gpointer userdata);
};

mainloop_io_t *mainloop_add_fd(
    const char *name, int priority, int fd, void *userdata, struct mainloop_fd_callbacks *callbacks);

void mainloop_del_fd(mainloop_io_t *client);

/*
 * Create a new tracked process
 * To track a process group, use -pid
 */
void
mainloop_add_child(pid_t pid,
    int timeout,
    const char *desc,
    void *userdata,
    void (*callback)(mainloop_child_t* p,
    int status,
    int signo,
    int exitcode));

void *
mainloop_get_child_userdata(mainloop_child_t *child);
int
mainloop_get_child_timeout(mainloop_child_t *child);
pid_t
mainloop_get_child_pid(mainloop_child_t *child);
void
mainloop_clear_child_userdata(mainloop_child_t *child);

#define G_PRIORITY_MEDIUM (G_PRIORITY_HIGH/2)

#endif
