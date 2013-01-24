/*
 * Copyright (c) 2012 David Vossel <dvossel@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef LRMD_PVT__H
#  define LRMD_PVT__H

#  include <glib.h>
#  include <crm/common/ipc.h>
#  include <crm/lrmd.h>
#  include <crm/stonith-ng.h>

#ifdef HAVE_GNUTLS_GNUTLS_H
#  undef KEYFILE
#  include <gnutls/gnutls.h>
#endif
GHashTable *rsc_list;

typedef struct lrmd_rsc_s {
    char *rsc_id;
    char *class;
    char *provider;
    char *type;

    int call_opts;

    /* NEVER dereference this pointer,
     * It simply exists as a switch to let us know
     * when the currently active operation has completed */
    void *active;

    /* Operations in this list
     * have not been executed yet. */
    GList *pending_ops;
    /* Operations in this list are recurring operations
     * that have been handed off from the pending ops list. */
    GList *recurring_ops;

    int stonith_started;

    crm_trigger_t *work;
} lrmd_rsc_t;

#ifdef HAVE_GNUTLS_GNUTLS_H
/* in remote_tls.c */
int lrmd_init_remote_tls_server(int port);
void lrmd_tls_server_destroy(void);

/* Hidden in lrmd client lib */
extern int lrmd_tls_send_msg(crm_remote_t *session, xmlNode *msg, uint32_t id, const char *msg_type);
extern int lrmd_tls_set_key(gnutls_datum_t *key, const char *location);
#endif

int lrmd_server_send_reply(crm_client_t *client, uint32_t id, xmlNode *reply);

int lrmd_server_send_notify(crm_client_t *client, xmlNode *msg);

void process_lrmd_message(crm_client_t * client, uint32_t id, xmlNode * request);

void free_rsc(gpointer data);

void lrmd_shutdown(int nsig);

void client_disconnect_cleanup(const char *client_id);

/*!
 * \brief Don't worry about freeing this connection. It is 
 *        taken care of after mainloop exits by the main() function.
 */
stonith_t *get_stonith_connection(void);

/*!
 * \brief This is a callback that tells the lrmd
 * the current stonith connection has gone away. This allows
 * us to timeout any pending stonith commands
 */
void stonith_connection_failed(void);

#endif
