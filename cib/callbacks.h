/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <glib.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/common/xml.h>
#include <crm/cluster.h>
#include <crm/common/ipcs.h>
#include <crm/common/mainloop.h>
#ifdef HAVE_GNUTLS_GNUTLS_H
#  undef KEYFILE
#  include <gnutls/gnutls.h>
#endif

extern gboolean cib_is_master;
extern GHashTable *peer_hash;
extern GHashTable *config_hash;

/* *INDENT-OFF* */
enum cib_notifications
{
    cib_notify_pre     = 0x0001,
    cib_notify_post    = 0x0002,
    cib_notify_replace = 0x0004,
    cib_notify_confirm = 0x0008,
    cib_notify_diff    = 0x0010,

    /* not a notification, but uses the same IPC bitmask */
    cib_is_daemon      = 0x1000, /* whether client is another cluster daemon */
};
/* *INDENT-ON* */

typedef struct cib_operation_s {
    const char *operation;
    gboolean modifies_cib;
    gboolean needs_privileges;
    gboolean needs_quorum;
    int (*prepare) (xmlNode *, xmlNode **, const char **);
    int (*cleanup) (int, xmlNode **, xmlNode **);
    int (*fn) (const char *, int, const char *, xmlNode *,
               xmlNode *, xmlNode *, xmlNode **, xmlNode **);
} cib_operation_t;

extern struct qb_ipcs_service_handlers ipc_ro_callbacks;
extern struct qb_ipcs_service_handlers ipc_rw_callbacks;
extern qb_ipcs_service_t *ipcs_ro;
extern qb_ipcs_service_t *ipcs_rw;
extern qb_ipcs_service_t *ipcs_shm;

extern void cib_peer_callback(xmlNode * msg, void *private_data);
extern void cib_client_status_callback(const char *node, const char *client,
                                       const char *status, void *private);
extern void cib_common_callback_worker(uint32_t id, uint32_t flags, xmlNode * op_request,
                                       crm_client_t * cib_client, gboolean privileged);

void cib_shutdown(int nsig);
void initiate_exit(void);
void terminate_cib(const char *caller, int fast);

extern gboolean cib_legacy_mode(void);

static inline const char *
cib_config_lookup(const char *opt)
{
    return g_hash_table_lookup(config_hash, opt);
}
