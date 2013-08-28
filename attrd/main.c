/* 
 * Copyright (C) 2013 Andrew Beekhof <andrew@beekhof.net>
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

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ipcs.h>
#include <crm/cluster/internal.h>
#include <crm/common/mainloop.h>

#include <crm/common/xml.h>

#include <crm/attrd.h>
#include <internal.h>

GMainLoop *mloop = NULL;
bool shutting_down = FALSE;
crm_cluster_t *cluster = NULL;

static void
attrd_shutdown(int nsig) {
    shutting_down = TRUE;
    crm_info("Shutting down");

    if (mloop != NULL && g_main_is_running(mloop)) {
        g_main_quit(mloop);
    } else {
        crm_exit(pcmk_ok);
    }
}

static void
attrd_cpg_dispatch(cpg_handle_t handle,
                 const struct cpg_name *groupName,
                 uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    uint32_t kind = 0;
    xmlNode *xml = NULL;
    const char *from = NULL;
    char *data = pcmk_message_common_cs(handle, nodeid, pid, msg, &kind, &from);

    if(data == NULL) {
        return;
    }

    if (kind == crm_class_cluster) {
        xml = string2xml(data);
    }

    if (xml == NULL) {
        crm_err("Bad message of class %d received from %s[%u]: '%.120s'", kind, from, nodeid, data);
    } else {
        crm_node_t *peer = crm_get_peer(nodeid, from);

        attrd_peer_message(peer, xml);
    }

    free_xml(xml);
    free(data);
}

static void
attrd_cpg_destroy(gpointer unused)
{
    if (shutting_down) {
        crm_info("Corosync disconnection complete");

    } else {
        crm_crit("Lost connection to Corosync service!");
        attrd_shutdown(0);
    }
}

static void
attrd_cpg_membership(cpg_handle_t handle,
                    const struct cpg_name *groupName,
                    const struct cpg_address *member_list, size_t member_list_entries,
                    const struct cpg_address *left_list, size_t left_list_entries,
                    const struct cpg_address *joined_list, size_t joined_list_entries)
{
    pcmk_cpg_membership(handle, groupName,
                        member_list, member_list_entries,
                        left_list, left_list_entries,
                        joined_list, joined_list_entries);
    attrd_peer_change_cb();
}


static int32_t
attrd_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    crm_trace("Connection %p", c);
    if (shutting_down) {
        crm_info("Ignoring new client [%d] during shutdown", crm_ipcs_client_pid(c));
        return -EPERM;
    }

    if (crm_client_new(c, uid, gid) == NULL) {
        return -EIO;
    }
    return 0;
}

static void
attrd_ipc_created(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p", c);
}

static int32_t
attrd_ipc_dispatch(qb_ipcs_connection_t * c, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    crm_client_t *client = crm_client_get(c);
    xmlNode *xml = crm_ipcs_recv(client, data, size, &id, &flags);

    if (flags & crm_ipc_client_response) {
        crm_trace("Ack'ing msg from %d (%p)", crm_ipcs_client_pid(c), c);
        crm_ipcs_send_ack(client, id, "ack", __FUNCTION__, __LINE__);
    }

    if (xml == NULL) {
        crm_debug("No msg from %d (%p)", crm_ipcs_client_pid(c), c);
        return 0;
    }
#if ENABLE_ACL
    determine_request_user(client->user, xml, F_ATTRD_USER);
#endif

    crm_trace("Processing msg from %d (%p)", crm_ipcs_client_pid(c), c);
    crm_log_xml_trace(xml, __PRETTY_FUNCTION__);

    attrd_client_message(client, xml);

    free_xml(xml);
    return 0;
}

/* Error code means? */
static int32_t
attrd_ipc_closed(qb_ipcs_connection_t * c)
{
    crm_client_t *client = crm_client_get(c);

    crm_trace("Connection %p", c);
    crm_client_destroy(client);
    return 0;
}

static void
attrd_ipc_destroy(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p", c);
}

struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = attrd_ipc_accept,
    .connection_created = attrd_ipc_created,
    .msg_process = attrd_ipc_dispatch,
    .connection_closed = attrd_ipc_closed,
    .connection_destroyed = attrd_ipc_destroy
};

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0, '?', "\tThis text"},
    {"verbose", 0, 0, 'V', "\tIncrease debug output"},

    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int
main(int argc, char **argv)
{
    int flag = 0;
    int index = 0;
    int argerr = 0;
    qb_ipcs_service_t *ipcs = NULL;

    mloop = g_main_new(FALSE);
    crm_log_init(T_ATTRD, LOG_NOTICE, TRUE, FALSE, argc, argv, FALSE);
    crm_set_options(NULL, "[options]", long_options,
                    "Daemon for aggregating and atomically storing node attribute updates into the CIB");

    mainloop_add_signal(SIGTERM, attrd_shutdown);

     while (1) {
        flag = crm_get_option(argc, argv, &index);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case 'h':          /* Help message */
                crm_help(flag, EX_OK);
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', EX_USAGE);
    }

    crm_info("Starting up");
    attributes = g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, free_attribute);
    cluster = malloc(sizeof(crm_cluster_t));

    cluster->destroy = attrd_cpg_destroy;
    cluster->cpg.cpg_deliver_fn = attrd_cpg_dispatch;
    cluster->cpg.cpg_confchg_fn = attrd_cpg_membership;

    if (crm_cluster_connect(cluster) == FALSE) {
        crm_err("Cluster connection failed");
        goto done;
    }

    crm_info("Cluster connection active");
    attrd_ipc_server_init(&ipcs, &ipc_callbacks);

    crm_info("Accepting attribute updates");
    g_main_run(mloop);

  done:
    crm_notice("Cleaning up before exit");

    crm_client_disconnect_all(ipcs);
    qb_ipcs_destroy(ipcs);
    g_hash_table_destroy(attributes);

    return crm_exit(pcmk_ok);
}
