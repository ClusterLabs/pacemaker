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
#include <crm/pengine/rules.h>
#include <crm/common/iso8601.h>
#include <crm/common/ipc.h>
#include <crm/common/ipcs.h>
#include <crm/cluster/internal.h>
#include <crm/cluster/election.h>

#include <crm/common/xml.h>

#include <crm/attrd.h>
#include <internal.h>

lrmd_t *the_lrmd = NULL;
crm_cluster_t *attrd_cluster = NULL;
election_t *writer = NULL;
crm_trigger_t *attrd_config_read = NULL;
static int attrd_exit_status = pcmk_ok;

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
    if (attrd_shutting_down()) {
        crm_info("Corosync disconnection complete");

    } else {
        crm_crit("Lost connection to Corosync service!");
        attrd_exit_status = ECONNRESET;
        attrd_shutdown(0);
    }
}

static void
attrd_cib_replaced_cb(const char *event, xmlNode * msg)
{
    crm_notice("Updating all attributes after %s event", event);
    if(election_state(writer) == election_won) {
        write_attributes(TRUE);
    }
}

static void
attrd_cib_destroy_cb(gpointer user_data)
{
    cib_t *conn = user_data;

    conn->cmds->signoff(conn);  /* Ensure IPC is cleaned up */

    if (attrd_shutting_down()) {
        crm_info("Connection disconnection complete");

    } else {
        /* eventually this should trigger a reconnect, not a shutdown */
        crm_err("Lost connection to CIB service!");
        attrd_exit_status = ECONNRESET;
        attrd_shutdown(0);
    }

    return;
}

static void
attrd_erase_cb(xmlNode *msg, int call_id, int rc, xmlNode *output,
               void *user_data)
{
    do_crm_log_unlikely((rc? LOG_NOTICE : LOG_DEBUG),
                        "Cleared transient attributes: %s "
                        CRM_XS " xpath=%s rc=%d",
                        pcmk_strerror(rc), (char *) user_data, rc);
}

#define XPATH_TRANSIENT "//node_state[@uname='%s']/" XML_TAG_TRANSIENT_NODEATTRS

/*!
 * \internal
 * \brief Wipe all transient attributes for this node from the CIB
 *
 * Clear any previous transient node attributes from the CIB. This is
 * normally done by the DC's crmd when this node leaves the cluster, but
 * this handles the case where the node restarted so quickly that the
 * cluster layer didn't notice.
 *
 * \todo If attrd respawns after crashing (see PCMK_respawned), ideally we'd
 *       skip this and sync our attributes from the writer. However, currently
 *       we reject any values for us that the writer has, in
 *       attrd_peer_update().
 */
static void
attrd_erase_attrs()
{
    int call_id;
    char *xpath = crm_strdup_printf(XPATH_TRANSIENT, attrd_cluster->uname);

    crm_info("Clearing transient attributes from CIB " CRM_XS " xpath=%s",
             xpath);

    call_id = the_cib->cmds->delete(the_cib, xpath, NULL,
                                    cib_quorum_override | cib_xpath);
    the_cib->cmds->register_callback_full(the_cib, call_id, 120, FALSE, xpath,
                                          "attrd_erase_cb", attrd_erase_cb,
                                          free);
}

static int
attrd_cib_connect(int max_retry)
{
    static int attempts = 0;

    int rc = -ENOTCONN;

    the_cib = cib_new();
    if (the_cib == NULL) {
        return DAEMON_RESPAWN_STOP;
    }

    do {
        if(attempts > 0) {
            sleep(attempts);
        }

        attempts++;
        crm_debug("CIB signon attempt %d", attempts);
        rc = the_cib->cmds->signon(the_cib, T_ATTRD, cib_command);

    } while(rc != pcmk_ok && attempts < max_retry);

    if (rc != pcmk_ok) {
        crm_err("Signon to CIB failed: %s (%d)", pcmk_strerror(rc), rc);
        goto cleanup;
    }

    crm_debug("Connected to the CIB after %d attempts", attempts);

    rc = the_cib->cmds->set_connection_dnotify(the_cib, attrd_cib_destroy_cb);
    if (rc != pcmk_ok) {
        crm_err("Could not set disconnection callback");
        goto cleanup;
    }

    rc = the_cib->cmds->add_notify_callback(the_cib, T_CIB_REPLACE_NOTIFY, attrd_cib_replaced_cb);
    if(rc != pcmk_ok) {
        crm_err("Could not set CIB notification callback");
        goto cleanup;
    }

    rc = the_cib->cmds->add_notify_callback(the_cib, T_CIB_DIFF_NOTIFY, attrd_cib_updated_cb);
    if (rc != pcmk_ok) {
        crm_err("Could not set CIB notification callback (update)");
        goto cleanup;
    }

    // We have no attribute values in memory, wipe the CIB to match
    attrd_erase_attrs();

    // Set a trigger for reading the CIB (for the alerts section)
    attrd_config_read = mainloop_add_trigger(G_PRIORITY_HIGH, attrd_read_options, NULL);

    // Always read the CIB at start-up
    mainloop_set_trigger(attrd_config_read);

    /* Set a private attribute for ourselves with the protocol version we
     * support. This lets all nodes determine the minimum supported version
     * across all nodes. It also ensures that the writer learns our node name,
     * so it can send our attributes to the CIB.
     */
    attrd_broadcast_protocol();

    return pcmk_ok;

  cleanup:
    the_cib->cmds->signoff(the_cib);
    cib_delete(the_cib);
    the_cib = NULL;
    return DAEMON_RESPAWN_STOP;
}

static int32_t
attrd_ipc_dispatch(qb_ipcs_connection_t * c, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    crm_client_t *client = crm_client_get(c);
    xmlNode *xml = crm_ipcs_recv(client, data, size, &id, &flags);
    const char *op;

    if (xml == NULL) {
        crm_debug("No msg from %d (%p)", crm_ipcs_client_pid(c), c);
        return 0;
    }
#if ENABLE_ACL
    CRM_ASSERT(client->user != NULL);
    crm_acl_get_set_user(xml, F_ATTRD_USER, client->user);
#endif

    crm_trace("Processing msg from %d (%p)", crm_ipcs_client_pid(c), c);
    crm_log_xml_trace(xml, __FUNCTION__);

    op = crm_element_value(xml, F_ATTRD_TASK);

    if (client->name == NULL) {
        const char *value = crm_element_value(xml, F_ORIG);
        client->name = crm_strdup_printf("%s.%d", value?value:"unknown", client->pid);
    }

    if (safe_str_eq(op, ATTRD_OP_PEER_REMOVE)) {
        attrd_send_ack(client, id, flags);
        attrd_client_peer_remove(client->name, xml);

    } else if (safe_str_eq(op, ATTRD_OP_CLEAR_FAILURE)) {
        attrd_send_ack(client, id, flags);
        attrd_client_clear_failure(xml);

    } else if (safe_str_eq(op, ATTRD_OP_UPDATE)) {
        attrd_send_ack(client, id, flags);
        attrd_client_update(xml);

    } else if (safe_str_eq(op, ATTRD_OP_UPDATE_BOTH)) {
        attrd_send_ack(client, id, flags);
        attrd_client_update(xml);

    } else if (safe_str_eq(op, ATTRD_OP_UPDATE_DELAY)) {
        attrd_send_ack(client, id, flags);
        attrd_client_update(xml);
  
    } else if (safe_str_eq(op, ATTRD_OP_REFRESH)) {
        attrd_send_ack(client, id, flags);
        attrd_client_refresh();

    } else if (safe_str_eq(op, ATTRD_OP_QUERY)) {
        /* queries will get reply, so no ack is necessary */
        attrd_client_query(client, id, flags, xml);

    } else {
        crm_info("Ignoring request from client %s with unknown operation %s",
                 client->name, op);
    }

    free_xml(xml);
    return 0;
}

static int
attrd_cluster_connect()
{
    attrd_cluster = calloc(1, sizeof(crm_cluster_t));

    attrd_cluster->destroy = attrd_cpg_destroy;
    attrd_cluster->cpg.cpg_deliver_fn = attrd_cpg_dispatch;
    attrd_cluster->cpg.cpg_confchg_fn = pcmk_cpg_membership;

    crm_set_status_callback(&attrd_peer_change_cb);

    if (crm_cluster_connect(attrd_cluster) == FALSE) {
        crm_err("Cluster connection failed");
        return DAEMON_RESPAWN_STOP;
    }
    return pcmk_ok;
}

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

    attrd_init_mainloop();
    crm_log_preinit(NULL, argc, argv);
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

    crm_log_init(T_ATTRD, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    crm_info("Starting up");
    attributes = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, free_attribute);

    attrd_exit_status = attrd_cluster_connect();
    if (attrd_exit_status != pcmk_ok) {
        goto done;
    }
    crm_info("Cluster connection active");

    attrd_exit_status = attrd_cib_connect(10);
    if (attrd_exit_status != pcmk_ok) {
        goto done;
    }
    crm_info("CIB connection active");

    writer = election_init(T_ATTRD, attrd_cluster->uname, 120000, attrd_election_cb);
    attrd_init_ipc(&ipcs, attrd_ipc_dispatch);
    crm_info("Accepting attribute updates");

    attrd_run_mainloop();

  done:
    crm_info("Shutting down attribute manager");

    election_fini(writer);
    if (ipcs) {
        crm_client_disconnect_all(ipcs);
        qb_ipcs_destroy(ipcs);
        g_hash_table_destroy(attributes);
    }

    attrd_lrmd_disconnect();
    attrd_cib_disconnect();

    return crm_exit(attrd_exit_status);
}
