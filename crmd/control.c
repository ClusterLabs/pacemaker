/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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

#include <crm/crm.h>

#include <crm/msg_xml.h>

#include <crm/pengine/rules.h>
#include <crm/cluster/internal.h>

#include <crmd.h>
#include <crmd_fsa.h>
#include <fsa_proto.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>
#include <crmd_lrm.h>
#include <tengine.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <grp.h>

qb_ipcs_service_t *ipcs = NULL;

extern gboolean crm_connect_corosync(crm_cluster_t *cluster);
extern void crmd_ha_connection_destroy(gpointer user_data);

void crm_shutdown(int nsig);
gboolean crm_read_options(gpointer user_data);

gboolean fsa_has_quorum = FALSE;
GHashTable *ipc_clients = NULL;
crm_trigger_t *fsa_source = NULL;
crm_trigger_t *config_read = NULL;

/*	 A_HA_CONNECT	*/
void
do_ha_control(long long action,
              enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state,
              enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    gboolean registered = FALSE;
    static crm_cluster_t cluster;

    if (action & A_HA_DISCONNECT) {
        if (is_openais_cluster()) {
            crm_peer_destroy();
#if SUPPORT_COROSYNC
            terminate_cs_connection();
#endif
            crm_info("Disconnected from OpenAIS");

#if SUPPORT_HEARTBEAT
        } else if (fsa_cluster_conn != NULL) {
            set_bit(fsa_input_register, R_HA_DISCONNECTED);
            fsa_cluster_conn->llc_ops->signoff(fsa_cluster_conn, FALSE);
            crm_info("Disconnected from Heartbeat");
#endif
        }
    }

    if (action & A_HA_CONNECT) {
        crm_set_status_callback(&peer_update_callback);

        if (is_openais_cluster()) {
#if SUPPORT_COROSYNC
            registered = crm_connect_corosync(&cluster);
#endif
        } else if (is_heartbeat_cluster()) {
#if SUPPORT_HEARTBEAT
            cluster.destroy = crmd_ha_connection_destroy;
            cluster.hb_dispatch = crmd_ha_msg_callback;

            registered = crm_cluster_connect(&cluster);
            fsa_cluster_conn = cluster.hb_conn;

            crm_trace("Be informed of Node Status changes");
            if (registered &&
                fsa_cluster_conn->llc_ops->set_nstatus_callback(fsa_cluster_conn,
                                                                crmd_ha_status_callback,
                                                                fsa_cluster_conn) != HA_OK) {

                crm_err("Cannot set nstatus callback: %s",
                        fsa_cluster_conn->llc_ops->errmsg(fsa_cluster_conn));
                registered = FALSE;
            }

            crm_trace("Be informed of CRM Client Status changes");
            if (registered &&
                fsa_cluster_conn->llc_ops->set_cstatus_callback(fsa_cluster_conn,
                                                                crmd_client_status_callback,
                                                                fsa_cluster_conn) != HA_OK) {

                crm_err("Cannot set cstatus callback: %s",
                        fsa_cluster_conn->llc_ops->errmsg(fsa_cluster_conn));
                registered = FALSE;
            }

            if (registered) {
                crm_trace("Requesting an initial dump of CRMD client_status");
                fsa_cluster_conn->llc_ops->client_status(fsa_cluster_conn, NULL, CRM_SYSTEM_CRMD,
                                                         -1);
            }
#endif
        }
        fsa_our_uname = cluster.uname;
        fsa_our_uuid = cluster.uuid;

        if (registered == FALSE) {
            set_bit(fsa_input_register, R_HA_DISCONNECTED);
            register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
            return;
        }

        populate_cib_nodes(node_update_none, __FUNCTION__);
        clear_bit(fsa_input_register, R_HA_DISCONNECTED);
        crm_info("Connected to the cluster");
    }

    if (action & ~(A_HA_CONNECT | A_HA_DISCONNECT)) {
        crm_err("Unexpected action %s in %s", fsa_action2string(action), __FUNCTION__);
    }
}

/*	 A_SHUTDOWN	*/
void
do_shutdown(long long action,
            enum crmd_fsa_cause cause,
            enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    /* just in case */
    set_bit(fsa_input_register, R_SHUTDOWN);

    if (is_heartbeat_cluster()) {
        if (is_set(fsa_input_register, pe_subsystem->flag_connected)) {
            crm_info("Terminating the %s", pe_subsystem->name);
            if (stop_subsystem(pe_subsystem, TRUE) == FALSE) {
                /* its gone... */
                crm_err("Faking %s exit", pe_subsystem->name);
                clear_bit(fsa_input_register, pe_subsystem->flag_connected);
            } else {
                crm_info("Waiting for subsystems to exit");
                crmd_fsa_stall(NULL);
            }
        }
        crm_info("All subsystems stopped, continuing");
    }

    if (stonith_api) {
        /* Prevent it from comming up again */
        clear_bit(fsa_input_register, R_ST_REQUIRED);

        crm_info("Disconnecting STONITH...");
        stonith_api->cmds->disconnect(stonith_api);
    }
}

/*	 A_SHUTDOWN_REQ	*/
void
do_shutdown_req(long long action,
                enum crmd_fsa_cause cause,
                enum crmd_fsa_state cur_state,
                enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    xmlNode *msg = NULL;

    crm_info("Sending shutdown request to %s", crm_str(fsa_our_dc));
    msg = create_request(CRM_OP_SHUTDOWN_REQ, NULL, NULL, CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);

/* 	set_bit(fsa_input_register, R_STAYDOWN); */
    if (send_cluster_message(NULL, crm_msg_crmd, msg, TRUE) == FALSE) {
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
    free_xml(msg);
}

extern crm_ipc_t *attrd_ipc;
extern char *max_generation_from;
extern xmlNode *max_generation_xml;
extern GHashTable *resource_history;
extern GHashTable *voted;
extern GHashTable *reload_hash;

void log_connected_client(gpointer key, gpointer value, gpointer user_data);

void
log_connected_client(gpointer key, gpointer value, gpointer user_data)
{
    crmd_client_t *client = value;

    crm_err("%s is still connected at exit", client->table_key);
}

static void
free_mem(fsa_data_t * msg_data)
{
    GListPtr gIter = NULL;

    if(attrd_ipc) {
        crm_ipc_close(attrd_ipc);
        crm_ipc_destroy(attrd_ipc);
    }
    if(crmd_mainloop) {
        g_main_loop_quit(crmd_mainloop);
        g_main_loop_unref(crmd_mainloop);
    }

#if SUPPORT_HEARTBEAT
    if (fsa_cluster_conn) {
        fsa_cluster_conn->llc_ops->delete(fsa_cluster_conn);
        fsa_cluster_conn = NULL;
    }
#endif

    for(gIter = fsa_message_queue; gIter != NULL; gIter = gIter->next) {
        fsa_data_t *fsa_data = gIter->data;
        crm_info("Dropping %s: [ state=%s cause=%s origin=%s ]",
                 fsa_input2string(fsa_data->fsa_input),
                 fsa_state2string(fsa_state),
                 fsa_cause2string(fsa_data->fsa_cause), fsa_data->origin);
        delete_fsa_input(fsa_data);
    }
    g_list_free(fsa_message_queue);
    delete_fsa_input(msg_data);

    if (ipc_clients) {
        crm_debug("Number of connected clients: %d", g_hash_table_size(ipc_clients));
/* 		g_hash_table_foreach(ipc_clients, log_connected_client, NULL); */
        g_hash_table_destroy(ipc_clients);
    }

    empty_uuid_cache();
    crm_peer_destroy();
    clear_bit(fsa_input_register, R_MEMBERSHIP);

    if (te_subsystem->client && te_subsystem->client->ipc) {
        crm_debug("Full destroy: TE");
        qb_ipcs_disconnect(te_subsystem->client->ipc);
    }
    free(te_subsystem);

    if (pe_subsystem->client && pe_subsystem->client->ipc) {
        crm_debug("Full destroy: PE");
        qb_ipcs_disconnect(pe_subsystem->client->ipc);
    }
    free(pe_subsystem);

    free(cib_subsystem);

    if (integrated_nodes) {
        g_hash_table_destroy(integrated_nodes);
    }
    if (finalized_nodes) {
        g_hash_table_destroy(finalized_nodes);
    }
    if (confirmed_nodes) {
        g_hash_table_destroy(confirmed_nodes);
    }
    if (reload_hash) {
        g_hash_table_destroy(reload_hash);
    }
    if (resource_history) {
        g_hash_table_destroy(resource_history);
    }
    if (voted) {
        g_hash_table_destroy(voted);
    }

    cib_delete(fsa_cib_conn);
    fsa_cib_conn = NULL;

    if (fsa_lrm_conn) {
        lrmd_api_delete(fsa_lrm_conn);
        fsa_lrm_conn = NULL;
    }

    free(transition_timer);
    free(integration_timer);
    free(finalization_timer);
    free(election_trigger);
    free(election_timeout);
    free(shutdown_escalation_timer);
    free(wait_timer);
    free(recheck_timer);

    free(fsa_our_dc_version);
    free(fsa_our_uname);
    free(fsa_our_uuid);
    free(fsa_our_dc);

    free(max_generation_from);
    free_xml(max_generation_xml);

    crm_xml_cleanup();
}

/*	 A_EXIT_0, A_EXIT_1	*/
void
do_exit(long long action,
        enum crmd_fsa_cause cause,
        enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    int exit_code = 0;
    int log_level = LOG_INFO;
    const char *exit_type = "gracefully";

    if (action & A_EXIT_1) {
        exit_code = 1;
        log_level = LOG_ERR;
        exit_type = "forcefully";
    }

    verify_stopped(cur_state, LOG_ERR);
    do_crm_log(log_level, "Performing %s - %s exiting the CRMd",
               fsa_action2string(action), exit_type);

    if (is_set(fsa_input_register, R_IN_RECOVERY)) {
        crm_err("Could not recover from internal error");
        exit_code = 2;
    }
    if (is_set(fsa_input_register, R_STAYDOWN)) {
        crm_warn("Inhibiting respawn by Heartbeat");
        exit_code = 100;
    }

    crm_info("[%s] stopped (%d)", crm_system_name, exit_code);
    free_mem(msg_data);
    exit(exit_code);
}

/*	 A_STARTUP	*/
void
do_startup(long long action,
           enum crmd_fsa_cause cause,
           enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    int was_error = 0;
    int interval = 1;           /* seconds between DC heartbeats */

    crm_debug("Registering Signal Handlers");
    mainloop_add_signal(SIGTERM, crm_shutdown);

    fsa_source = mainloop_add_trigger(G_PRIORITY_HIGH, crm_fsa_trigger, NULL);
    config_read = mainloop_add_trigger(G_PRIORITY_HIGH, crm_read_options, NULL);

    ipc_clients = g_hash_table_new(crm_str_hash, g_str_equal);

    crm_debug("Creating CIB and LRM objects");
    fsa_cib_conn = cib_new();
    fsa_lrm_conn = lrmd_api_new();

    /* set up the timers */
    transition_timer = calloc(1, sizeof(fsa_timer_t));
    integration_timer = calloc(1, sizeof(fsa_timer_t));
    finalization_timer = calloc(1, sizeof(fsa_timer_t));
    election_trigger = calloc(1, sizeof(fsa_timer_t));
    election_timeout = calloc(1, sizeof(fsa_timer_t));
    shutdown_escalation_timer = calloc(1, sizeof(fsa_timer_t));
    wait_timer = calloc(1, sizeof(fsa_timer_t));
    recheck_timer = calloc(1, sizeof(fsa_timer_t));

    interval = interval * 1000;

    if (election_trigger != NULL) {
        election_trigger->source_id = 0;
        election_trigger->period_ms = -1;
        election_trigger->fsa_input = I_DC_TIMEOUT;
        election_trigger->callback = crm_timer_popped;
        election_trigger->repeat = FALSE;
    } else {
        was_error = TRUE;
    }

    if (election_timeout != NULL) {
        election_timeout->source_id = 0;
        election_timeout->period_ms = -1;
        election_timeout->fsa_input = I_ELECTION_DC;
        election_timeout->callback = crm_timer_popped;
        election_timeout->repeat = FALSE;
    } else {
        was_error = TRUE;
    }

    if (transition_timer != NULL) {
        transition_timer->source_id = 0;
        transition_timer->period_ms = -1;
        transition_timer->fsa_input = I_PE_CALC;
        transition_timer->callback = crm_timer_popped;
        transition_timer->repeat = FALSE;
    } else {
        was_error = TRUE;
    }

    if (integration_timer != NULL) {
        integration_timer->source_id = 0;
        integration_timer->period_ms = -1;
        integration_timer->fsa_input = I_INTEGRATED;
        integration_timer->callback = crm_timer_popped;
        integration_timer->repeat = FALSE;
    } else {
        was_error = TRUE;
    }

    if (finalization_timer != NULL) {
        finalization_timer->source_id = 0;
        finalization_timer->period_ms = -1;
        finalization_timer->fsa_input = I_FINALIZED;
        finalization_timer->callback = crm_timer_popped;
        finalization_timer->repeat = FALSE;
        /* for possible enabling... a bug in the join protocol left
         *    a slave in S_PENDING while we think its in S_NOT_DC
         *
         * raising I_FINALIZED put us into a transition loop which is
         *    never resolved.
         * in this loop we continually send probes which the node
         *    NACK's because its in S_PENDING
         *
         * if we have nodes where heartbeat is active but the
         *    CRM is not... then this will be handled in the
         *    integration phase
         */
        finalization_timer->fsa_input = I_ELECTION;

    } else {
        was_error = TRUE;
    }

    if (shutdown_escalation_timer != NULL) {
        shutdown_escalation_timer->source_id = 0;
        shutdown_escalation_timer->period_ms = -1;
        shutdown_escalation_timer->fsa_input = I_STOP;
        shutdown_escalation_timer->callback = crm_timer_popped;
        shutdown_escalation_timer->repeat = FALSE;
    } else {
        was_error = TRUE;
    }

    if (wait_timer != NULL) {
        wait_timer->source_id = 0;
        wait_timer->period_ms = 2000;
        wait_timer->fsa_input = I_NULL;
        wait_timer->callback = crm_timer_popped;
        wait_timer->repeat = FALSE;
    } else {
        was_error = TRUE;
    }

    if (recheck_timer != NULL) {
        recheck_timer->source_id = 0;
        recheck_timer->period_ms = -1;
        recheck_timer->fsa_input = I_PE_CALC;
        recheck_timer->callback = crm_timer_popped;
        recheck_timer->repeat = FALSE;
    } else {
        was_error = TRUE;
    }

    /* set up the sub systems */
    cib_subsystem = calloc(1, sizeof(struct crm_subsystem_s));
    te_subsystem = calloc(1, sizeof(struct crm_subsystem_s));
    pe_subsystem = calloc(1, sizeof(struct crm_subsystem_s));

    if (cib_subsystem != NULL) {
        cib_subsystem->pid = -1;
        cib_subsystem->name = CRM_SYSTEM_CIB;
        cib_subsystem->flag_connected = R_CIB_CONNECTED;
        cib_subsystem->flag_required = R_CIB_REQUIRED;

    } else {
        was_error = TRUE;
    }

    if (te_subsystem != NULL) {
        te_subsystem->pid = -1;
        te_subsystem->name = CRM_SYSTEM_TENGINE;
        te_subsystem->flag_connected = R_TE_CONNECTED;
        te_subsystem->flag_required = R_TE_REQUIRED;

    } else {
        was_error = TRUE;
    }

    if (pe_subsystem != NULL) {
        pe_subsystem->pid = -1;
        pe_subsystem->path = CRM_DAEMON_DIR;
        pe_subsystem->name = CRM_SYSTEM_PENGINE;
        pe_subsystem->command = CRM_DAEMON_DIR "/" CRM_SYSTEM_PENGINE;
        pe_subsystem->args = NULL;
        pe_subsystem->flag_connected = R_PE_CONNECTED;
        pe_subsystem->flag_required = R_PE_REQUIRED;

    } else {
        was_error = TRUE;
    }

    if (was_error == FALSE && is_heartbeat_cluster()) {
        if(start_subsystem(pe_subsystem) == FALSE) {
            was_error = TRUE;
        }
    }

    if (was_error) {
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }

    welcomed_nodes = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                           g_hash_destroy_str, g_hash_destroy_str);
    integrated_nodes = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                             g_hash_destroy_str, g_hash_destroy_str);
    finalized_nodes = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                            g_hash_destroy_str, g_hash_destroy_str);
    confirmed_nodes = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                            g_hash_destroy_str, g_hash_destroy_str);
}

static int32_t
crmd_ipc_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    crmd_client_t *blank_client = NULL;
#if ENABLE_ACL
    struct group *crm_grp = NULL;
#endif

    crm_trace("Connecting %p for uid=%d gid=%d", c, uid, gid);

    blank_client = calloc(1, sizeof(crmd_client_t));
    CRM_ASSERT(blank_client != NULL);

    crm_trace("Created client: %p", blank_client);

    blank_client->ipc = c;
    blank_client->sub_sys = NULL;
    blank_client->uuid = NULL;
    blank_client->table_key = NULL;

#if ENABLE_ACL
    crm_grp = getgrnam(CRM_DAEMON_GROUP);
    if (crm_grp) {
        qb_ipcs_connection_auth_set(c, -1, crm_grp->gr_gid, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    }

    blank_client->user = uid2username(uid);
#endif

    qb_ipcs_context_set(c, blank_client);

    return 0;
}

static void
crmd_ipc_created(qb_ipcs_connection_t *c)
{
    crm_trace("Client %p connected", c);
}

static int32_t
crmd_ipc_dispatch(qb_ipcs_connection_t *c, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    crmd_client_t *client = qb_ipcs_context_get(c);

    xmlNode *msg = crm_ipcs_recv(c, data, size, &id, &flags);
    crm_trace("Invoked: %s", client->table_key);

    if(flags & crm_ipc_client_response) {
        crm_ipcs_send_ack(c, id, "ack", __FUNCTION__, __LINE__);
    }

    if (msg == NULL) {
        return 0;
    }

#if ENABLE_ACL
    determine_request_user(client->user, msg, F_CRM_USER);
#endif

    crm_trace("Processing msg from %s", client->table_key);
    crm_log_xml_trace(msg, "CRMd[inbound]");

    if (crmd_authorize_message(msg, client)) {
        route_message(C_IPC_MESSAGE, msg);
    }
    
    trigger_fsa(fsa_source);    
    free_xml(msg);
    return 0;
}

static int32_t
crmd_ipc_closed(qb_ipcs_connection_t *c) 
{
    return 0;
}

static void
crmd_ipc_destroy(qb_ipcs_connection_t *c) 
{
    crmd_client_t *client = qb_ipcs_context_get(c);

    if (client == NULL) {
        crm_trace("No client to delete");
        return;
    }

    process_client_disconnect(client);
    
    crm_trace("Disconnecting client %s (%p)", client->table_key, client);
    free(client->table_key);
    free(client->sub_sys);
    free(client->uuid);
    free(client->user);
    free(client);

    trigger_fsa(fsa_source);    
}

/*	 A_STOP	*/
void
do_stop(long long action,
        enum crmd_fsa_cause cause,
        enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    if (is_heartbeat_cluster()) {
        stop_subsystem(pe_subsystem, FALSE);   
    }

    mainloop_del_ipc_server(ipcs);
    register_fsa_input(C_FSA_INTERNAL, I_TERMINATE, NULL);
}

/*	 A_STARTED	*/
void
do_started(long long action,
           enum crmd_fsa_cause cause,
           enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    static struct qb_ipcs_service_handlers crmd_callbacks = 
        {
            .connection_accept = crmd_ipc_accept,
            .connection_created = crmd_ipc_created,
            .msg_process = crmd_ipc_dispatch,
            .connection_closed = crmd_ipc_closed,
            .connection_destroyed = crmd_ipc_destroy
        };

    if (cur_state != S_STARTING) {
        crm_err("Start cancelled... %s", fsa_state2string(cur_state));
        return;

    } else if (is_set(fsa_input_register, R_MEMBERSHIP) == FALSE) {
        crm_info("Delaying start, no membership data (%.16llx)", R_MEMBERSHIP);

        crmd_fsa_stall(NULL);
        return;

    } else if (is_set(fsa_input_register, R_LRM_CONNECTED) == FALSE) {
        crm_info("Delaying start, LRM not connected (%.16llx)", R_LRM_CONNECTED);

        crmd_fsa_stall(NULL);
        return;

    } else if (is_set(fsa_input_register, R_CIB_CONNECTED) == FALSE) {
        crm_info("Delaying start, CIB not connected (%.16llx)", R_CIB_CONNECTED);

        crmd_fsa_stall(NULL);
        return;

    } else if (is_set(fsa_input_register, R_READ_CONFIG) == FALSE) {
        crm_info("Delaying start, Config not read (%.16llx)", R_READ_CONFIG);

        crmd_fsa_stall(NULL);
        return;

    } else if (is_set(fsa_input_register, R_PEER_DATA) == FALSE) {

        /* try reading from HA */
        crm_info("Delaying start, No peer data (%.16llx)", R_PEER_DATA);

#if SUPPORT_HEARTBEAT
        if (is_heartbeat_cluster()) {
            HA_Message *msg = NULL;
            crm_trace("Looking for a HA message");
            msg = fsa_cluster_conn->llc_ops->readmsg(fsa_cluster_conn, 0);
            if (msg != NULL) {
                crm_trace("There was a HA message");
                ha_msg_del(msg);
            }
        }
#endif
        crmd_fsa_stall(NULL);
        return;
    }

    crm_debug("Init server comms");
    ipcs = mainloop_add_ipc_server(CRM_SYSTEM_CRMD, QB_IPC_NATIVE, &crmd_callbacks);
    if (ipcs == NULL) {
        crm_err("Couldn't start IPC server");
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }

    if (stonith_reconnect == NULL) {
        int dummy;

        stonith_reconnect = mainloop_add_trigger(G_PRIORITY_LOW, te_connect_stonith, &dummy);
    }
    set_bit(fsa_input_register, R_ST_REQUIRED);
    mainloop_set_trigger(stonith_reconnect);

    crm_notice("The local CRM is operational");
    clear_bit(fsa_input_register, R_STARTING);
    register_fsa_input(msg_data->fsa_cause, I_PENDING, NULL);
}

/*	 A_RECOVER	*/
void
do_recover(long long action,
           enum crmd_fsa_cause cause,
           enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    set_bit(fsa_input_register, R_IN_RECOVERY);
    crm_err("Action %s (%.16llx) not supported", fsa_action2string(action), action);

    register_fsa_input(C_FSA_INTERNAL, I_TERMINATE, NULL);
}

/* *INDENT-OFF* */
pe_cluster_option crmd_opts[] = {
	/* name, old-name, validate, default, description */
	{ "dc-version", NULL, "string", NULL, "none", NULL, "Version of Pacemaker on the cluster's DC.", "Includes the hash which identifies the exact Mercurial changeset it was built from.  Used for diagnostic purposes." },
	{ "cluster-infrastructure", NULL, "string", NULL, "heartbeat", NULL, "The messaging stack on which Pacemaker is currently running.", "Used for informational and diagnostic purposes." },
	{ XML_CONFIG_ATTR_DC_DEADTIME, "dc_deadtime", "time", NULL, "20s", &check_time, "How long to wait for a response from other nodes during startup.", "The \"correct\" value will depend on the speed/load of your network and the type of switches used." },
	{ XML_CONFIG_ATTR_RECHECK, "cluster_recheck_interval", "time",
	  "Zero disables polling.  Positive values are an interval in seconds (unless other SI units are specified. eg. 5min)", "15min", &check_timer,
	  "Polling interval for time based changes to options, resource parameters and constraints.",
	  "The Cluster is primarily event driven, however the configuration can have elements that change based on time."
	  "  To ensure these changes take effect, we can optionally poll the cluster's status for changes." },
	{ XML_CONFIG_ATTR_ELECTION_FAIL, "election_timeout", "time", NULL, "2min", &check_timer, "*** Advanced Use Only ***.", "If need to adjust this value, it probably indicates the presence of a bug." },
	{ XML_CONFIG_ATTR_FORCE_QUIT, "shutdown_escalation", "time", NULL, "20min", &check_timer, "*** Advanced Use Only ***.", "If need to adjust this value, it probably indicates the presence of a bug." },
	{ "crmd-integration-timeout", NULL, "time", NULL, "3min", &check_timer, "*** Advanced Use Only ***.", "If need to adjust this value, it probably indicates the presence of a bug." },
	{ "crmd-finalization-timeout", NULL, "time", NULL, "30min", &check_timer, "*** Advanced Use Only ***.", "If you need to adjust this value, it probably indicates the presence of a bug." },
	{ "crmd-transition-delay", NULL, "time", NULL, "0s", &check_timer, "*** Advanced Use Only ***\nEnabling this option will slow down cluster recovery under all conditions", "Delay cluster recovery for the configured interval to allow for additional/related events to occur.\nUseful if your configuration is sensitive to the order in which ping updates arrive." },
	{ XML_ATTR_EXPECTED_VOTES, NULL, "integer", NULL, "2", &check_number, "The number of nodes expected to be in the cluster", "Used to calculate quorum in openais based clusters." },
};
/* *INDENT-ON* */

void
crmd_metadata(void)
{
    config_metadata("CRM Daemon", "1.0",
                    "CRM Daemon Options",
                    "This is a fake resource that details the options that can be configured for the CRM Daemon.",
                    crmd_opts, DIMOF(crmd_opts));
}

static void
verify_crmd_options(GHashTable * options)
{
    verify_all_options(options, crmd_opts, DIMOF(crmd_opts));
}

static const char *
crmd_pref(GHashTable * options, const char *name)
{
    return get_cluster_pref(options, crmd_opts, DIMOF(crmd_opts), name);
}

static void
config_query_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    const char *value = NULL;
    GHashTable *config_hash = NULL;
    ha_time_t *now = new_ha_date(TRUE);

    if (rc != pcmk_ok) {
        fsa_data_t *msg_data = NULL;

        crm_err("Local CIB query resulted in an error: %s", pcmk_strerror(rc));
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);

        if (rc == -EACCES || rc == -pcmk_err_dtd_validation) {
            crm_err("The cluster is mis-configured - shutting down and staying down");
            set_bit(fsa_input_register, R_STAYDOWN);
        }
        goto bail;
    }

    crm_debug("Call %d : Parsing CIB options", call_id);
    config_hash =
        g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

    unpack_instance_attributes(output, output, XML_CIB_TAG_PROPSET, NULL, config_hash,
                               CIB_OPTIONS_FIRST, FALSE, now);

    verify_crmd_options(config_hash);

    value = crmd_pref(config_hash, XML_CONFIG_ATTR_DC_DEADTIME);
    election_trigger->period_ms = crm_get_msec(value);

    value = crmd_pref(config_hash, XML_CONFIG_ATTR_FORCE_QUIT);
    shutdown_escalation_timer->period_ms = crm_get_msec(value);
    crm_debug("Shutdown escalation occurs after: %dms", shutdown_escalation_timer->period_ms);

    value = crmd_pref(config_hash, XML_CONFIG_ATTR_ELECTION_FAIL);
    election_timeout->period_ms = crm_get_msec(value);

    value = crmd_pref(config_hash, XML_CONFIG_ATTR_RECHECK);
    recheck_timer->period_ms = crm_get_msec(value);
    crm_debug("Checking for expired actions every %dms", recheck_timer->period_ms);

    value = crmd_pref(config_hash, "crmd-transition-delay");
    transition_timer->period_ms = crm_get_msec(value);

    value = crmd_pref(config_hash, "crmd-integration-timeout");
    integration_timer->period_ms = crm_get_msec(value);

    value = crmd_pref(config_hash, "crmd-finalization-timeout");
    finalization_timer->period_ms = crm_get_msec(value);

#if SUPPORT_COROSYNC
    if (is_classic_ais_cluster()) {
        value = crmd_pref(config_hash, XML_ATTR_EXPECTED_VOTES);
        crm_debug("Sending expected-votes=%s to corosync", value);
        send_ais_text(crm_class_quorum, value, TRUE, NULL, crm_msg_ais);
    }
#endif

    set_bit(fsa_input_register, R_READ_CONFIG);
    crm_trace("Triggering FSA: %s", __FUNCTION__);
    mainloop_set_trigger(fsa_source);

    g_hash_table_destroy(config_hash);
  bail:
    free_ha_date(now);
}

gboolean
crm_read_options(gpointer user_data)
{
    int call_id =
        fsa_cib_conn->cmds->query(fsa_cib_conn, XML_CIB_TAG_CRMCONFIG, NULL, cib_scope_local);

    add_cib_op_callback(fsa_cib_conn, call_id, FALSE, NULL, config_query_callback);
    crm_trace("Querying the CIB... call %d", call_id);
    return TRUE;
}

/*	 A_READCONFIG	*/
void
do_read_config(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state,
               enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    mainloop_set_trigger(config_read);
}

void
crm_shutdown(int nsig)
{
    if (crmd_mainloop != NULL && g_main_is_running(crmd_mainloop)) {
        if (is_set(fsa_input_register, R_SHUTDOWN)) {
            crm_err("Escalating the shutdown");
            register_fsa_input_before(C_SHUTDOWN, I_ERROR, NULL);

        } else {
            set_bit(fsa_input_register, R_SHUTDOWN);
            register_fsa_input(C_SHUTDOWN, I_SHUTDOWN, NULL);

            if (shutdown_escalation_timer->period_ms < 1) {
                const char *value = crmd_pref(NULL, XML_CONFIG_ATTR_FORCE_QUIT);
                int msec = crm_get_msec(value);

                crm_debug("Using default shutdown escalation: %dms", msec);
                shutdown_escalation_timer->period_ms = msec;
            }

            /* cant rely on this... */
            crm_notice("Requesting shutdown, upper limit is %dms", shutdown_escalation_timer->period_ms);
            crm_timer_start(shutdown_escalation_timer);
        }

    } else {
        crm_info("exit from shutdown");
        exit(EX_OK);

    }
}

void
default_cib_update_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    if (rc != pcmk_ok) {
        fsa_data_t *msg_data = NULL;

        crm_err("CIB Update failed: %s", pcmk_strerror(rc));
        crm_log_xml_warn(output, "update:failed");

        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
}
