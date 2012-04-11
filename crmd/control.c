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
#include <crm/cib.h>
#include <crm/msg_xml.h>

#include <crm/pengine/rules.h>
#include <crm/common/cluster.h>
#include "../lib/cluster/stack.h"

#include <crmd.h>
#include <crmd_fsa.h>
#include <fsa_proto.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>
#include <crmd_lrm.h>
#include <tengine.h>

#include <sys/types.h>
#include <sys/stat.h>

char *ipc_server = NULL;

extern gboolean crm_connect_corosync(void);
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

    if (action & A_HA_DISCONNECT) {
        if (is_openais_cluster()) {
            crm_peer_destroy();
#if SUPPORT_COROSYNC
            terminate_ais_connection();
#endif
            crm_info("Disconnected from OpenAIS");

#if SUPPORT_HEARTBEAT
        } else if (fsa_cluster_conn != NULL) {
            set_bit_inplace(fsa_input_register, R_HA_DISCONNECTED);
            fsa_cluster_conn->llc_ops->signoff(fsa_cluster_conn, FALSE);
            crm_info("Disconnected from Heartbeat");
#endif
        }
    }

    if (action & A_HA_CONNECT) {
        crm_set_status_callback(&ais_status_callback);

        if (is_openais_cluster()) {
#if SUPPORT_COROSYNC
            registered = crm_connect_corosync();
#endif
        } else if (is_heartbeat_cluster()) {
#if SUPPORT_HEARTBEAT
            registered =
                crm_cluster_connect(&fsa_our_uname, &fsa_our_uuid, crmd_ha_msg_callback,
                                    crmd_ha_connection_destroy, &fsa_cluster_conn);
#endif
        }
#if SUPPORT_HEARTBEAT
        if (is_heartbeat_cluster()) {
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
        }
#endif

        if (registered == FALSE) {
            set_bit_inplace(fsa_input_register, R_HA_DISCONNECTED);
            register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
            return;
        }

        clear_bit_inplace(fsa_input_register, R_HA_DISCONNECTED);
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
    set_bit_inplace(fsa_input_register, R_SHUTDOWN);

    if (is_heartbeat_cluster()) {
        if (is_set(fsa_input_register, pe_subsystem->flag_connected)) {
            crm_info("Terminating the %s", pe_subsystem->name);
            if (stop_subsystem(pe_subsystem, TRUE) == FALSE) {
                /* its gone... */
                crm_err("Faking %s exit", pe_subsystem->name);
                clear_bit_inplace(fsa_input_register, pe_subsystem->flag_connected);
            } else {
                crm_info("Waiting for subsystems to exit");
                crmd_fsa_stall(NULL);
            }
        }
        crm_info("All subsystems stopped, continuing");
    }

    if (stonith_api) {
        /* Prevent it from comming up again */
        clear_bit_inplace(fsa_input_register, R_ST_REQUIRED);

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

/* 	set_bit_inplace(fsa_input_register, R_STAYDOWN); */
    if (send_cluster_message(NULL, crm_msg_crmd, msg, TRUE) == FALSE) {
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
    free_xml(msg);
}

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
    g_main_loop_quit(crmd_mainloop);
    g_main_loop_unref(crmd_mainloop);

#if SUPPORT_HEARTBEAT
    if (fsa_cluster_conn) {
        fsa_cluster_conn->llc_ops->delete(fsa_cluster_conn);
        fsa_cluster_conn = NULL;
    }
#endif
    slist_destroy(fsa_data_t, fsa_data, fsa_message_queue,
                  crm_info("Dropping %s: [ state=%s cause=%s origin=%s ]",
                           fsa_input2string(fsa_data->fsa_input),
                           fsa_state2string(fsa_state),
                           fsa_cause2string(fsa_data->fsa_cause), fsa_data->origin);
                  delete_fsa_input(fsa_data);
        );
    delete_fsa_input(msg_data);

    if (ipc_clients) {
        crm_debug("Number of connected clients: %d", g_hash_table_size(ipc_clients));
/* 		g_hash_table_foreach(ipc_clients, log_connected_client, NULL); */
        g_hash_table_destroy(ipc_clients);
    }

    empty_uuid_cache();
    crm_peer_destroy();
    clear_bit_inplace(fsa_input_register, R_MEMBERSHIP);

    if (te_subsystem->client && te_subsystem->client->client_source) {
        crm_debug("Full destroy: TE");
        G_main_del_IPC_Channel(te_subsystem->client->client_source);
    } else {
        crm_debug("Partial destroy: TE");
        crmd_ipc_connection_destroy(te_subsystem->client);
    }
    crm_free(te_subsystem);

    if (pe_subsystem->client && pe_subsystem->client->client_source) {
        crm_debug("Full destroy: PE");
        G_main_del_IPC_Channel(pe_subsystem->client->client_source);
    } else {
        crm_debug("Partial destroy: PE");
        crmd_ipc_connection_destroy(pe_subsystem->client);
    }
    crm_free(pe_subsystem);

    crm_free(cib_subsystem);

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
        fsa_lrm_conn->lrm_ops->delete(fsa_lrm_conn);
    }

    crm_free(transition_timer);
    crm_free(integration_timer);
    crm_free(finalization_timer);
    crm_free(election_trigger);
    crm_free(election_timeout);
    crm_free(shutdown_escalation_timer);
    crm_free(wait_timer);
    crm_free(recheck_timer);

    crm_free(fsa_our_dc_version);
    crm_free(fsa_our_uname);
    crm_free(fsa_our_uuid);
    crm_free(fsa_our_dc);
    crm_free(ipc_server);

    crm_free(max_generation_from);
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

    free_mem(msg_data);

    crm_info("[%s] stopped (%d)", crm_system_name, exit_code);
    cl_flush_logs();
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
    fsa_lrm_conn = ll_lrm_new(XML_CIB_TAG_LRM);

    /* set up the timers */
    crm_malloc0(transition_timer, sizeof(fsa_timer_t));
    crm_malloc0(integration_timer, sizeof(fsa_timer_t));
    crm_malloc0(finalization_timer, sizeof(fsa_timer_t));
    crm_malloc0(election_trigger, sizeof(fsa_timer_t));
    crm_malloc0(election_timeout, sizeof(fsa_timer_t));
    crm_malloc0(shutdown_escalation_timer, sizeof(fsa_timer_t));
    crm_malloc0(wait_timer, sizeof(fsa_timer_t));
    crm_malloc0(recheck_timer, sizeof(fsa_timer_t));

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
    crm_malloc0(cib_subsystem, sizeof(struct crm_subsystem_s));
    crm_malloc0(te_subsystem, sizeof(struct crm_subsystem_s));
    crm_malloc0(pe_subsystem, sizeof(struct crm_subsystem_s));

    if (cib_subsystem != NULL) {
        cib_subsystem->pid = -1;
        cib_subsystem->path = CRM_DAEMON_DIR;
        cib_subsystem->name = CRM_SYSTEM_CIB;
        cib_subsystem->command = CRM_DAEMON_DIR "/" CRM_SYSTEM_CIB;
        cib_subsystem->args = "-VVc";
        cib_subsystem->flag_connected = R_CIB_CONNECTED;
        cib_subsystem->flag_required = R_CIB_REQUIRED;

    } else {
        was_error = TRUE;
    }

    if (te_subsystem != NULL) {
        te_subsystem->pid = -1;
        te_subsystem->path = CRM_DAEMON_DIR;
        te_subsystem->name = CRM_SYSTEM_TENGINE;
        te_subsystem->command = CRM_DAEMON_DIR "/" CRM_SYSTEM_TENGINE;
        te_subsystem->args = NULL;
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

    set_sigchld_proctrack(G_PRIORITY_HIGH, DEFAULT_MAXDISPATCHTIME);
}

/*	 A_STOP	*/
void
do_stop(long long action,
        enum crmd_fsa_cause cause,
        enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    register_fsa_input(C_FSA_INTERNAL, I_TERMINATE, NULL);
}

/*	 A_STARTED	*/
void
do_started(long long action,
           enum crmd_fsa_cause cause,
           enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
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
        HA_Message *msg = NULL;

        /* try reading from HA */
        crm_info("Delaying start, No peer data (%.16llx)", R_PEER_DATA);

        crm_trace("Looking for a HA message");
#if SUPPORT_HEARTBEAT
        if (is_heartbeat_cluster()) {
            msg = fsa_cluster_conn->llc_ops->readmsg(fsa_cluster_conn, 0);
        }
#endif
        if (msg != NULL) {
            crm_trace("There was a HA message");
            crm_msg_del(msg);
        }
        crmd_fsa_stall(NULL);
        return;
    }

    crm_debug("Init server comms");
    if (ipc_server == NULL) {
        ipc_server = crm_strdup(CRM_SYSTEM_CRMD);
    }

    if (init_server_ipc_comms(ipc_server, crmd_client_connect, default_ipc_connection_destroy)) {
        crm_err("Couldn't start IPC server");
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }

    if (stonith_reconnect == NULL) {
        int dummy;

        stonith_reconnect = mainloop_add_trigger(G_PRIORITY_LOW, te_connect_stonith, &dummy);
    }
    set_bit_inplace(fsa_input_register, R_ST_REQUIRED);
    mainloop_set_trigger(stonith_reconnect);

    crm_notice("The local CRM is operational");
    clear_bit_inplace(fsa_input_register, R_STARTING);
    register_fsa_input(msg_data->fsa_cause, I_PENDING, NULL);
}

/*	 A_RECOVER	*/
void
do_recover(long long action,
           enum crmd_fsa_cause cause,
           enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    set_bit_inplace(fsa_input_register, R_IN_RECOVERY);
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

    if (rc != cib_ok) {
        fsa_data_t *msg_data = NULL;

        crm_err("Local CIB query resulted in an error: %s", cib_error2string(rc));
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);

        if (rc == cib_bad_permissions
            || rc == cib_dtd_validation || rc == cib_bad_digest || rc == cib_bad_config) {
            crm_err("The cluster is mis-configured - shutting down and staying down");
            set_bit_inplace(fsa_input_register, R_STAYDOWN);
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

    set_bit_inplace(fsa_input_register, R_READ_CONFIG);
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
            set_bit_inplace(fsa_input_register, R_SHUTDOWN);
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
        exit(LSB_EXIT_OK);

    }
}

static void
default_cib_update_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    if (rc != cib_ok) {
        fsa_data_t *msg_data = NULL;

        crm_err("CIB Update failed: %s", cib_error2string(rc));
        crm_log_xml_warn(output, "update:failed");

        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
}

#if SUPPORT_HEARTBEAT
static void
populate_cib_nodes_ha(gboolean with_client_status)
{
    int call_id = 0;
    const char *ha_node = NULL;
    xmlNode *cib_node_list = NULL;

    if (fsa_cluster_conn == NULL) {
        crm_debug("Not connected");
        return;
    }

    /* Async get client status information in the cluster */
    crm_info("Requesting the list of configured nodes");
    fsa_cluster_conn->llc_ops->init_nodewalk(fsa_cluster_conn);

    cib_node_list = create_xml_node(NULL, XML_CIB_TAG_NODES);
    do {
        const char *ha_node_type = NULL;
        const char *ha_node_uuid = NULL;
        xmlNode *cib_new_node = NULL;

        ha_node = fsa_cluster_conn->llc_ops->nextnode(fsa_cluster_conn);
        if (ha_node == NULL) {
            continue;
        }

        ha_node_type = fsa_cluster_conn->llc_ops->node_type(fsa_cluster_conn, ha_node);
        if (safe_str_neq(NORMALNODE, ha_node_type)) {
            crm_debug("Node %s: skipping '%s'", ha_node, ha_node_type);
            continue;
        }

        ha_node_uuid = get_uuid(ha_node);
        if (ha_node_uuid == NULL) {
            crm_warn("Node %s: no uuid found", ha_node);
            continue;
        }

        crm_debug("Node: %s (uuid: %s)", ha_node, ha_node_uuid);
        cib_new_node = create_xml_node(cib_node_list, XML_CIB_TAG_NODE);
        crm_xml_add(cib_new_node, XML_ATTR_ID, ha_node_uuid);
        crm_xml_add(cib_new_node, XML_ATTR_UNAME, ha_node);
        crm_xml_add(cib_new_node, XML_ATTR_TYPE, ha_node_type);

    } while (ha_node != NULL);

    fsa_cluster_conn->llc_ops->end_nodewalk(fsa_cluster_conn);

    /* Now update the CIB with the list of nodes */
    fsa_cib_update(XML_CIB_TAG_NODES, cib_node_list,
                   cib_scope_local | cib_quorum_override, call_id, NULL);
    add_cib_op_callback(fsa_cib_conn, call_id, FALSE, NULL, default_cib_update_callback);

    free_xml(cib_node_list);
    crm_trace("Complete");
}

#endif

static void
create_cib_node_definition(gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;
    xmlNode *cib_nodes = user_data;
    xmlNode *cib_new_node = NULL;

    crm_trace("Creating node entry for %s/%s", node->uname, node->uuid);
    cib_new_node = create_xml_node(cib_nodes, XML_CIB_TAG_NODE);
    crm_xml_add(cib_new_node, XML_ATTR_ID, node->uuid);
    crm_xml_add(cib_new_node, XML_ATTR_UNAME, node->uname);
    crm_xml_add(cib_new_node, XML_ATTR_TYPE, NORMALNODE);
}

void
populate_cib_nodes(gboolean with_client_status)
{
    int call_id = 0;
    xmlNode *cib_node_list = NULL;

#if SUPPORT_HEARTBEAT
    if (is_heartbeat_cluster()) {
        populate_cib_nodes_ha(with_client_status);
        return;
    }
#endif

    cib_node_list = create_xml_node(NULL, XML_CIB_TAG_NODES);
    g_hash_table_foreach(crm_peer_cache, create_cib_node_definition, cib_node_list);

    fsa_cib_update(XML_CIB_TAG_NODES, cib_node_list, cib_scope_local | cib_quorum_override, call_id,
                   NULL);
    add_cib_op_callback(fsa_cib_conn, call_id, FALSE, NULL, default_cib_update_callback);

    free_xml(cib_node_list);
    crm_trace("Complete");
}
