
/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <heartbeat.h>
#include <hb_api.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/lsb_exitcodes.h>

#include <crm/common/ipc.h>
#include <attrd.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

/* GMainLoop *mainloop = NULL; */
#define OPTARGS	"V?p:a:d:s:S:h:Dm:"

IPC_Channel *attrd = NULL;
GMainLoop*  mainloop = NULL;
GHashTable *ping_nodes = NULL;
const char *pingd_attr = "pingd";
gboolean do_filter = FALSE;
ll_cluster_t *pingd_cluster = NULL;
gboolean need_shutdown = FALSE;

const char *attr_set = NULL;
const char *attr_section = NULL;
const char *attr_dampen = NULL;
int attr_multiplier = 1;

void pingd_nstatus_callback(
	const char *node, const char *status, void *private_data);
void pingd_lstatus_callback(
	const char *node, const char *link, const char *status,
	void *private_data);
void do_node_walk(ll_cluster_t *hb_cluster);
void send_update(void);

static gboolean
pingd_shutdown(int nsig, gpointer unused)
{
	need_shutdown = TRUE;
	send_update();
	crm_info("Exiting");
	
	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_main_quit(mainloop);
	} else {
		exit(0);
	}
	return FALSE;
}

static void
usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s [-%s]\n", cmd, OPTARGS);
	fprintf(stream, "\t--%s (-%c) \t\t\tThis text\n", "help", '?');
	fprintf(stream, "\t--%s (-%c) \t\tRun in daemon mode\n", "daemonize", 'D');
	fprintf(stream, "\t--%s (-%c) <filename>\tFile in which to store the process' PID\n"
		"\t\t\t\t\t* Default=/tmp/pingd.pid\n", "pid-file", 'p');
	fprintf(stream, "\t--%s (-%c) <string>\tName of the node attribute to set\n"
		"\t\t\t\t\t* Default=pingd\n", "attr-name", 'a');
	fprintf(stream, "\t--%s (-%c) <string>\tName of the set in which to set the attribute\n"
		"\t\t\t\t\t* Default=cib-bootstrap-options\n", "attr-set", 's');
	fprintf(stream, "\t--%s (-%c) <string>\tWhich part of the CIB to put the attribute in\n"
		"\t\t\t\t\t* Default=status\n", "attr-section", 'S');
	fprintf(stream, "\t--%s (-%c) <single_host_name>\tMonitor a subset of the ping nodes listed in ha.cf (can be specified multiple times)\n", "ping-host", 'h');
	fprintf(stream, "\t--%s (-%c) <integer>\t\tHow long to wait for no further changes to occur before updating the CIB with a changed attribute\n", "attr-dampen", 'd');
	fprintf(stream, "\t--%s (-%c) <integer>\tFor every connected node, add <integer> to the value set in the CIB\n"
		"\t\t\t\t\t\t* Default=1\n", "value-multiplier", 'm');

	fflush(stream);

	exit(exit_status);
}

#if SUPPORT_HEARTBEAT
static gboolean
pingd_ha_dispatch(IPC_Channel *channel, gpointer user_data)
{
	gboolean stay_connected = TRUE;

	crm_debug_2("Invoked");

	while(pingd_cluster != NULL && IPC_ISRCONN(channel)) {
		if(pingd_cluster->llc_ops->msgready(pingd_cluster) == 0) {
			crm_debug_2("no message ready yet");
			break;
		}
		/* invoke the callbacks but dont block */
		pingd_cluster->llc_ops->rcvmsg(pingd_cluster, 0);
	}
	
	if (pingd_cluster == NULL || channel->ch_status != IPC_CONNECT) {
		if(need_shutdown == FALSE) {
			crm_crit("Lost connection to heartbeat service.");
		} else {
			crm_info("Lost connection to heartbeat service.");
		}
		stay_connected = FALSE;
	}
    
	return stay_connected;
}


static void
pingd_ha_connection_destroy(gpointer user_data)
{
	crm_debug_3("Invoked");
	if(need_shutdown) {
		/* we signed out, so this is expected */
		crm_info("Heartbeat disconnection complete");
		return;
	}

	crm_crit("Lost connection to heartbeat service!");
}

static gboolean
register_with_ha(void) 
{
	if(pingd_cluster == NULL) {
		pingd_cluster = ll_cluster_new("heartbeat");
	}
	if(pingd_cluster == NULL) {
		crm_err("Cannot create heartbeat object");
		return FALSE;
	}
	
	crm_debug("Signing in with Heartbeat");
	if (pingd_cluster->llc_ops->signon(
		    pingd_cluster, crm_system_name) != HA_OK) {

		crm_err("Cannot sign on with heartbeat: %s",
			pingd_cluster->llc_ops->errmsg(pingd_cluster));
		crm_err("REASON: %s", pingd_cluster->llc_ops->errmsg(pingd_cluster));
		return FALSE;
	}

	do_node_walk(pingd_cluster);	

	crm_debug_3("Be informed of Node Status changes");
	if (HA_OK != pingd_cluster->llc_ops->set_nstatus_callback(
		    pingd_cluster, pingd_nstatus_callback, NULL)) {
		
		crm_err("Cannot set nstatus callback: %s",
			pingd_cluster->llc_ops->errmsg(pingd_cluster));
		crm_err("REASON: %s", pingd_cluster->llc_ops->errmsg(pingd_cluster));
		return FALSE;
	}

	if (pingd_cluster->llc_ops->set_ifstatus_callback(
		    pingd_cluster, pingd_lstatus_callback, NULL) != HA_OK) {
		cl_log(LOG_ERR, "Cannot set if status callback");
		crm_err("REASON: %s", pingd_cluster->llc_ops->errmsg(pingd_cluster));
		return FALSE;
	}
	
	crm_debug_3("Adding channel to mainloop");
	G_main_add_IPC_Channel(
		G_PRIORITY_HIGH, pingd_cluster->llc_ops->ipcchan(
			pingd_cluster),
		FALSE, pingd_ha_dispatch, pingd_cluster,  
		pingd_ha_connection_destroy);

	return TRUE;
}
#endif

int
main(int argc, char **argv)
{
	int lpc;
	int argerr = 0;
	int flag;
	char *pid_file = NULL;
	gboolean daemonize = FALSE;
	
#ifdef HAVE_GETOPT_H
	int option_index = 0;
	static struct option long_options[] = {
		/* Top-level Options */
		{"verbose", 0, 0, 'V'},
		{"help", 0, 0, '?'},
		{"pid-file",  1, 0, 'p'},		
		{"ping-host", 1, 0, 'h'},		
		{"attr-name", 1, 0, 'a'},		
		{"attr-set",  1, 0, 's'},		
		{"daemonize", 0, 0, 'D'},		
		{"attr-section", 1, 0, 'S'},		
		{"attr-dampen",  1, 0, 'd'},		
		{"value-multiplier",  1, 0, 'm'},		

		{0, 0, 0, 0}
	};
#endif
	pid_file = crm_strdup("/tmp/pingd.pid");

	G_main_add_SignalHandler(
		G_PRIORITY_HIGH, SIGTERM, pingd_shutdown, NULL, NULL);
	
	ping_nodes = g_hash_table_new_full(
                     g_str_hash, g_str_equal,
		     g_hash_destroy_str, g_hash_destroy_str);	

	crm_log_init(basename(argv[0]), LOG_INFO, TRUE, FALSE, argc, argv);
	
	while (1) {
#ifdef HAVE_GETOPT_H
		flag = getopt_long(argc, argv, OPTARGS,
				   long_options, &option_index);
#else
		flag = getopt(argc, argv, OPTARGS);
#endif
		if (flag == -1)
			break;

		switch(flag) {
			case 'V':
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			case 'p':
				pid_file = crm_strdup(optarg);
				break;
			case 'a':
				pingd_attr = crm_strdup(optarg);
				break;
			case 'h':
				do_filter = TRUE;
				fprintf(stdout, "Adding ping host %s", optarg);
				g_hash_table_insert(ping_nodes,
						    crm_strdup(optarg),
						    crm_strdup(optarg));
				break;
			case 's':
				attr_set = crm_strdup(optarg);
				break;
			case 'm':
				attr_multiplier = crm_parse_int(optarg, "1");
				break;
			case 'S':
				attr_section = crm_strdup(optarg);
				break;
			case 'd':
				attr_dampen = crm_strdup(optarg);
				break;
			case 'D':
				daemonize = TRUE;
				break;
			case '?':
				usage(crm_system_name, LSB_EXIT_GENERIC);
				break;
			default:
				printf("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
				crm_err("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
				++argerr;
				break;
		}
	}

	if (optind < argc) {
		crm_err("non-option ARGV-elements: ");
		printf("non-option ARGV-elements: ");
		while (optind < argc) {
			crm_err("%s ", argv[optind++]);
			printf("%s ", argv[optind++]);
		}
		printf("\n");
	}
	if (argerr) {
		usage(crm_system_name, LSB_EXIT_GENERIC);
	}

	crm_make_daemon(crm_system_name, daemonize, pid_file);

	for(lpc = 0; attrd == NULL && lpc < 30; lpc++) {
		crm_debug("attrd registration attempt: %d", lpc);
		sleep(5);
		attrd = init_client_ipc_comms_nodispatch(T_ATTRD);
	}
	
	if(attrd == NULL) {
		crm_err("attrd registration failed");
		cl_flush_logs();
		exit(LSB_EXIT_GENERIC);
	}
	
#if SUPPORT_HEARTBEAT
	if(register_with_ha() == FALSE) {
		crm_err("HA registration failed");
		cl_flush_logs();
		exit(LSB_EXIT_GENERIC);
	}
#endif	
	crm_info("Starting %s", crm_system_name);
	mainloop = g_main_new(FALSE);
	g_main_run(mainloop);
	
	crm_info("Exiting %s", crm_system_name);	
	return 0;
}


static void count_ping_nodes(gpointer key, gpointer value, gpointer user_data)
{
	int *num_active = user_data;
	CRM_CHECK(num_active != NULL, return);

	if(need_shutdown) {
		return;
	}
	
	if(safe_str_eq(value, PINGSTATUS)) {
		(*num_active)++;
	} else if(safe_str_eq(value, LINKUP)) {
		(*num_active)++;
	}
}

void
send_update(void) 
{
	int num_active = 0;
	HA_Message *update = ha_msg_new(4);
	ha_msg_add(update, F_TYPE, T_ATTRD);
	ha_msg_add(update, F_ORIG, crm_system_name);
	ha_msg_add(update, F_ATTRD_TASK, "update");
	ha_msg_add(update, F_ATTRD_ATTRIBUTE, pingd_attr);

	g_hash_table_foreach(ping_nodes, count_ping_nodes, &num_active);
	crm_info("%d active ping nodes", num_active);

	ha_msg_add_int(update, F_ATTRD_VALUE, attr_multiplier*num_active);
	
	if(attr_set != NULL) {
		ha_msg_add(update, F_ATTRD_SET,     attr_set);
	}
	if(attr_section != NULL) {
		ha_msg_add(update, F_ATTRD_SECTION, attr_section);
	}
	if(attr_dampen != NULL) {
		ha_msg_add(update, F_ATTRD_DAMPEN,  attr_dampen);
	}

	if(send_ipc_message(attrd, update) == FALSE) {
		crm_err("Could not send update");
		exit(1);
	}
	crm_msg_del(update);
}

void
pingd_nstatus_callback(
	const char *node, const char * status,	void* private_data)
{
	crm_notice("Status update: Ping node %s now has status [%s]",
		   node, status);
	
	if(g_hash_table_lookup(ping_nodes, node) != NULL) {
		g_hash_table_replace(
			ping_nodes, crm_strdup(node), crm_strdup(status));
		send_update();
	}
}

void
pingd_lstatus_callback(const char *node, const char *lnk, const char *status,
		       void *private)
{
	crm_notice("Status update: Ping node %s now has status [%s]",
		   node, status);
	pingd_nstatus_callback(node, status, private);
}

void
do_node_walk(ll_cluster_t *hb_cluster)
{
	const char *ha_node = NULL;

	/* Async get client status information in the cluster */
	crm_debug_2("Invoked");
	crm_debug_3("Requesting an initial dump of CRMD client_status");
	hb_cluster->llc_ops->client_status(
		hb_cluster, NULL, CRM_SYSTEM_CRMD, -1);
	
	crm_info("Requesting the list of configured nodes");
	hb_cluster->llc_ops->init_nodewalk(hb_cluster);

	do {
		const char *ha_node_type = NULL;
		const char *ha_node_status = NULL;

		ha_node = hb_cluster->llc_ops->nextnode(hb_cluster);
		if(ha_node == NULL) {
			continue;
		}
		
		ha_node_type = hb_cluster->llc_ops->node_type(
			hb_cluster, ha_node);
		if(safe_str_neq(PINGNODE, ha_node_type)) {
			crm_debug("Node %s: skipping '%s'",
				  ha_node, ha_node_type);
			continue;
		}

		if(do_filter
		   && g_hash_table_lookup(ping_nodes, ha_node) == NULL) {
			crm_debug("Filtering: %s", ha_node);
			continue;
		}
		
		ha_node_status = hb_cluster->llc_ops->node_status(
			hb_cluster, ha_node);

		crm_debug("Adding: %s=%s", ha_node, ha_node_status);
		g_hash_table_replace(ping_nodes, crm_strdup(ha_node),
				     crm_strdup(ha_node_status));

	} while(ha_node != NULL);

	hb_cluster->llc_ops->end_nodewalk(hb_cluster);
	crm_debug_2("Complete");
	send_update();
}
