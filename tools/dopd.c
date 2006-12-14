/* $Id$ */
/* drbd outdate peer daemon
 * Copyright (C) 2006 LINBIT <http://www.linbit.com/>
 * Written by Rasto Levrinc <rasto@linbit.com>
 *
 * based on ipfail.c and attrd.c
 *
 * This library is free software; you can redistribute it and/or
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

#include <portability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <libgen.h>
#include <heartbeat.h>
#include <ha_msg.h>
#include <hb_api.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/GSource.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/coredumps.h>
#include <dopd.h>
#include <clplumbing/cl_misc.h>

#include <crm/crm.h>
#include <crm/common/ipc.h>


const char *node_name;	   /* The node we are connected to	      */
int node_stable;	   /* Other node stable?		      */
int quitnow = 0;	   /* Allows a signal to break us out of loop */
GMainLoop *mainloop;	   /* Reference to the mainloop for events    */
ll_cluster_t *dopd_cluster_conn;

/* only one client can be connected at a time */

typedef struct dopd_client_s
{
	char  *id;

	IPC_Channel *channel;
	GCHSource   *source;
} dopd_client_t;

IPC_Channel *CURR_CLIENT_CHANNEL = NULL;

/* send_message_to_the_peer()
 * send message with drbd resource to other node.
 */
static gboolean
send_message_to_the_peer(const char *drbd_peer, const char *drbd_resource)
{
	HA_Message *msg = NULL;

	crm_info("sending start_outdate message to the other node %s -> %s",
		  node_name, drbd_peer);

	msg = ha_msg_new(3);
	ha_msg_add(msg, F_TYPE, "start_outdate");
	ha_msg_add(msg, F_ORIG, node_name);
	ha_msg_add(msg, F_DOPD_RES, drbd_resource);

	crm_debug("sending [start_outdate res: %s] to node: %s", 
		  drbd_resource, drbd_peer);
	dopd_cluster_conn->llc_ops->sendnodemsg(dopd_cluster_conn, msg, drbd_peer);
	ha_msg_del(msg);

	return TRUE;
}

/* msg_start_outdate()
 * got start_outdate message with resource from other node. Execute drbd
 * outdate command, convert return code and send message to other node
 * with return code.
 *
 * Conversion of return codes:
 *     0 => 4
 *     5 => 3
 *    17 => 6
 * other => 5
 */
void
msg_start_outdate(struct ha_msg *msg, void *private)
{
	ll_cluster_t *hb = (ll_cluster_t *)private;
	int rc = 5;
	int command_ret;

	char rc_string[4];
	HA_Message *msg2 = NULL;
	const char *drbd_resource = ha_msg_value(msg, F_DOPD_RES);
	char *command;

	/* execute outdate command */
	crm_malloc0(command, strlen(OUTDATE_COMMAND) + 1 + strlen(drbd_resource) + 1);
	strcpy(command, OUTDATE_COMMAND);
	strcat(command, " ");
	strcat(command, drbd_resource);
	crm_debug("command: %s", command);
	command_ret = system(command) >> 8;

	/* convert return code */
	if (command_ret == 0)
		rc = 4;
	else if (command_ret == 5)
		rc = 3;
	else if (command_ret == 17)
		rc = 6;
	else
		crm_info("unknown exit code from %s: %i",
				command, command_ret);
	crm_free(command);

	crm_debug("msg_start_outdate: %s, command rc: %i, rc: %i",
			 ha_msg_value(msg, F_ORIG), command_ret, rc);
	sprintf(rc_string, "%i", rc);

	crm_info("sending return code: %s, %s -> %s\n",
			rc_string, node_name, ha_msg_value(msg, F_ORIG));
	/* send return code to oder node */
	msg2 = ha_msg_new(3);
	ha_msg_add(msg2, F_TYPE, "outdate_rc");
	ha_msg_add(msg2, F_DOPD_VALUE, rc_string);
	ha_msg_add(msg2, F_ORIG, node_name);

	hb->llc_ops->sendnodemsg(hb, msg2, ha_msg_value(msg, F_ORIG));
	ha_msg_del(msg2);
}

/* msg_outdate_rc()
 * got outdate_rc message with return code from other node. Send the 
 * return code to the outdater client.
 */
void
msg_outdate_rc(struct ha_msg *msg_in, void *private)
{
	HA_Message *msg_out;
	const char *rc_string = ha_msg_value(msg_in, F_DOPD_VALUE);

	if (CURR_CLIENT_CHANNEL == NULL)
		return;
	crm_debug("msg_outdate_rc: %s", rc_string);
	msg_out = ha_msg_new(3);
	ha_msg_add(msg_out, F_TYPE, "outdater_rc");
	ha_msg_add(msg_out, F_ORIG, node_name);
	ha_msg_add(msg_out, F_DOPD_VALUE, rc_string);

	if (send_ipc_message(CURR_CLIENT_CHANNEL, msg_out) == FALSE) {
		crm_err("Could not send message to the client");
	}
	CURR_CLIENT_CHANNEL = NULL;
}

/* check_drbd_peer()
 * walk the nodes and return TRUE if peer is not this node and it exists.
 */
gboolean
check_drbd_peer(const char *drbd_peer)
{
	const char *node;
	gboolean found = FALSE;
	if (!strcmp(drbd_peer, node_name)) {
		crm_warn("drbd peer node %s is me!\n", drbd_peer);
		return FALSE;
	}

	crm_debug("Starting node walk");
	if (dopd_cluster_conn->llc_ops->init_nodewalk(dopd_cluster_conn) != HA_OK) {
		crm_warn("Cannot start node walk");
		crm_warn("REASON: %s", dopd_cluster_conn->llc_ops->errmsg(dopd_cluster_conn));
		return FALSE;
	}
	while((node = dopd_cluster_conn->llc_ops->nextnode(dopd_cluster_conn)) != NULL) {
		crm_debug("Cluster node: %s: status: %s", node,
			    dopd_cluster_conn->llc_ops->node_status(dopd_cluster_conn, node));

		/* Look for the peer */
		if (!strcmp("normal", dopd_cluster_conn->llc_ops->node_type(dopd_cluster_conn, node))
			&& !strcmp(node, drbd_peer)) {
			crm_debug("node %s found\n", node);
			found = TRUE;
			break;
		}
	}
	if (dopd_cluster_conn->llc_ops->end_nodewalk(dopd_cluster_conn) != HA_OK) {
		crm_info("Cannot end node walk");
		crm_info("REASON: %s", dopd_cluster_conn->llc_ops->errmsg(dopd_cluster_conn));
	}

	if (found == FALSE)
		crm_warn("drbd peer %s was not found\n", drbd_peer);
	return found;
}

/* outdater_callback()
 * got message from outdater client with drbd resource, it will be sent
 * to the other node.
 */
static gboolean
outdater_callback(IPC_Channel *client, gpointer user_data)
{
	int lpc = 0;
	HA_Message *msg = NULL;
	HA_Message *msg_client = NULL;
	const char *drbd_peer = NULL;
	const char *drbd_resource = NULL;
	dopd_client_t *curr_client = (dopd_client_t*)user_data;
	gboolean stay_connected = TRUE;

	crm_debug("invoked: %s", curr_client->id);

	/* allow one connection from outdater at a time */
	if (CURR_CLIENT_CHANNEL != NULL &&
	    CURR_CLIENT_CHANNEL != curr_client->channel) {
		crm_debug("one client already connected");
		return FALSE;
	}
	CURR_CLIENT_CHANNEL = curr_client->channel;

	while (IPC_ISRCONN(client)) {
		if(client->ops->is_message_pending(client) == 0) {
			break;
		}

		msg = msgfromIPC_noauth(client);
		if (msg == NULL) {
			crm_debug("%s: no message this time",
				  curr_client->id);
			continue;
		}

		lpc++;

		crm_debug("Processing msg from %s", curr_client->id);
		crm_debug("Got message from (%s). (peer: %s, res :%s)",
				ha_msg_value(msg, F_ORIG),
				ha_msg_value(msg, F_OUTDATER_PEER),
				ha_msg_value(msg, F_OUTDATER_RES));

		drbd_resource = ha_msg_value(msg, F_OUTDATER_RES);
		drbd_peer = ha_msg_value(msg, F_OUTDATER_PEER);
		if (check_drbd_peer(drbd_peer))
			send_message_to_the_peer(drbd_peer, drbd_resource);
		else {
			/* wrong peer was specified,
			   send return code 5 to the client */
			msg_client = ha_msg_new(3);
			ha_msg_add(msg_client, F_TYPE, "outdate_rc");
			ha_msg_add(msg_client, F_ORIG, node_name);
			ha_msg_add(msg_client, F_DOPD_VALUE, "5");
			msg_outdate_rc(msg_client, NULL);
		}

		crm_msg_del(msg);
		msg = NULL;

		if(client->ch_status != IPC_CONNECT) {
			break;
		}
	}
	crm_debug("Processed %d messages", lpc);
	if (client->ch_status != IPC_CONNECT) {
		stay_connected = FALSE;
	}
	return stay_connected;
}

/* outdater_ipc_connection_destroy()
 * clean client struct
 */
static void
outdater_ipc_connection_destroy(gpointer user_data)
{
	dopd_client_t *client = (dopd_client_t*)user_data;

	if (client == NULL)
		return;

	if (client->source != NULL) {
		crm_debug("Deleting %s (%p) from mainloop",
				client->id, client->source);
		G_main_del_IPC_Channel(client->source);
		client->source = NULL;
	}
	crm_free(client->id);
	if (client->channel == CURR_CLIENT_CHANNEL) {
		crm_debug("connection from client closed");
		CURR_CLIENT_CHANNEL = NULL;
	}
	crm_free(client);
	return;
}

/* outdater_client_connect()
 * outdater is connected set outdater_callback.
 */
static gboolean
outdater_client_connect(IPC_Channel *channel, gpointer user_data)
{
	dopd_client_t *new_client = NULL;
	crm_debug("Connecting channel");
	if(channel == NULL) {
		crm_err("Channel was NULL");
		return FALSE;

	} else if(channel->ch_status != IPC_CONNECT) {
		crm_err("Channel was disconnected");
		return FALSE;
	}

	crm_malloc0(new_client, sizeof(dopd_client_t));
	new_client->channel = channel;
	crm_malloc0(new_client->id, 10);
	strcpy(new_client->id, "outdater");

	new_client->source = G_main_add_IPC_Channel(
		G_PRIORITY_DEFAULT, channel, FALSE, outdater_callback,
		new_client, outdater_ipc_connection_destroy);

	crm_debug("Client %s (%p) connected",
			  new_client->id,
			  new_client->source);

	return TRUE;
}

static void
outdater_client_destroy(gpointer user_data)
{
	crm_info("ipc server destroy");
}

int
is_stable(ll_cluster_t *hb)
{
	const char *resources = hb->llc_ops->get_resources(hb);
	if (!resources)
		/* Heartbeat is not providing resource management */
		return -1;

	if (!strcmp(resources, "transition"))
		return 0;

	return 1;
}

/* set_callbacks()
 * set callbacks for communication between two nodes
 */
void
set_callbacks(ll_cluster_t *hb)
{
	/* Add each of the callbacks we use with the API */
	if (hb->llc_ops->set_msg_callback(hb, "start_outdate",
					  msg_start_outdate, hb) != HA_OK) {
		crm_err("Cannot set msg_start_outdate callback");
		crm_err("REASON: %s", hb->llc_ops->errmsg(hb));
		exit(2);
	}

	if (hb->llc_ops->set_msg_callback(hb, "outdate_rc",
					  msg_outdate_rc, hb) != HA_OK) {
		crm_err("Cannot set msg_outdate_rc callback");
		crm_err("REASON: %s", hb->llc_ops->errmsg(hb));
		exit(2);
	}
}

void
set_signals(ll_cluster_t *hb)
{
	/* Setup the various signals */

	CL_SIGINTERRUPT(SIGINT, 1);
	CL_SIGNAL(SIGINT, gotsig);
	CL_SIGINTERRUPT(SIGTERM, 1);
	CL_SIGNAL(SIGTERM, gotsig);

	crm_debug("Setting message signal");
	if (hb->llc_ops->setmsgsignal(hb, 0) != HA_OK) {
		crm_err("Cannot set message signal");
		crm_err("REASON: %s", hb->llc_ops->errmsg(hb));
		exit(13);
	}
}

void
gotsig(int nsig)
{
	(void)nsig;
	quitnow = 1;
}

/* Used to handle the API in the gmainloop */
gboolean
dopd_dispatch(IPC_Channel* ipc, gpointer user_data)
{
	struct ha_msg *reply;
	ll_cluster_t *hb = user_data;

	reply = hb->llc_ops->readmsg(hb, 0);

	if (reply != NULL) {
		ha_msg_del(reply); reply=NULL;
		return TRUE;
	}
	return TRUE;
}

void
dopd_dispatch_destroy(gpointer user_data)
{
	return;
}

gboolean
dopd_timeout_dispatch(gpointer user_data)
{
	ll_cluster_t *hb = user_data;

	if (quitnow) {
		g_main_quit(mainloop);
		return FALSE;
	}

	if (hb->llc_ops->msgready(hb)) {
		return dopd_dispatch(NULL, user_data);
	}
	return TRUE;
}

/* Sign in to the API */
void
open_api(ll_cluster_t *hb)
{
	crm_debug("Signing in with heartbeat");
	if (hb->llc_ops->signon(hb, "dopd")!= HA_OK) {
		crm_err("Cannot sign on with heartbeat");
		crm_err("REASON: %s", hb->llc_ops->errmsg(hb));
		exit(1);
	}
}

/* Log off of the API and clean up */
void
close_api(ll_cluster_t *hb)
{
	if (hb->llc_ops->signoff(hb, FALSE) != HA_OK) {
		crm_err("Cannot sign off from heartbeat.");
		crm_err("REASON: %s", hb->llc_ops->errmsg(hb));
		exit(14);
	}
	if (hb->llc_ops->delete(hb) != HA_OK) {
		crm_err("REASON: %s", hb->llc_ops->errmsg(hb));
		crm_err("Cannot delete API object.");
		exit(15);
	}
}

int
main(int argc, char **argv)
{
	unsigned fmask;
	char pid[10];
	char *bname, *parameter;
	IPC_Channel *apiIPC;
	int rc;

	/* Get the name of the binary for logging purposes */
	bname = ha_strdup(argv[0]);
	crm_log_init(bname);

	dopd_cluster_conn = ll_cluster_new("heartbeat");

	memset(pid, 0, sizeof(pid));
	snprintf(pid, sizeof(pid), "%ld", (long)getpid());
	crm_debug("PID=%s", pid);

	open_api(dopd_cluster_conn);

	node_stable = is_stable(dopd_cluster_conn);
	if (node_stable == -1) {
		crm_err("No managed resources");
		exit(100);
	}

	/* Obtain our local node name */
	node_name = dopd_cluster_conn->llc_ops->get_mynodeid(dopd_cluster_conn);
	if (node_name == NULL) {
		crm_err("Cannot get my nodeid");
		crm_err("REASON: %s", dopd_cluster_conn->llc_ops->errmsg(dopd_cluster_conn));
		exit(19);
	}
	crm_debug("[We are %s]", node_name);

	/* See if we should drop cores somewhere odd... */
	parameter = dopd_cluster_conn->llc_ops->get_parameter(dopd_cluster_conn, KEY_COREROOTDIR);
	if (parameter) {
		cl_set_corerootdir(parameter);
		cl_cdtocoredir();
	}
	cl_cdtocoredir();


	set_callbacks(dopd_cluster_conn);

	fmask = LLC_FILTER_DEFAULT;

	crm_debug("Setting message filter mode");
	if (dopd_cluster_conn->llc_ops->setfmode(dopd_cluster_conn, fmask) != HA_OK) {
		crm_err("Cannot set filter mode");
		crm_err("REASON: %s", dopd_cluster_conn->llc_ops->errmsg(dopd_cluster_conn));
		exit(8);
	}

	set_signals(dopd_cluster_conn);

	crm_debug("Waiting for messages...");
	errno = 0;

	mainloop = g_main_new(TRUE);

	apiIPC = dopd_cluster_conn->llc_ops->ipcchan(dopd_cluster_conn);

	/* Watch the API IPC for input */
	G_main_add_IPC_Channel(G_PRIORITY_HIGH, apiIPC, FALSE,
			       dopd_dispatch, (gpointer)dopd_cluster_conn,
			       dopd_dispatch_destroy);

	Gmain_timeout_add_full(G_PRIORITY_DEFAULT, 1000,
				dopd_timeout_dispatch, (gpointer)dopd_cluster_conn,
				dopd_dispatch_destroy);
	rc = init_server_ipc_comms(
			ha_strdup(T_OUTDATER),
			outdater_client_connect,
			outdater_client_destroy);
	if (rc != 0)
		crm_err("Could not start IPC server");

	g_main_run(mainloop);
	g_main_destroy(mainloop);

	if (!quitnow && errno != EAGAIN && errno != EINTR) {
		crm_err("read_hb_msg returned NULL");
		crm_err("REASON: %s", dopd_cluster_conn->llc_ops->errmsg(dopd_cluster_conn));
	}

	close_api(dopd_cluster_conn);

	return 0;
}
