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

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/cluster.h>

#include <crm/stonith-ng.h>
#include <crm/stonith-ng-internal.h>
#include <crm/common/xml.h>

#include <crm/common/util.h>
#include <internal.h>


typedef struct st_query_result_s
{
	char *host;
	int devices;
        GListPtr device_list;

} st_query_result_t;

GHashTable *remote_op_list = NULL;
void call_remote_stonith(remote_fencing_op_t *op, st_query_result_t *peer);
extern xmlNode *stonith_create_op(
    int call_id, const char *token, const char *op, xmlNode *data, int call_options);

static void free_remote_query(gpointer data)
{
    if(data) {
	st_query_result_t *query = data;
        crm_trace("Free'ing query result from %s", query->host);
	free(query->host);
	free(query);
    }
}

static void free_remote_op(gpointer data)
{
    remote_fencing_op_t *op = data;

    crm_trace("Free'ing op %s for %s", op->id, op->target);
    crm_log_xml_debug(op->request, "Destroying");

    free(op->id);
    free(op->action);
    free(op->target);
    free(op->client_id);
    free(op->originator);

    if(op->query_timer) {
	g_source_remove(op->query_timer);
    }
    if(op->op_timer) {
	g_source_remove(op->op_timer);
    }
    if(op->query_results) {
	slist_destroy(st_query_result_t, result, op->query_results,
		      free_remote_query(result);
	    );
    }
    if(op->request) {
	free_xml(op->request);
	op->request = NULL;
    }
    free(op);
}

static void remote_op_done(remote_fencing_op_t *op, xmlNode *data, int rc) 
{
    xmlNode *reply = NULL;
    xmlNode *local_data = NULL;
    xmlNode *notify_data = NULL;

    op->completed = time(NULL);
    
    if(op->query_timer) {
	g_source_remove(op->query_timer);
	op->query_timer = 0;
    }
    if(op->op_timer) {
	g_source_remove(op->op_timer);
	op->op_timer = 0;
    }
    
    if(data == NULL) {
	data = create_xml_node(NULL, "remote-op");
	local_data = data;

    } else {
	op->delegate = crm_element_value_copy(data, F_ORIG);
    }
    
    crm_xml_add_int(data, "state", op->state);
    crm_xml_add(data, F_STONITH_TARGET,    op->target);
    crm_xml_add(data, F_STONITH_OPERATION, op->action); 

    if(op->request != NULL) {
	reply = stonith_construct_reply(op->request, NULL, data, rc);
	crm_xml_add(reply, F_STONITH_DELEGATE,  op->delegate);
	
        do_crm_log(rc==stonith_ok?LOG_NOTICE:LOG_ERR,
                   "Operation %s of %s by %s for %s[%s]: %s",
                   op->action, op->target, op->delegate?op->delegate:"<no-one>",
                   op->originator, op->client_id, stonith_error2string(rc));

    } else {
        crm_err("Already sent notifications for '%s of %s by %s' (op=%s, for=%s, state=%d): %s",
                op->action, op->target, op->delegate, op->id, op->client_id, op->state,
                stonith_error2string(rc));
	return;
    }
    
    if(reply) {
	do_local_reply(reply, op->client_id, op->call_options & st_opt_sync_call, FALSE);
    }

    /* Do notification with a clean data object */
    notify_data = create_xml_node(NULL, "st-data");
    crm_xml_add_int(notify_data, "state",	  op->state);
    crm_xml_add_int(notify_data, F_STONITH_RC,    rc);
    crm_xml_add(notify_data, F_STONITH_TARGET,    op->target);
    crm_xml_add(notify_data, F_STONITH_OPERATION, op->action); 
    crm_xml_add(notify_data, F_STONITH_DELEGATE,  op->delegate);
    crm_xml_add(notify_data, F_STONITH_REMOTE,    op->id);
    crm_xml_add(notify_data, F_STONITH_ORIGIN,    op->originator);
    
    do_stonith_notify(0, STONITH_OP_FENCE, rc, notify_data, NULL);
    
    free_xml(notify_data);
    free_xml(local_data);
    free_xml(reply);

    /* Free non-essential parts of the record
     * Keep the record around so we can query the history
     */
    if(op->query_results) {
	slist_destroy(st_query_result_t, result, op->query_results,
		      free_remote_query(result);
	    );
	op->query_results = NULL;
    }

    if(op->request) {
	free_xml(op->request);
	op->request = NULL;
    }
}


static gboolean remote_op_timeout(gpointer userdata)
{
    remote_fencing_op_t *op = userdata;
    op->query_timer = 0;

    if(op->state == st_done) {
	crm_debug("Action %s (%s) for %s already completed", op->action, op->id, op->target);
	return FALSE;
    }
    
    crm_debug("Action %s (%s) for %s timed out", op->action, op->id, op->target);
    remote_op_done(op, NULL, st_err_timeout);
    op->state = st_failed;

    return FALSE;
}

static gboolean remote_op_query_timeout(gpointer data)
{
    remote_fencing_op_t *op = data;

    op->query_timer = 0;
    if(op->state == st_done) {
	crm_debug("Operation %s for %s already completed", op->id, op->target);
	
    } else if(op->state == st_exec) {
	crm_debug("Operation %s for %s already in progress", op->id, op->target);
	
    } else if(op->query_results) {
	crm_debug("Query %s for %s complete: %d", op->id, op->target, op->state);
	call_remote_stonith(op, NULL);

    } else {
	if(op->op_timer) {
	    g_source_remove(op->op_timer);
	    op->op_timer = 0;
	}
	remote_op_timeout(op);
    }
    
    
    return FALSE;
}

static int stonith_topology_next(remote_fencing_op_t *op) 
{
    stonith_topology_t *tp = NULL;
    if(op->target) {
        /* Queries don't have a target set */
        tp = g_hash_table_lookup(topology, op->target);
    }
    if(tp == NULL) {
        return stonith_ok;
    }

    set_bit(op->call_options, st_opt_topology);

    do {
        op->level++;

    } while(op->level < ST_LEVEL_MAX && tp->levels[op->level] == NULL);

    if(op->level < ST_LEVEL_MAX) {
        crm_trace("Attempting fencing level %d for %s (%d devices)", op->level, op->target, g_list_length(tp->levels[op->level]));
        op->devices = tp->levels[op->level];
        return stonith_ok;
    }

    crm_notice("All fencing options for %s failed", op->target);
    return st_err_invalid_level;
}

void *create_remote_stonith_op(const char *client, xmlNode *request, gboolean peer)
{
    remote_fencing_op_t *op = NULL;
    xmlNode *dev = get_xpath_object("//@"F_STONITH_TARGET, request, LOG_TRACE);
    
    if(remote_op_list == NULL) {
	remote_op_list = g_hash_table_new_full(
	    crm_str_hash, g_str_equal, NULL, free_remote_op);
    }
    
    if(peer && dev) {
	const char *peer_id = crm_element_value(dev, F_STONITH_REMOTE);
	CRM_CHECK(peer_id != NULL, return NULL);
	
	op = g_hash_table_lookup(remote_op_list, peer_id);
	if(op) {
	    crm_debug("%s already exists", peer_id);
	    return op;
	}
    }
    
    op = calloc(1, sizeof(remote_fencing_op_t));
    crm_element_value_int(request, F_STONITH_TIMEOUT, (int*)&(op->base_timeout));

    if(peer && dev) {
	op->id = crm_element_value_copy(dev, F_STONITH_REMOTE);
        crm_trace("Recorded new stonith op: %s", op->id);

    } else {
	op->id = crm_generate_uuid();
        crm_trace("Generated new stonith op: %s", op->id);
    }

    g_hash_table_replace(remote_op_list, op->id, op);
    CRM_LOG_ASSERT(g_hash_table_lookup(remote_op_list, op->id) != NULL);

    op->state = st_query;
    op->action = crm_element_value_copy(dev, F_STONITH_ACTION);
    op->originator = crm_element_value_copy(dev, "src");

    if(op->originator == NULL) {
	/* Local request */
	op->originator = crm_strdup(stonith_our_uname);
    }

    if(client) {
        op->client_id = crm_strdup(client);
    }
    op->target = crm_element_value_copy(dev, F_STONITH_TARGET);
    op->request = copy_xml(request); /* TODO: Figure out how to avoid this */
    crm_element_value_int(request, F_STONITH_CALLOPTS, (int*)&(op->call_options));

    if(op->call_options & st_opt_cs_nodeid) {
        int nodeid = crm_atoi(op->target, NULL);
        crm_node_t *node = crm_get_peer(nodeid, NULL);

        /* Ensure the conversion only happens once */
        op->call_options &= ~st_opt_cs_nodeid;

        if(node) {
            free(op->target);
            op->target = crm_strdup(node->uname);
        }
    }

    if(stonith_topology_next(op) != stonith_ok) {
        op->state = st_failed;
    }
    return op;
}


remote_fencing_op_t *initiate_remote_stonith_op(stonith_client_t *client, xmlNode *request, gboolean manual_ack) 
{
    xmlNode *query = NULL;
    remote_fencing_op_t *op = NULL;

    op = create_remote_stonith_op(client->id, request, FALSE);
    query = stonith_create_op(0, op->id, STONITH_OP_QUERY, NULL, 0);

    if(!manual_ack) {
        op->op_timer = g_timeout_add(1200*op->base_timeout, remote_op_timeout, op);
        op->query_timer = g_timeout_add(100*op->base_timeout, remote_op_query_timeout, op);

    } else {
        crm_xml_add(query, F_STONITH_DEVICE, "manual_ack");    
    }
    
    crm_xml_add(query, F_STONITH_REMOTE, op->id);
    crm_xml_add(query, F_STONITH_TARGET, op->target);
    crm_xml_add(query, F_STONITH_ACTION, op->action);    
    crm_xml_add(query, F_STONITH_CLIENTID, op->client_id);    
    crm_xml_add_int(query, F_STONITH_TIMEOUT, op->base_timeout);
    
    crm_info("Initiating remote operation %s for %s: %s", op->action, op->target, op->id);
    CRM_CHECK(op->action, return NULL);
    
    send_cluster_message(NULL, crm_msg_stonith_ng, query, FALSE);

    free_xml(query);
    return op;
}

static gint sort_strings(gconstpointer a, gconstpointer b)
{
    return strcmp(a, b);
}

static st_query_result_t *stonith_choose_peer(remote_fencing_op_t *op)
{
    GListPtr iter = NULL;
    do {
        if(op->devices) {
            crm_trace("Checking for someone to fence %s with %s", op->target, (char*)op->devices->data);
        } else {
            crm_trace("Checking for someone to fence %s", op->target);
        }
        for(iter = op->query_results; iter != NULL; iter = iter->next) {
            st_query_result_t *peer = iter->data;
            if(is_set(op->call_options, st_opt_topology)) {
                /* Do they have the next device of the current fencing level? */
                GListPtr match = NULL;
                if(op->devices) {
                    match = g_list_find_custom(peer->device_list, op->devices->data, sort_strings);
                }
                if(match) {
                    crm_trace("Removing %s from %s (%d remaining)", (char*)match->data, peer->host, g_list_length(peer->device_list));
                    peer->device_list = g_list_remove(peer->device_list, match->data);
                    return peer;
                }

            } else if(peer && peer->devices > 0) {
                /* No topology: Use the current best peer */
                crm_trace("Simple fencing");
                return peer;
            }
        }

        /* Try the next fencing level if there is one */
    } while(is_set(op->call_options, st_opt_topology)
            && stonith_topology_next(op) == stonith_ok);

    if(op->devices) {
        crm_trace("Couldn't find anyone to fence %s with %s", op->target, (char*)op->devices->data);
    } else {
        crm_trace("Couldn't find anyone to fence %s", op->target);
    }

    return NULL;
}

void call_remote_stonith(remote_fencing_op_t *op, st_query_result_t *peer) 
{
    const char *device = NULL;

    op->state = st_exec;

    if(peer == NULL) {
        peer = stonith_choose_peer(op);
    }

    if(is_set(op->call_options, st_opt_topology)) {
        device = op->devices->data;
    }
        
    if(peer) {
        xmlNode *query = stonith_create_op(0, op->id, STONITH_OP_FENCE, NULL, 0);;
        crm_xml_add(query, F_STONITH_REMOTE, op->id);
        crm_xml_add(query, F_STONITH_TARGET, op->target);    
        crm_xml_add(query, F_STONITH_ACTION, op->action);    
        crm_xml_add(query, F_STONITH_CLIENTID, op->client_id);
        crm_xml_add_int(query, F_STONITH_TIMEOUT, op->base_timeout/4); /* Allow a quarter of the timeout for querying */

        if(device) {
            crm_info("Requesting that %s perform op %s %s with %s", peer->host, op->action, op->target, device);
            crm_xml_add(query, F_STONITH_DEVICE, device);
            crm_xml_add(query, F_STONITH_MODE, "slave");

        } else {
            crm_info("Requesting that %s perform op %s %s", peer->host, op->action, op->target);
            crm_xml_add(query, F_STONITH_MODE, "smart");
        }

	send_cluster_message(peer->host, crm_msg_stonith_ng, query, FALSE);
        free_xml(query);
        return;

    } else if(op->query_timer == 0) {
	/* We've exhausted all available peers */
	crm_info("No remaining peers capable of terminating %s", op->target);
	remote_op_timeout(op);
	
    } else if(device) {
	crm_info("Waiting for additional peers capable of terminating %s with %s", op->target, device);

    } else {
	crm_info("Waiting for additional peers capable of terminating %s", op->target);
    }
    
    free_remote_query(peer);
}

static gint sort_peers(gconstpointer a, gconstpointer b)
{
    const st_query_result_t *peer_a = a;
    const st_query_result_t *peer_b = a;

    if(peer_a->devices > peer_b->devices) {
	return -1;

    } else if(peer_a->devices > peer_b->devices) {
	return 1;
    }
    return 0;
}

int process_remote_stonith_query(xmlNode *msg) 
{
    int devices = 0;
    const char *id = NULL;
    const char *host = NULL;
    remote_fencing_op_t *op = NULL;
    st_query_result_t *result = NULL;
    xmlNode *dev = get_xpath_object("//@"F_STONITH_REMOTE, msg, LOG_ERR);
    xmlNode *child = NULL;
    
    CRM_CHECK(dev != NULL, return st_err_internal);

    id = crm_element_value(dev, F_STONITH_REMOTE);
    CRM_CHECK(id != NULL, return st_err_internal);
    
    dev = get_xpath_object("//@st-available-devices", msg, LOG_ERR);
    CRM_CHECK(dev != NULL, return st_err_internal);
    crm_element_value_int(dev, "st-available-devices", &devices);

    op = g_hash_table_lookup(remote_op_list, id);
    if(op == NULL) {
	crm_debug("Unknown or expired remote op: %s", id);
	return st_err_unknown_operation;
    }

    op->replies++;
    host = crm_element_value(msg, F_ORIG);

    if(devices <= 0) {
        /* If we're doing 'known' then we might need to fire anyway */
        crm_trace("Query result from %s (%d devices)", host, devices);
        return stonith_ok;

    } else if(op->call_options & st_opt_allow_suicide) {
        crm_trace("Allowing %s to potentialy fence itself", op->target);

    } else if(safe_str_eq(host, op->target)) {
        crm_info("Ignoring reply from %s, hosts are not permitted to commit suicide", op->target);
        return stonith_ok;
    }

    crm_debug("Query result from %s (%d devices)", host, devices);
    result = calloc(1, sizeof(st_query_result_t));
    result->host = crm_strdup(host);
    result->devices = devices;

    for (child = __xml_first_child(dev); child != NULL; child = __xml_next(child)) {
        const char *device = ID(child);
        if(device) {
            result->device_list = g_list_prepend(result->device_list, crm_strdup(device));
        }
    }

    CRM_CHECK(devices == g_list_length(result->device_list),
              crm_err("Mis-match: Query claimed to have %d devices but %d found", devices, g_list_length(result->device_list)));

    op->query_results = g_list_insert_sorted(op->query_results, result, sort_peers);

    if(op->state == st_query && is_set(op->call_options, st_opt_all_replies) == FALSE) {
        call_remote_stonith(op, result);

    } else if(op->state == st_done) {
        crm_info("Discarding query result from %s (%d devices): Operation is in state %d",
                 result->host, result->devices, op->state);
    }

    return stonith_ok;
}

int process_remote_stonith_exec(xmlNode *msg) 
{
    int rc = 0;
    const char *id = NULL;
    remote_fencing_op_t *op = NULL;
    xmlNode *dev = get_xpath_object("//@"F_STONITH_REMOTE, msg, LOG_ERR);

    CRM_CHECK(dev != NULL, return st_err_internal);

    id = crm_element_value(dev, F_STONITH_REMOTE);
    CRM_CHECK(id != NULL, return st_err_internal);
    
    dev = get_xpath_object("//@"F_STONITH_RC, msg, LOG_ERR);
    CRM_CHECK(dev != NULL, return st_err_internal);

    crm_element_value_int(dev, F_STONITH_RC, &rc);

    if(remote_op_list) {
	op = g_hash_table_lookup(remote_op_list, id);
    }

    if(op == NULL && rc == stonith_ok) {
        /* Record successful fencing operations */
        const char *client_id = crm_element_value(msg, F_STONITH_CLIENTID);

        op = create_remote_stonith_op(client_id, msg, TRUE);
    }
    
    if(op == NULL) {
	/* Could be for an event that began before we started */
	/* TODO: Record the op for later querying */
	crm_info("Unknown or expired remote op: %s", id);
	return st_err_unknown_operation;
    }

    if(is_set(op->call_options, st_opt_topology)) {
        if(rc == stonith_ok && op->devices) {
            /* Success, are there any more? */
            crm_notice("Call to %s for %s passed, %s next", (char*)op->devices->data,
                       op->target, op->devices->next?(char*)op->devices->next->data:"<none>");
            op->devices = op->devices->next;

        } else {
            crm_notice("Call to %s for %s failed: %d", (char*)op->devices->data, op->target, rc);
        }
    }
    
    if(rc == stonith_ok && op->devices == NULL) {
        crm_trace("All done for %s", op->target);
	op->state = st_done;
	remote_op_done(op, msg, rc);
	
    } else {
        /* Retry on failure or execute the rest of the topology */
        crm_trace("Next for %s (rc was %d)", op->target, rc);
	call_remote_stonith(op, NULL);
    }
    return rc;
}

int stonith_fence_history(xmlNode *msg, xmlNode **output) 
{
    int rc = 0;
    const char *target = NULL;
    xmlNode *dev = get_xpath_object("//@"F_STONITH_TARGET, msg, LOG_TRACE);

    if(dev) {
        int options = 0;

	target = crm_element_value(dev, F_STONITH_TARGET);
        crm_element_value_int(msg, F_STONITH_CALLOPTS, &options);
        if(target && (options & st_opt_cs_nodeid)) {
            int nodeid = crm_atoi(target, NULL);
            crm_node_t *node = crm_get_peer(nodeid, NULL);
            if(node) {
                target = node->uname;
            }
        }
    }
    *output = create_xml_node(NULL, F_STONITH_HISTORY_LIST);

    if (remote_op_list) {
        GHashTableIter iter;
	remote_fencing_op_t *op = NULL;

	g_hash_table_iter_init(&iter, remote_op_list); 
	while(g_hash_table_iter_next(&iter, NULL, (void**)&op)) {
	    xmlNode *entry = NULL;
	    if (target && strcmp(op->target, target) != 0) {
	        continue;
	    }

	    rc = 0;
	    entry = create_xml_node(*output, STONITH_OP_EXEC);
	    crm_xml_add(entry, F_STONITH_TARGET, op->target);	    
	    crm_xml_add(entry, F_STONITH_ACTION, op->action);
	    crm_xml_add(entry, F_STONITH_ORIGIN, op->originator);
	    crm_xml_add(entry, F_STONITH_DELEGATE, op->delegate);
	    crm_xml_add_int(entry, F_STONITH_DATE, op->completed);
	    crm_xml_add_int(entry, F_STONITH_STATE, op->state);
	}
    }

    return rc;
}

