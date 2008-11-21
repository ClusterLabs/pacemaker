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
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <pwd.h>
#include <glib.h>
#include <bzlib.h>

#include <crm/ais_common.h>
#include "./utils.h"

int in_shutdown = FALSE;
extern int send_cluster_msg_raw(AIS_Message *ais_msg);

void log_ais_message(int level, AIS_Message *msg) 
{
    char *data = get_ais_data(msg);
    do_ais_log(level,
	       "Msg[%d] (dest=%s:%s, from=%s:%s.%d, remote=%s, size=%d): %.90s",
	       msg->id, ais_dest(&(msg->host)), msg_type2text(msg->host.type),
	       ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
	       msg->sender.pid,
	       msg->sender.uname==local_uname?"false":"true",
	       ais_data_len(msg), data);
    ais_free(data);
}

gboolean process_ais_message(AIS_Message *msg) 
{
    char *data = get_ais_data(msg);
    do_ais_log(LOG_NOTICE,
	       "Msg[%d] (dest=%s:%s, from=%s:%s.%d, remote=%s, size=%d): %.90s",
	       msg->id, ais_dest(&(msg->host)), msg_type2text(msg->host.type),
	       ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
	       msg->sender.pid,
	       msg->sender.uname==local_uname?"false":"true",
	       ais_data_len(msg), data);
    ais_free(data);
    return TRUE;
}

static int
ais_string_to_boolean(const char * s)
{
    int rc = 0;
    if(s == NULL) {
	return rc;
    }
    
    if(strcasecmp(s, "true") == 0
       || strcasecmp(s, "on") == 0
       || strcasecmp(s, "yes") == 0
       || strcasecmp(s, "y") == 0
       || strcasecmp(s, "1") == 0) {
	rc = 1;
    }
    return rc;
}

gboolean spawn_child(crm_child_t *child)
{
    int rc = 0;
    int lpc = 0;
    int uid = 0;
    int gid = 0;
    struct rlimit oflimits;
    struct passwd *pwentry = NULL;
    gboolean use_valgrind = FALSE;
    const char *devnull = "/dev/null";
    const char *env_valgrind = getenv("HA_VALGRIND_ENABLED");

    if(child->uid) {
	pwentry = getpwnam(child->uid);
	AIS_CHECK(pwentry != NULL,
		  ais_err("Invalid uid (%s) specified for %s", child->uid, child->name);
		  return TRUE);
	uid = pwentry->pw_uid;
	gid = pwentry->pw_gid;
    }
    
    if(child->command == NULL) {
	ais_info("Nothing to do for child \"%s\"", child->name);
	return TRUE;
    }
    
    child->pid = fork();
    AIS_ASSERT(child->pid != -1);

    if(env_valgrind == NULL) {
	use_valgrind = FALSE;

    } else if(ais_string_to_boolean(env_valgrind)) {
	use_valgrind = TRUE;

    } else if(strstr(env_valgrind, child->name)) {
	use_valgrind = TRUE;	
    }

    if(use_valgrind && strlen(VALGRIND_BIN) == 0) {
	ais_warn("Cannot enable valgrind for %s:"
		 " The location of the valgrind binary is unknown", child->name);
	use_valgrind = FALSE;
    }
    
    if(child->pid > 0) {
	/* parent */
	ais_info("Forked child %d for process %s%s", child->pid, child->name,
		 use_valgrind?" (valgrind enabled)":"");
	return TRUE;
    }
    
    /* Child */
    ais_debug("Executing \"%s (%s)\" (pid %d)",
	      child->command, child->name, (int) getpid());

    if(0 && gid) {
	rc = setgid(gid);
	if(rc < 0) {
	    ais_perror("Could not set group to %d", gid);
	}
    }
    
    if(uid) {
 	rc = setuid(uid);
	if(rc < 0) {
	    ais_perror("Could not set user to %d (%s)", uid, child->uid);
	}
    }
    
    /* A precautionary measure */
    getrlimit(RLIMIT_NOFILE, &oflimits);
    for (; lpc < oflimits.rlim_cur; lpc++) {
	close(lpc);
    }

    (void)open(devnull, O_RDONLY);	/* Stdin:  fd 0 */
    (void)open(devnull, O_WRONLY);	/* Stdout: fd 1 */
    (void)open(devnull, O_WRONLY);	/* Stderr: fd 2 */

    if(use_valgrind) {
	char *opts[] = {
	    ais_strdup(VALGRIND_BIN),
	    ais_strdup(child->command),
	    NULL
	};
	(void)execvp(VALGRIND_BIN, opts);

    } else {
	char *opts[] = { ais_strdup(child->command), NULL };
	(void)execvp(child->command, opts);
    }

    ais_perror("FATAL: Cannot exec %s", child->command);
    exit(100);
    return TRUE; /* never reached */
}

gboolean
stop_child(crm_child_t *child, int signal)
{
    if(signal == 0) {
	signal = SIGTERM;
    }

    if(child->command == NULL) {
	ais_info("Nothing to do for child \"%s\"", child->name);
	return TRUE;
    }
    
    ais_debug("Stopping CRM child \"%s\"", child->name);
    
    if (child->pid <= 0) {
	ais_debug_2("Client %s not running", child->name);
	return TRUE;
    }
    
    errno = 0;
    if(kill(child->pid, signal) == 0) {
	ais_notice("Sent -%d to %s: [%d]", signal, child->name, child->pid);
	
    } else {
	ais_perror("Sent -%d to %s: [%d]", signal, child->name, child->pid);
    }
    
    return TRUE;
}

void destroy_ais_node(gpointer data) 
{
    crm_node_t *node = data;
    ais_info("Destroying entry for node %u", node->id);

    ais_free(node->addr);
    ais_free(node->uname);
    ais_free(node->state);
    ais_free(node);
}

int update_member(unsigned int id, uint64_t born, uint64_t seq, int32_t votes,
		  uint32_t procs, const char *uname, const char *state, const char *version) 
{
    int changed = 0;
    crm_node_t *node = NULL;
    
    node = g_hash_table_lookup(membership_list, GUINT_TO_POINTER(id));	

    if(node == NULL) {	
	ais_malloc0(node, sizeof(crm_node_t));
	ais_info("Creating entry for node %u born on "U64T"", id, seq);
	node->id = id;
	node->addr = NULL;
	node->state = ais_strdup("unknown");
	
	g_hash_table_insert(membership_list, GUINT_TO_POINTER(id), node);
	node = g_hash_table_lookup(membership_list, GUINT_TO_POINTER(id));
    }

    if(seq != 0) {
	node->last_seen = seq;
    }

    if(born != 0) {
	changed = TRUE;
	node->born = born;
	ais_info("%p Node %u (%s) born on: "U64T, node, id, uname, born);
    }

    if(version != NULL) {
	ais_free(node->version);
	node->version = ais_strdup(version);
    }
    
    if(uname != NULL) {
	if(node->uname == NULL || ais_str_eq(node->uname, uname) == FALSE) {
	    ais_info("%p Node %u now known as %s (was: %s)",
		     node, id, uname, node->uname);
	    ais_free(node->uname);
	    node->uname = ais_strdup(uname);
	    changed = TRUE;
	}
    }

    if(procs != 0 && procs != node->processes) {
	ais_info("Node %s now has process list: %.32x (%u)",
		 node->uname, procs, procs);
	node->processes = procs;
	changed = TRUE;
    }

    if(votes >= 0 && votes != node->votes) {
	ais_info("Node %s now has %d quorum votes (was %d)",
		 node->uname, votes, node->votes);
	node->votes = votes;
	changed = TRUE;
    }
    
    if(state != NULL) {
	if(node->state == NULL || ais_str_eq(node->state, state) == FALSE) {
	    ais_free(node->state);
	    node->state = ais_strdup(state);
	    ais_info("Node %u/%s is now: %s",
		     id, node->uname?node->uname:"unknown", state);
	    changed = TRUE;
	}
    }
    
    AIS_ASSERT(node != NULL);
    return changed;
}

void delete_member(uint32_t id, const char *uname) 
{
    if(uname == NULL) {
	g_hash_table_remove(membership_list, GUINT_TO_POINTER(id));
	return;
    }
    ais_err("Deleting by uname is not yet supported");
}

const char *member_uname(uint32_t id) 
{
     crm_node_t *node = g_hash_table_lookup(
	 membership_list, GUINT_TO_POINTER(id));	
     if(node == NULL) {
	 return ".unknown.";
     }
     if(node->uname == NULL) {
	 return ".pending.";
     }
     return node->uname;
}

char *append_member(char *data, crm_node_t *node)
{
    int size = 1; /* nul */
    int offset = 0;
    static int fixed_len = 4 + 8 + 7 + 6 + 6 + 7 + 11;

    if(data) {
	size = strlen(data);
    }
    offset = size;

    size += fixed_len;
    size += 32; /* node->id */
    size += 100; /* node->seq, node->born */
    size += strlen(node->state);
    if(node->uname) {
	size += (7 + strlen(node->uname));
    }
    if(node->addr) {
	size += (6 + strlen(node->addr));
    }
    if(node->version) {
	size += (9 + strlen(node->version));
    }
    data = realloc(data, size);

    offset += snprintf(data + offset, size - offset, "<node id=\"%u\" ", node->id);
    if(node->uname) {
	offset += snprintf(data + offset, size - offset, "uname=\"%s\" ", node->uname);
    }
    offset += snprintf(data + offset, size - offset, "state=\"%s\" ", node->state);
    offset += snprintf(data + offset, size - offset, "born=\""U64T"\" ", node->born);
    offset += snprintf(data + offset, size - offset, "seen=\""U64T"\" ", node->last_seen);
    offset += snprintf(data + offset, size - offset, "votes=\"%d\" ", node->votes);
    offset += snprintf(data + offset, size - offset, "processes=\"%u\" ", node->processes);
    if(node->addr) {
	offset += snprintf(data + offset, size - offset, "addr=\"%s\" ", node->addr);
    }
    if(node->version) {
	offset += snprintf(data + offset, size - offset, "version=\"%s\" ", node->version);
    }
    offset += snprintf(data + offset, size - offset, "/>");

    return data;
}

void swap_sender(AIS_Message *msg) 
{
    int tmp = 0;
    char tmp_s[256];
    tmp = msg->host.type;
    msg->host.type = msg->sender.type;
    msg->sender.type = tmp;

    tmp = msg->host.type;
    msg->host.size = msg->sender.type;
    msg->sender.type = tmp;

    memcpy(tmp_s, msg->host.uname, 256);
    memcpy(msg->host.uname, msg->sender.uname, 256);
    memcpy(msg->sender.uname, tmp_s, 256);
}

char *get_ais_data(AIS_Message *msg)
{
    int rc = BZ_OK;
    char *uncompressed = NULL;
    unsigned int new_size = msg->size;
    
    if(msg->is_compressed == FALSE) {
	uncompressed = strdup(msg->data);

    } else {
	ais_malloc0(uncompressed, new_size);
	
	rc = BZ2_bzBuffToBuffDecompress(
	    uncompressed, &new_size, msg->data, msg->compressed_size, 1, 0);
	if(rc != BZ_OK) {
	    ais_info("rc=%d, new=%u expected=%u", rc, new_size, msg->size);
	}
	AIS_ASSERT(rc == BZ_OK);
	AIS_ASSERT(new_size == msg->size);
    }
    
    return uncompressed;
}

int send_cluster_msg(
    enum crm_ais_msg_types type, const char *host, const char *data) 
{
    int rc = 0;
    int data_len = 0;
    AIS_Message *ais_msg = NULL;
    int total_size = sizeof(AIS_Message);

    ENTER("");
    AIS_ASSERT(local_nodeid != 0);

    if(data != NULL) {
	data_len = 1 + strlen(data);
	total_size += data_len;
    } 
    ais_malloc0(ais_msg, total_size);
	
    ais_msg->header.size = total_size;
    ais_msg->header.id = 0;
    
    ais_msg->size = data_len;
    memcpy(ais_msg->data, data, data_len);
    ais_msg->sender.type = crm_msg_ais;

    ais_msg->host.type = type;
    ais_msg->host.id = 0;
    if(host) {
	ais_msg->host.size = strlen(host);
	memset(ais_msg->host.uname, 0, MAX_NAME);
	memcpy(ais_msg->host.uname, host, ais_msg->host.size);
/* 	ais_msg->host.id = nodeid_lookup(host); */
		
    } else {
	ais_msg->host.type = type;
	ais_msg->host.size = 0;
	memset(ais_msg->host.uname, 0, MAX_NAME);
    }
    
    rc = send_cluster_msg_raw(ais_msg);
    ais_free(ais_msg);
    
    LEAVE("");
    return rc;	
}

extern struct corosync_api_v1 *crm_api;

int send_client_msg(
    void *conn, enum crm_ais_msg_class class, enum crm_ais_msg_types type, const char *data) 
{
    int rc = 0;
    int data_len = 0;
    int total_size = sizeof(AIS_Message);
    AIS_Message *ais_msg = NULL;
    static int msg_id = 0;

    ENTER("");
    AIS_ASSERT(local_nodeid != 0);

    msg_id++;
    AIS_ASSERT(msg_id != 0 /* wrap-around */);

    if(data != NULL) {
	data_len = 1 + strlen(data);
    }
    total_size += data_len;
    
    ais_malloc0(ais_msg, total_size);
	
    ais_msg->id = msg_id;
    ais_msg->header.size = total_size;
    ais_msg->header.id = class;
    
    ais_msg->size = data_len;
    memcpy(ais_msg->data, data, data_len);
    
    ais_msg->host.type = type;
    ais_msg->host.size = 0;
    memset(ais_msg->host.uname, 0, MAX_NAME);
    ais_msg->host.id = 0;

    ais_msg->sender.type = crm_msg_ais;
    ais_msg->sender.size = local_uname_len;
    memset(ais_msg->sender.uname, 0, MAX_NAME);
    memcpy(ais_msg->sender.uname, local_uname, ais_msg->sender.size);
    ais_msg->sender.id = local_nodeid;

    rc = 1;
    if (conn == NULL) {
	ais_err("No connection");
	    
    } else if (!libais_connection_active(conn)) {
	ais_warn("Connection no longer active");
	    
/* 	} else if ((queue->size - 1) == queue->used) { */
/* 	    ais_err("Connection is throttled: %d", queue->size); */

    } else {
#ifdef AIS_WHITETANK
	rc = openais_dispatch_send (conn, ais_msg, total_size);
#endif
#ifdef AIS_COROSYNC
	rc = crm_api->ipc_dispatch_send (conn, ais_msg, total_size);
#endif
	AIS_CHECK(rc == 0,
		  ais_err("Message not sent (%d): %s", rc, data?data:"<null>"));
    }

    ais_free(ais_msg);
    LEAVE("");
    return rc;    
}

static char *
ais_concat(const char *prefix, const char *suffix, char join) 
{
	int len = 0;
	char *new_str = NULL;
	AIS_ASSERT(prefix != NULL);
	AIS_ASSERT(suffix != NULL);
	len = strlen(prefix) + strlen(suffix) + 2;

	ais_malloc0(new_str, (len));
	sprintf(new_str, "%s%c%s", prefix, join, suffix);
	new_str[len-1] = 0;
	return new_str;
}

unsigned int config_find_init(plugin_init_type *config, char *name) 
{
    unsigned int local_handle = 0;
#ifdef AIS_COROSYNC
    config->object_find_create(OBJECT_PARENT_HANDLE, name, strlen(name), &local_handle);
#endif
    
#ifdef AIS_WHITETANK 
    config->object_find_reset (OBJECT_PARENT_HANDLE);
#endif
    return local_handle;
}

unsigned int config_find_next(plugin_init_type *config, char *name, unsigned int top_handle) 
{
    int rc = 0;
    unsigned int local_handle = 0;

#ifdef AIS_COROSYNC
    rc = config->object_find_next (top_handle, &local_handle);
#endif
    
#ifdef AIS_WHITETANK 
    rc = config->object_find(OBJECT_PARENT_HANDLE, name, strlen (name), &local_handle);
#endif

    if(rc < 0) {
	ais_info("No additional configuration supplied for: %s", name);
	local_handle = 0;
    } else {
	ais_info("Processing additional %s options...", name);
    }
    return local_handle;
}

void config_find_done(plugin_init_type *config, unsigned int local_handle) 
{
#ifdef AIS_COROSYNC
    config->object_find_destroy (local_handle);
#endif
}

int get_config_opt(
    plugin_init_type *config,
    unsigned int object_service_handle,
    char *key, char **value, const char *fallback)
{
    char *env_key = NULL;
    *value = NULL;

    if(object_service_handle > 0) {
	config->object_key_get(
	    object_service_handle, key, strlen(key), (void**)value, NULL);
    }
    
    if (*value) {
	ais_info("Found '%s' for option: %s", *value, key);
	return 0;
    }

    env_key = ais_concat("HA", key, '_');
    *value = getenv(env_key);
    ais_free(env_key);

    if (*value) {
	ais_info("Found '%s' in ENV for option: %s", *value, key);
	return 0;
    }

    if(fallback) {
	ais_info("Defaulting to '%s' for option: %s", fallback, key);
	*value = ais_strdup(fallback);

    } else {
	ais_info("No default for option: %s", key);
    }
    
    return -1;
}

int
ais_get_boolean(const char * value)
{
	if(value == NULL) {
		return 0;

	} else if (strcasecmp(value, "true") == 0
		   ||	strcasecmp(value, "on") == 0
		   ||	strcasecmp(value, "yes") == 0
		   ||	strcasecmp(value, "y") == 0
		   ||	strcasecmp(value, "1") == 0){
		return 1;
	}
	return 0;
}
