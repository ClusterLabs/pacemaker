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
#include <bzlib.h>
#include <crm/ais.h>
#include <crm/common/cluster.h>
#include <sys/utsname.h>
#include "stack.h"
#ifdef SUPPORT_COROSYNC
#  include <corosync/corodefs.h>
#endif

#ifdef SUPPORT_CMAN
#  include <libcman.h>
cman_handle_t pcmk_cman_handle = NULL;
#endif

#ifdef SUPPORT_CS_QUORUM
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>

#  include <corosync/cpg.h>
#  include <corosync/quorum.h>

quorum_handle_t pcmk_quorum_handle = 0;
cpg_handle_t pcmk_cpg_handle = 0;
struct cpg_name pcmk_cpg_group = {
    .length = 0,
    .value[0] = 0,
};
#endif

enum crm_quorum_source quorum_source = crm_quorum_pacemaker;

enum crm_quorum_source get_quorum_source(void) 
{
    const char *quorum_type = getenv("HA_quorum_type");
    if(safe_str_eq("cman", quorum_type)) {
#ifdef SUPPORT_CMAN
	return crm_quorum_cman;
#else
	crm_err("Quorum provider %s is not supported by this installation", quorum_type);
#endif
    } else if(safe_str_eq("corosync", quorum_type)) {
#ifdef SUPPORT_CMAN
	return crm_quorum_corosync;
#else
	crm_err("Quorum provider %s is not supported by this installation", quorum_type);
#endif
    }
    return crm_quorum_pacemaker;
}

enum crm_ais_msg_types text2msg_type(const char *text) 
{
	int type = crm_msg_none;

	CRM_CHECK(text != NULL, return type);
	if(safe_str_eq(text, "ais")) {
		type = crm_msg_ais;
	} else if(safe_str_eq(text, "crm_plugin")) {
		type = crm_msg_ais;
	} else if(safe_str_eq(text, CRM_SYSTEM_CIB)) {
		type = crm_msg_cib;
	} else if(safe_str_eq(text, CRM_SYSTEM_CRMD)) {
		type = crm_msg_crmd;
	} else if(safe_str_eq(text, CRM_SYSTEM_DC)) {
		type = crm_msg_crmd;
	} else if(safe_str_eq(text, CRM_SYSTEM_TENGINE)) {
		type = crm_msg_te;
	} else if(safe_str_eq(text, CRM_SYSTEM_PENGINE)) {
		type = crm_msg_pe;
	} else if(safe_str_eq(text, CRM_SYSTEM_LRMD)) {
		type = crm_msg_lrmd;
	} else if(safe_str_eq(text, CRM_SYSTEM_STONITHD)) {
		type = crm_msg_stonithd;
	} else if(safe_str_eq(text, "stonith-ng")) {
		type = crm_msg_stonith_ng;
	} else if(safe_str_eq(text, "attrd")) {
		type = crm_msg_attrd;

	} else {
	    /* This will normally be a transient client rather than
	     * a cluster daemon.  Set the type to the pid of the client
	     */
	    int scan_rc = sscanf(text, "%d", &type);
	    if(scan_rc != 1) {
		/* Ensure its sane */
		type = crm_msg_none;
	    }
	}
	return type;
}

char *get_ais_data(const AIS_Message *msg)
{
    int rc = BZ_OK;
    char *uncompressed = NULL;
    unsigned int new_size = msg->size + 1;
    
    if(msg->is_compressed == FALSE) {
	crm_debug_2("Returning uncompressed message data");
	uncompressed = strdup(msg->data);

    } else {
	crm_debug_2("Decompressing message data");
	crm_malloc0(uncompressed, new_size);
	
	rc = BZ2_bzBuffToBuffDecompress(
	    uncompressed, &new_size, (char*)msg->data, msg->compressed_size, 1, 0);
	
	CRM_ASSERT(rc == BZ_OK);
	CRM_ASSERT(new_size == msg->size);
    }
    
    return uncompressed;
}


#if SUPPORT_COROSYNC
int ais_fd_sync = -1;
int ais_fd_async = -1; /* never send messages via this channel */
void *ais_ipc_ctx = NULL;
hdb_handle_t ais_ipc_handle = 0;
GFDSource *ais_source = NULL;
GFDSource *ais_source_sync = NULL;
GFDSource *cman_source = NULL;
GFDSource *cpg_source = NULL;
GFDSource *quorumd_source = NULL;
static char *ais_cluster_name = NULL;

gboolean get_ais_nodeid(uint32_t *id, char **uname)
{
    struct iovec iov;
    int retries = 0;
    int rc = CS_OK;
    coroipc_response_header_t header;
    struct crm_ais_nodeid_resp_s answer;

    header.error = CS_OK;
    header.id = crm_class_nodeid;
    header.size = sizeof(coroipc_response_header_t);

    CRM_CHECK(id != NULL, return FALSE);
    CRM_CHECK(uname != NULL, return FALSE);

    iov.iov_base = &header;
    iov.iov_len = header.size;
    
  retry:
    errno = 0;
    rc = coroipcc_msg_send_reply_receive(
	ais_ipc_handle, &iov, 1, &answer, sizeof (answer));
    if(rc == CS_OK) {
	CRM_CHECK(answer.header.size == sizeof (struct crm_ais_nodeid_resp_s),
		  crm_err("Odd message: id=%d, size=%d, error=%d",
			  answer.header.id, answer.header.size, answer.header.error));
	CRM_CHECK(answer.header.id == crm_class_nodeid, crm_err("Bad response id: %d", answer.header.id));
    }

    if(rc == CS_ERR_TRY_AGAIN && retries < 20) {
	retries++;
	crm_info("Peer overloaded: Re-sending message (Attempt %d of 20)", retries);
	sleep(retries); /* Proportional back off */
	goto retry;
    }

    if(rc != CS_OK) {    
	crm_err("Sending nodeid request: FAILED (rc=%d): %s", rc, ais_error2text(rc));
	return FALSE;
	
    } else if(answer.header.error != CS_OK) {
	crm_err("Bad response from peer: (rc=%d): %s", rc, ais_error2text(rc));
	return FALSE;
    }

    crm_info("Server details: id=%u uname=%s cname=%s",
	     answer.id, answer.uname, answer.cname);
    
    *id = answer.id;
    *uname = crm_strdup(answer.uname);
    ais_cluster_name = crm_strdup(answer.cname);

    return TRUE;
}

gboolean crm_get_cluster_name(char **cname)
{
    CRM_CHECK(cname != NULL, return FALSE);
    if(ais_cluster_name) {
	*cname = crm_strdup(ais_cluster_name);
	return TRUE;
    }
    return FALSE;
}

gboolean
send_ais_text(int class, const char *data,
	      gboolean local, const char *node, enum crm_ais_msg_types dest)
{
    static int msg_id = 0;
    static int local_pid = 0;
    static int sender_len = 0;
    static char *sender_uname = NULL;

    int retries = 0;
    int rc = CS_OK;
    int buf_len = sizeof(coroipc_response_header_t);

    char *buf = NULL;
    struct iovec iov;
    coroipc_response_header_t *header = NULL;
    AIS_Message *ais_msg = NULL;
    enum crm_ais_msg_types sender = text2msg_type(crm_system_name);

    /* There are only 6 handlers registered to crm_lib_service in plugin.c */
    CRM_CHECK(class < 6, crm_err("Invalid message class: %d", class); return FALSE); 

    if(data == NULL) {
	data = "";
    }
    
    if(local_pid == 0) {
	local_pid = getpid();
    }

    if(sender == crm_msg_none) {
	sender = local_pid;
    }
    
    crm_malloc0(ais_msg, sizeof(AIS_Message));
    
    ais_msg->id = msg_id++;
    ais_msg->header.id = class;
    ais_msg->header.error = CS_OK;
    
    ais_msg->host.type = dest;
    ais_msg->host.local = local;
    if(node) {
	ais_msg->host.size = strlen(node);
	memset(ais_msg->host.uname, 0, MAX_NAME);
	memcpy(ais_msg->host.uname, node, ais_msg->host.size);
	ais_msg->host.id = 0;
	
    } else {
	ais_msg->host.size = 0;
	memset(ais_msg->host.uname, 0, MAX_NAME);
	ais_msg->host.id = 0;
    }

    if(sender_len == 0) {
	struct utsname name;
	if(uname(&name) < 0) {
	    crm_perror(LOG_ERR,"uname(2) call failed");
	    exit(100);
	}
	sender_uname = crm_strdup(name.nodename);
	sender_len = strlen(sender_uname) + 1;
	if(sender_len > MAX_NAME) {
	    crm_err("Host name '%s' is too long", sender_uname);
	    exit(100);
	}
    }
    
    ais_msg->sender.id = 0;
    ais_msg->sender.type = sender;
    ais_msg->sender.pid = local_pid;
    ais_msg->sender.size = sender_len;
    memset(ais_msg->sender.uname, 0, MAX_NAME);
    memcpy(ais_msg->sender.uname, sender_uname, ais_msg->sender.size);

    ais_msg->size = 1 + strlen(data);

    if(ais_msg->size < CRM_BZ2_THRESHOLD) {
  failback:
	crm_realloc(ais_msg, sizeof(AIS_Message) + ais_msg->size);
	memcpy(ais_msg->data, data, ais_msg->size);
	
    } else {
	char *compressed = NULL;
	char *uncompressed = crm_strdup(data);
	unsigned int len = (ais_msg->size * 1.1) + 600; /* recomended size */
	
	crm_debug_5("Compressing message payload");
	crm_malloc(compressed, len);
	
	rc = BZ2_bzBuffToBuffCompress(
	    compressed, &len, uncompressed, ais_msg->size, CRM_BZ2_BLOCKS, 0, CRM_BZ2_WORK);

	crm_free(uncompressed);
	
	if(rc != BZ_OK) {
	    crm_err("Compression failed: %d", rc);
	    crm_free(compressed);
	    goto failback;  
	}

	crm_realloc(ais_msg, sizeof(AIS_Message) + len + 1);
	memcpy(ais_msg->data, compressed, len);
	ais_msg->data[len] = 0;
	crm_free(compressed);

	ais_msg->is_compressed = TRUE;
	ais_msg->compressed_size = len;

	crm_debug_2("Compression details: %d -> %d",
		  ais_msg->size, ais_data_len(ais_msg));
    } 

    ais_msg->header.size = sizeof(AIS_Message) + ais_data_len(ais_msg);

    crm_debug_3("Sending%s message %d to %s.%s (data=%d, total=%d)",
		ais_msg->is_compressed?" compressed":"",
		ais_msg->id, ais_dest(&(ais_msg->host)), msg_type2text(dest),
		ais_data_len(ais_msg), ais_msg->header.size);

    iov.iov_base = ais_msg;
    iov.iov_len = ais_msg->header.size;
  retry:
    errno = 0;
    crm_realloc(buf, buf_len);

    if(dest != crm_msg_ais && quorum_source != crm_quorum_pacemaker) {
#ifdef SUPPORT_CS_QUORUM
	rc = cpg_mcast_joined(pcmk_cpg_handle, CPG_TYPE_AGREED, &iov, 1);
#else
	ASSERT(quorum_source == crm_quorum_pacemaker);
#endif
    } else {
	rc = coroipcc_msg_send_reply_receive(ais_ipc_handle, &iov, 1, buf, buf_len);
	header = (coroipc_response_header_t *)buf;
    }
    
    if(rc == CS_ERR_TRY_AGAIN && retries < 20) {
	retries++;
	crm_info("Peer overloaded or membership in flux:"
		 " Re-sending message (Attempt %d of 20)", retries);
	sleep(retries); /* Proportional back off */
	goto retry;

    } else if(rc == CS_OK && header) {

	CRM_CHECK_AND_STORE(header->size == sizeof (coroipc_response_header_t),
			    crm_err("Odd message: id=%d, size=%d, class=%d, error=%d",
				    header->id, header->size, class, header->error));

	if(buf_len < header->size) {
	    crm_err("Increasing buffer length to %d and retrying", header->size);
	    buf_len = header->size + 1;
	    goto retry;

	} else if(header->id == crm_class_nodeid && header->size == sizeof (struct crm_ais_nodeid_resp_s)){
	    struct crm_ais_nodeid_resp_s *answer = (struct crm_ais_nodeid_resp_s *)header;
	    crm_err("Server details: id=%u uname=%s counter=%u", answer->id, answer->uname, answer->counter);

	} else {
	    CRM_CHECK_AND_STORE(header->id == CRM_MESSAGE_IPC_ACK,
				crm_err("Bad response id (%d) for request (%d)", header->id, ais_msg->header.id));
	    CRM_CHECK(header->error == CS_OK, rc = header->error);
	}
    }
    
    if(rc != CS_OK) {    
	crm_perror(LOG_ERR,"Sending message %d: FAILED (rc=%d): %s",
		  ais_msg->id, rc, ais_error2text(rc));
	ais_fd_async = -1;
    } else {
	crm_debug_4("Message %d: sent", ais_msg->id);
    }

    crm_free(buf);
    crm_free(ais_msg);
    return (rc == CS_OK);
}

gboolean
send_ais_message(xmlNode *msg, 
		 gboolean local, const char *node, enum crm_ais_msg_types dest)
{
    gboolean rc = TRUE;
    char *data = NULL;

    if(ais_fd_async < 0 || ais_source == NULL) {
	crm_err("Not connected to AIS: %d %p", ais_fd_async, ais_source);
	return FALSE;
    }

    data = dump_xml_unformatted(msg);
    rc = send_ais_text(0, data, local, node, dest);
    crm_free(data);
    return rc;
}

void terminate_ais_connection(void) 
{
    if(ais_ipc_ctx) {
	coroipcc_service_disconnect(ais_ipc_handle);
    }
    crm_notice("Disconnected from AIS");
/*     G_main_del_fd(ais_source); */
/*     G_main_del_fd(ais_source_sync);     */

#ifdef SUPPORT_CMAN
    if(quorum_source == crm_quorum_cman) {
	cpg_leave(pcmk_cpg_handle, &pcmk_cpg_group);
	cman_stop_notification(pcmk_cman_handle);
	cman_finish(pcmk_cman_handle);
    }
#endif

#ifdef SUPPORT_CS_QUORUM
    if(quorum_source == crm_quorum_corosync) {
	quorum_finalize(pcmk_quorum_handle);
	cpg_leave(pcmk_cpg_handle, &pcmk_cpg_group);
    }
#endif
}

int ais_membership_timer = 0;
gboolean ais_membership_force = FALSE;

static gboolean ais_dispatch_message(
    AIS_Message *msg, gboolean (*dispatch)(AIS_Message*,char*,int))
{
    char *data = NULL;
    char *uncompressed = NULL;
    
    xmlNode *xml = NULL;
    CRM_ASSERT(msg != NULL);
    
    crm_debug_3("Got new%s message (size=%d, %d, %d)",
		msg->is_compressed?" compressed":"",
		ais_data_len(msg), msg->size, msg->compressed_size);
    
    data = msg->data;
    if(msg->is_compressed && msg->size > 0) {
	int rc = BZ_OK;
	unsigned int new_size = msg->size + 1;

	if(check_message_sanity(msg, NULL) == FALSE) {
	    goto badmsg;
	}

	crm_debug_5("Decompressing message data");
	crm_malloc0(uncompressed, new_size);
	rc = BZ2_bzBuffToBuffDecompress(
	    uncompressed, &new_size, data, msg->compressed_size, 1, 0);

	if(rc != BZ_OK) {
	    crm_err("Decompression failed: %d", rc);
	    goto badmsg;
	}
	
	CRM_ASSERT(rc == BZ_OK);
	CRM_ASSERT(new_size == msg->size);

	data = uncompressed;

    } else if(check_message_sanity(msg, data) == FALSE) {
	goto badmsg;

    } else if(safe_str_eq("identify", data)) {
	int pid = getpid();
	char *pid_s = crm_itoa(pid);
	send_ais_text(0, pid_s, TRUE, NULL, crm_msg_ais);
	crm_free(pid_s);
	goto done;
    }

    if(msg->header.id != crm_class_members) {
	crm_update_peer(msg->sender.id, 0,0,0,0, msg->sender.uname, msg->sender.uname, NULL, NULL);
    }
    
    if(msg->header.id == crm_class_rmpeer) {
	uint32_t id = crm_int_helper(data, NULL);
	crm_info("Removing peer %s/%u", data, id);
	reap_crm_member(id);
	goto done;

    } else if(msg->header.id == crm_class_members
	|| msg->header.id == crm_class_quorum) {

	xml = string2xml(data);
	if(xml == NULL) {
	    crm_err("Invalid membership update: %s", data);
	    goto badmsg;
	}
	
	if(quorum_source != crm_quorum_pacemaker) {
	    xml_child_iter(xml, node, crm_update_cman_node(node, crm_peer_seq));

	} else {
	    const char *value = NULL;
	    gboolean quorate = FALSE;	
	    
	    value = crm_element_value(xml, "quorate");
	    CRM_CHECK(value != NULL, crm_log_xml_err(xml, "No quorum value:"); goto badmsg);
	    if(crm_is_true(value)) {
		quorate = TRUE;
	    }
	    
	    value = crm_element_value(xml, "id");
	    CRM_CHECK(value != NULL, crm_log_xml_err(xml, "No membership id"); goto badmsg);
	    crm_peer_seq = crm_int_helper(value, NULL);
	    
	    if(quorate != crm_have_quorum) {
		crm_notice("Membership %s: quorum %s", value, quorate?"acquired":"lost");
		crm_have_quorum = quorate;
		
	    } else {
		crm_info("Membership %s: quorum %s", value, quorate?"retained":"still lost");
	    }
	
	    xml_child_iter(xml, node, crm_update_ais_node(node, crm_peer_seq));
	}
    }

    if(dispatch != NULL) {
	dispatch(msg, data, 0);
    }
    
  done:
    crm_free(uncompressed);
    free_xml(xml);
    return TRUE;

  badmsg:
    crm_err("Invalid message (id=%d, dest=%s:%s, from=%s:%s.%d):"
	    " min=%d, total=%d, size=%d, bz2_size=%d",
	    msg->id, ais_dest(&(msg->host)), msg_type2text(msg->host.type),
	    ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
	    msg->sender.pid, (int)sizeof(AIS_Message),
	    msg->header.size, msg->size, msg->compressed_size);
    goto done;
}

gboolean ais_dispatch(int sender, gpointer user_data)
{
    int rc = CS_OK;
    char *buffer = NULL;
    gboolean good = TRUE;
    gboolean (*dispatch)(AIS_Message*,char*,int) = user_data;

    rc = coroipcc_dispatch_get (ais_ipc_handle, (void**)&buffer, 0);

    if (rc == 0 || buffer == NULL) {
	/* Zero is a legal "no message afterall" value */
	return TRUE;
	
    } else if (rc != CS_OK) {
	crm_perror(LOG_ERR,"Receiving message body failed: (%d) %s", rc, ais_error2text(rc));
	goto bail;
    }

    good = ais_dispatch_message((AIS_Message*)buffer, dispatch);
    coroipcc_dispatch_put (ais_ipc_handle);
    return good;

  bail:
    crm_err("AIS connection failed");
    return FALSE;
}

static void
ais_destroy(gpointer user_data)
{
    crm_err("AIS connection terminated");
    ais_fd_sync = -1;
    exit(1);
}

#ifdef SUPPORT_CMAN

static gboolean pcmk_cman_dispatch(int sender, gpointer user_data)
{
    int rc = cman_dispatch(pcmk_cman_handle, CMAN_DISPATCH_ONE);
    if(rc < 0) {
	crm_err("Connection to cman failed: %d", rc);
	return FALSE;
    }
    return TRUE;
}

static char *append_cman_member(char *data, cman_node_t *node, uint32_t seq)
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
    size += strlen(CRM_NODE_MEMBER);
    if(node->cn_name) {
	size += (7 + strlen(node->cn_name));
    }
    data = realloc(data, size);

    offset += snprintf(data + offset, size - offset, "<node id=\"%u\" ", node->cn_nodeid);
    if(node->cn_name) {
	offset += snprintf(data + offset, size - offset, "uname=\"%s\" ", node->cn_name);
    }
    offset += snprintf(data + offset, size - offset, "state=\"%s\" ", node->cn_member?CRM_NODE_MEMBER:CRM_NODE_LOST);
    offset += snprintf(data + offset, size - offset, "born=\"%u\" ", node->cn_incarnation);
    offset += snprintf(data + offset, size - offset, "seen=\"%d\" ", seq);
    offset += snprintf(data + offset, size - offset, "/>");

    return data;
}

#define MAX_NODES 256

static void cman_event_callback(cman_handle_t handle, void *privdata, int reason, int arg)
{
    char *payload = NULL;
    int rc = 0, lpc = 0, size = 256, node_count = 0;

    cman_cluster_t cluster;
    static cman_node_t cman_nodes[MAX_NODES];
    gboolean (*dispatch)(AIS_Message*,char*,int) = privdata;
    
    switch (reason) {
	case CMAN_REASON_STATECHANGE:

	    memset(&cluster, 0, sizeof(cluster));
	    rc = cman_get_cluster(pcmk_cman_handle, &cluster);
	    if (rc < 0) {
		crm_err("Couldn't query cman cluster details: %d %d", rc, errno);
		return;
	    }

	    if(arg != crm_have_quorum) {
		crm_notice("Membership %d: quorum %s", cluster.ci_generation, arg?"acquired":"lost");
		crm_have_quorum = arg;
		
	    } else {
		crm_info("Membership %d: quorum %s", cluster.ci_generation, arg?"retained":"still lost");
	    }

	    rc = cman_get_nodes(pcmk_cman_handle, MAX_NODES, &node_count, cman_nodes);
	    if (rc < 0) {
		crm_err("Couldn't query cman node list: %d %d", rc, errno);
		return;
	    }

	    crm_malloc0(payload, size);
	    snprintf(payload, size, "<nodes id=\"%d\" quorate=\"%s\">",
		     cluster.ci_generation, arg?"true":"false");
	    
	    for (lpc = 0; lpc < node_count; lpc++) {
		if (cman_nodes[lpc].cn_nodeid == 0) {
		    /* Never allow node ID 0 to be considered a member #315711 */
		    cman_nodes[lpc].cn_member = 0;
		    break;
		}
		crm_update_peer(cman_nodes[lpc].cn_nodeid, cman_nodes[lpc].cn_incarnation, cluster.ci_generation, 0, 0,
				cman_nodes[lpc].cn_name, cman_nodes[lpc].cn_name, NULL, cman_nodes[lpc].cn_member?CRM_NODE_MEMBER:CRM_NODE_LOST);
		if (dispatch && cman_nodes[lpc].cn_member) {
		    payload = append_cman_member(payload, &(cman_nodes[lpc]), cluster.ci_generation);
		}
	    }

	    if(dispatch) {
		AIS_Message ais_msg;
		memset(&ais_msg, 0, sizeof(AIS_Message));
		
		ais_msg.header.id = crm_class_members;
		ais_msg.header.error = CS_OK;
		ais_msg.header.size = sizeof(AIS_Message);
		
		ais_msg.host.type = crm_msg_none;
		ais_msg.sender.type = crm_msg_ais;

		size = strlen(payload);
		payload = realloc(payload, size + 9) ;/* 9 = </nodes> + nul */
		sprintf(payload + size, "</nodes>");
		
		/* ais_msg.data = payload; */
		ais_msg.size = size + 9;
		/* ais_msg.header.size += ais_msg.size; */
		
		dispatch(&ais_msg, payload, 0);		
	    }

	    crm_free(payload);
	    break;

	case CMAN_REASON_TRY_SHUTDOWN:
	    /*cman_replyto_shutdown() */
	    crm_info("CMAN wants to shut down: %s", arg?"forced":"managed");
	    break;
	    
	case CMAN_REASON_CONFIG_UPDATE:
	    /* Ignore */
	    break;
    }
}
#endif

static gboolean init_cman_connection(
    gboolean (*dispatch)(AIS_Message*,char*,int), void (*destroy)(gpointer))
{
#ifdef SUPPORT_CMAN
    int rc = -1;
    cman_cluster_t cluster;
    crm_info("Configuring Pacemaker to obtain quorum from cman");

    memset(&cluster, 0, sizeof(cluster));

    pcmk_cman_handle = cman_init(dispatch);
    if(pcmk_cman_handle == NULL || cman_is_active(pcmk_cman_handle) == FALSE) {
	crm_err("Couldn't connect to cman");
	goto cman_bail;
    }

    rc = cman_get_cluster(pcmk_cman_handle, &cluster);
    if (rc < 0) {
	crm_err("Couldn't query cman cluster details: %d %d", rc, errno);
	goto cman_bail;	
    }
    ais_cluster_name = crm_strdup(cluster.ci_name);	
	
    rc = cman_start_notification(pcmk_cman_handle, cman_event_callback);
    if (rc < 0) {
	crm_err("Couldn't register for cman notifications: %d %d", rc, errno);
	goto cman_bail;
    }

    /* Get the current membership state */
    cman_event_callback(pcmk_cman_handle, dispatch, CMAN_REASON_STATECHANGE,
			cman_is_quorate(pcmk_cman_handle));
    
    cman_source = G_main_add_fd(
	G_PRIORITY_HIGH, cman_get_fd(pcmk_cman_handle), FALSE,
	pcmk_cman_dispatch, dispatch, destroy);

  cman_bail:
    if (rc < 0) {
	crm_err("Falling back to Pacemaker's internal quorum implementation");
	quorum_source = crm_quorum_pacemaker;
	cman_finish(pcmk_cman_handle);
    }
#else
    crm_err("cman qorum is not supported in this build");
    quorum_source = crm_quorum_pacemaker;
#endif
    return TRUE;
}

#ifdef SUPPORT_CS_QUORUM
gboolean (*pcmk_cpg_dispatch_fn)(AIS_Message*,char*,int) = NULL;

static char * node_pid_format(unsigned int nodeid, int pid, gboolean show_ip) {
	static char buffer[100];
	if (show_ip) {
		struct in_addr saddr;
#if __BYTE_ORDER == __BIG_ENDIAN
		saddr.s_addr = swab32(nodeid);
#else
		saddr.s_addr = nodeid;
#endif
		sprintf(buffer, "node/pid %s/%d", inet_ntoa(saddr),pid);
	} 
	else {
		sprintf(buffer, "node/pid %d/%d", nodeid, pid);
	} 
	return buffer;
}

static gboolean pcmk_cpg_dispatch(int sender, gpointer user_data)
{
    int rc = 0;
    pcmk_cpg_dispatch_fn = user_data;
    rc = cpg_dispatch(pcmk_cpg_handle, CS_DISPATCH_ALL);
    if(rc < 0) {
	crm_err("Connection to the CPG API failed: %d", rc);
	return FALSE;
    }
    return TRUE;
}

static void pcmk_cpg_deliver (
	cpg_handle_t handle,
	const struct cpg_name *groupName,
	uint32_t nodeid,
	uint32_t pid,
	void *msg,
	size_t msg_len)
{
    AIS_Message *ais_msg = (AIS_Message*)msg;

    crm_debug("Message (len=%lu) from %s\n",
	      (unsigned long int) msg_len, node_pid_format(nodeid, pid, TRUE));
    if(ais_msg->sender.id > 0 && ais_msg->sender.id != nodeid) {
	crm_err("Nodeid mismatch: claimed=%u, actual=%u", ais_msg->sender.id, nodeid);
	return;
    }

    ais_msg->sender.id = nodeid;
    if(ais_msg->sender.size == 0) {
	crm_node_t *peer = crm_get_peer(nodeid, NULL);
	if(peer == NULL) {
	    crm_err("Peer with nodeid=%u is unknown", nodeid);

	} else if(peer->uname == NULL) {
	    crm_err("No uname for peer with nodeid=%u", nodeid);

	} else {
	    ais_msg->sender.size = strlen(peer->uname);
	    memset(ais_msg->sender.uname, 0, MAX_NAME);
	    memcpy(ais_msg->sender.uname, peer->uname, ais_msg->sender.size);
	}
    }

    ais_dispatch_message(ais_msg, pcmk_cpg_dispatch_fn);
}

static void pcmk_cpg_membership(
	cpg_handle_t handle,
	const struct cpg_name *groupName,
	const struct cpg_address *member_list, size_t member_list_entries,
	const struct cpg_address *left_list, size_t left_list_entries,
	const struct cpg_address *joined_list, size_t joined_list_entries)
{
    /* Don't care about CPG membership */
}

static gboolean pcmk_quorum_dispatch(int sender, gpointer user_data)
{
    int rc = 0;
    rc = quorum_dispatch(pcmk_quorum_handle, CS_DISPATCH_ALL);
    if(rc < 0) {
	crm_err("Connection to the Quorum API failed: %d", rc);
	return FALSE;
    }
    return TRUE;
}

static void pcmk_quorum_notification(
	quorum_handle_t handle,
	uint32_t quorate,
	uint64_t ring_id,
	uint32_t view_list_entries,
	uint32_t *view_list)
{
	int i;

	if(quorate != crm_have_quorum) {
	    crm_notice("Membership "U64T": quorum %s (%lu)", ring_id,
		       quorate?"acquired":"lost", (long unsigned int)view_list_entries);
	    crm_have_quorum = quorate;
	    
	} else {
	    crm_info("Membership "U64T": quorum %s (%lu)", ring_id,
		     quorate?"retained":"still lost", (long unsigned int)view_list_entries);
	}
	for (i=0; i<view_list_entries; i++) {
		crm_debug(" %d ", view_list[i]);
	}
}

cpg_callbacks_t cpg_callbacks = {
    .cpg_deliver_fn =            pcmk_cpg_deliver,
    .cpg_confchg_fn =            pcmk_cpg_membership,
};

quorum_callbacks_t quorum_callbacks = {
    .quorum_notify_fn = pcmk_quorum_notification,
};

#endif

static gboolean init_cpg_connection(
    gboolean (*dispatch)(AIS_Message*,char*,int), void (*destroy)(gpointer), uint32_t *nodeid)
{
#ifdef SUPPORT_CS_QUORUM
    int rc = -1;
    int fd = 0;
	
    strcpy(pcmk_cpg_group.value, crm_system_name);
    pcmk_cpg_group.length = strlen(crm_system_name)+1;
    rc = cpg_initialize (&pcmk_cpg_handle, &cpg_callbacks);
    if (rc != CS_OK) {
	crm_err("Could not connect to the Cluster Process Group API: %d\n", rc);
	goto cpg_bail;
    }

    rc = cpg_local_get (pcmk_cpg_handle, (unsigned int*)nodeid);
    if (rc != CS_OK) {
	crm_err("Could not get local node id from the CPG API");
	goto cpg_bail;
    }	

    rc = cpg_join(pcmk_cpg_handle, &pcmk_cpg_group);
    if (rc != CS_OK) {
	crm_err("Could not join the CPG group '%s': %d", crm_system_name, rc);
	goto cpg_bail;
    }

    rc = cpg_fd_get(pcmk_cpg_handle, &fd);
    if (rc != CS_OK) {
	crm_err("Could not obtain the CPG API connection: %d\n", rc);
	goto cpg_bail;
    }

    cpg_source = G_main_add_fd(
	G_PRIORITY_HIGH, fd, FALSE, pcmk_cpg_dispatch, dispatch, destroy);

  cpg_bail:
    if (rc < 0) {
	crm_err("Falling back to Pacemaker's internal quorum implementation");
	quorum_source = crm_quorum_pacemaker;
	cpg_finalize(pcmk_cpg_handle);
    }
#else
    crm_err("corosync qorum is not supported in this build");
    quorum_source = crm_quorum_pacemaker;
#endif
    return TRUE;
}

static gboolean init_quorum_connection(
    gboolean (*dispatch)(AIS_Message*,char*,int), void (*destroy)(gpointer))
{
#ifdef SUPPORT_CS_QUORUM
    int rc = -1;
    int fd = 0;
    int quorate = 0;
	
    crm_info("Configuring Pacemaker to obtain quorum from Corosync");

    rc = quorum_initialize(&pcmk_quorum_handle, &quorum_callbacks);
    if ( rc != CS_OK) {
	crm_err("Could not connect to the Quorum API: %d\n", rc);
	goto quorum_bail;
    }

    rc = quorum_getquorate(pcmk_quorum_handle, &quorate);
    if ( rc != CS_OK) {
	crm_err("Could not obtain the current Quorum API state: %d\n", rc);
	goto quorum_bail;
    }
    crm_notice("Quorum %s", quorate?"acquired":"lost");
    crm_have_quorum = quorate;

    rc = quorum_trackstart(pcmk_quorum_handle, CS_TRACK_CHANGES);
    if ( rc != CS_OK) {
	crm_err("Could not setup Quorum API notifications: %d\n", rc);
	goto quorum_bail;
    }

    rc = quorum_fd_get(pcmk_quorum_handle, &fd);
    if (rc != CS_OK) {
	crm_err("Could not obtain the Quorum API connection: %d\n", rc);
	goto quorum_bail;
    }

    quorumd_source = G_main_add_fd(
	G_PRIORITY_HIGH, fd, FALSE, pcmk_quorum_dispatch, dispatch, destroy);

  quorum_bail:
    if (rc < 0) {
	quorum_finalize(pcmk_quorum_handle);
    }
	
#else
    crm_err("corosync qorum is not supported in this build");
    quorum_source = crm_quorum_pacemaker;
#endif
    return TRUE;
}

gboolean init_ais_connection(
    gboolean (*dispatch)(AIS_Message*,char*,int), void (*destroy)(gpointer),
    char **our_uuid, char **our_uname, int *nodeid)
{
    int retries = 0;
    while(retries++ < 30) {
	int rc = init_ais_connection_once(dispatch, destroy, our_uuid, our_uname, nodeid);
	switch(rc) {
	    case CS_OK:
		return TRUE;
		break;
	    case CS_ERR_TRY_AGAIN:
		break;
	    default:
		return FALSE;
	}
    }

    crm_err("Retry count exceeded: %d", retries);
    return FALSE;
}

gboolean init_ais_connection_once(
    gboolean (*dispatch)(AIS_Message*,char*,int),
    void (*destroy)(gpointer), char **our_uuid, char **our_uname, int *nodeid)
{
    int pid = 0;
    int rc = CS_OK;
    char *pid_s = NULL;
    struct utsname name;
    uint32_t local_nodeid = 0;
    char *local_uname = NULL;
    
    crm_info("Creating connection to our AIS plugin");
    rc = coroipcc_service_connect(
	COROSYNC_SOCKET_NAME, PCMK_SERVICE_ID,
	AIS_IPC_MESSAGE_SIZE, AIS_IPC_MESSAGE_SIZE, AIS_IPC_MESSAGE_SIZE,
	&ais_ipc_handle);
    if(ais_ipc_handle) {
	coroipcc_fd_get(ais_ipc_handle, &ais_fd_async);
    }
    if(ais_fd_async <= 0 && rc == CS_OK) {
	crm_err("No context created, but connection reported 'ok'");
	rc = CS_ERR_LIBRARY;
    }
    if (rc != CS_OK) {
	crm_info("Connection to our AIS plugin (%d) failed: %s (%d)", PCMK_SERVICE_ID, ais_error2text(rc), rc);
    }

    if(rc != CS_OK) {
	return rc;
    }

    if(destroy == NULL) {
	destroy = ais_destroy;
    } 

    if(dispatch) {
	ais_source = G_main_add_fd(
	    G_PRIORITY_HIGH, ais_fd_async, FALSE, ais_dispatch, dispatch, destroy);
    }
    
    crm_info("AIS connection established");
    quorum_source = get_quorum_source();
    
    pid = getpid();
    pid_s = crm_itoa(pid);
    send_ais_text(0, pid_s, TRUE, NULL, crm_msg_ais);
    crm_free(pid_s);

    crm_peer_init();
    if(uname(&name) < 0) {
	crm_perror(LOG_ERR,"uname(2) call failed");
	exit(100);
    }

    if(quorum_source == crm_quorum_cman) {
	if(init_cman_connection(dispatch, destroy)) {
	    init_cpg_connection(dispatch, destroy, &local_nodeid);
	}
	
    } else if(quorum_source == crm_quorum_corosync) {
	if(init_quorum_connection(dispatch, destroy)) {
	    init_cpg_connection(dispatch, destroy, &local_nodeid);
	}
    }
    
    if(quorum_source == crm_quorum_pacemaker) {
	get_ais_nodeid(&local_nodeid, &local_uname);
	if(safe_str_neq(name.nodename, local_uname)) {
	    crm_crit("Node name mismatch!  OpenAIS supplied %s, our lookup returned %s",
		     local_uname, name.nodename);
	    crm_notice("Node name mismatches usually occur when assigned automatically by DHCP servers");
	    crm_notice("If this node was part of the cluster with a different name,"
		       " you will need to remove the old entry with crm_node --remove");
	}

    } else {
	local_uname = crm_strdup(name.nodename);
    }
    
    if(local_nodeid != 0) {
	/* Ensure the local node always exists */
	crm_update_peer(local_nodeid, 0, 0, 0, 0, local_uname, local_uname, NULL, NULL);
    }

    if(our_uuid != NULL) {
	*our_uuid = crm_strdup(local_uname);
    }

    if(our_uname != NULL) {
	*our_uname = local_uname;
    } else {
	crm_free(local_uname);
    }

    if(nodeid != NULL) {
	*nodeid = local_nodeid;
    }

    return TRUE;
}

gboolean check_message_sanity(const AIS_Message *msg, const char *data) 
{
    gboolean sane = TRUE;
    gboolean repaired = FALSE;
    int dest = msg->host.type;
    int tmp_size = msg->header.size - sizeof(AIS_Message);

    if(sane && msg->header.size == 0) {
	crm_warn("Message with no size");
	sane = FALSE;
    }

    if(sane && msg->header.error != CS_OK) {
	crm_warn("Message header contains an error: %d", msg->header.error);
	sane = FALSE;
    }

    if(sane && ais_data_len(msg) != tmp_size) {
	crm_warn("Message payload size is incorrect: expected %d, got %d", ais_data_len(msg), tmp_size);
	sane = TRUE;
    }

    if(sane && ais_data_len(msg) == 0) {
	crm_warn("Message with no payload");
	sane = FALSE;
    }

    if(sane && data && msg->is_compressed == FALSE) {
	int str_size = strlen(data) + 1;
	if(ais_data_len(msg) != str_size) {
	    int lpc = 0;
	    crm_warn("Message payload is corrupted: expected %d bytes, got %d",
		    ais_data_len(msg), str_size);
	    sane = FALSE;
	    for(lpc = (str_size - 10); lpc < msg->size; lpc++) {
		if(lpc < 0) {
		    lpc = 0;
		}
		crm_debug("bad_data[%d]: %d / '%c'", lpc, data[lpc], data[lpc]);
	    }
	}
    }
    
    if(sane == FALSE) {
	crm_err("Invalid message %d: (dest=%s:%s, from=%s:%s.%d, compressed=%d, size=%d, total=%d)",
		msg->id, ais_dest(&(msg->host)), msg_type2text(dest),
		ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
		msg->sender.pid, msg->is_compressed, ais_data_len(msg),
		msg->header.size);
	
    } else if(repaired) {
	crm_err("Repaired message %d: (dest=%s:%s, from=%s:%s.%d, compressed=%d, size=%d, total=%d)",
		msg->id, ais_dest(&(msg->host)), msg_type2text(dest),
		ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
		msg->sender.pid, msg->is_compressed, ais_data_len(msg),
		msg->header.size);
    } else {
	crm_debug_3("Verfied message %d: (dest=%s:%s, from=%s:%s.%d, compressed=%d, size=%d, total=%d)",
		    msg->id, ais_dest(&(msg->host)), msg_type2text(dest),
		    ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
		    msg->sender.pid, msg->is_compressed, ais_data_len(msg),
		    msg->header.size);
    }
    
    return sane;
}
#endif

