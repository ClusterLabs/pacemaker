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
#include <openais/saAis.h>
#include <sys/utsname.h>
#include "stack.h"
#include <clplumbing/timers.h>
#include <clplumbing/Gmain_timeout.h>

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
	} else if(safe_str_eq(text, "attrd")) {
		type = crm_msg_attrd;
	} else {
		crm_debug_2("Unknown message type: %s", text);
	}
	return type;
}

char *get_ais_data(AIS_Message *msg)
{
    int rc = BZ_OK;
    char *uncompressed = NULL;
    unsigned int new_size = msg->size;
    
    if(msg->is_compressed == FALSE) {
	crm_debug_2("Returning uncompressed message data");
	uncompressed = strdup(msg->data);

    } else {
	crm_debug_2("Decompressing message data");
	crm_malloc0(uncompressed, new_size);
	
	rc = BZ2_bzBuffToBuffDecompress(
	    uncompressed, &new_size, msg->data, msg->compressed_size, 1, 0);
	
	CRM_ASSERT(rc = BZ_OK);
	CRM_ASSERT(new_size == msg->size);
    }
    
    return uncompressed;
}


#if SUPPORT_AIS
int ais_fd_sync = -1;
static int ais_fd_async = -1; /* never send messages via this channel */
GFDSource *ais_source = NULL;
GFDSource *ais_source_sync = NULL;

gboolean
send_ais_text(int class, const char *data,
	      gboolean local, const char *node, enum crm_ais_msg_types dest)
{
    int retries = 0;
    static int msg_id = 0;
    static int local_pid = 0;

    int rc = SA_AIS_OK;
    mar_res_header_t header;
    AIS_Message *ais_msg = NULL;
    enum crm_ais_msg_types sender = text2msg_type(crm_system_name);

    if(local_pid == 0) {
	local_pid = getpid();
    }

    CRM_CHECK(data != NULL, return FALSE);
    crm_malloc0(ais_msg, sizeof(AIS_Message));
    
    ais_msg->id = msg_id++;
    ais_msg->header.id = class;
    
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
    
    ais_msg->sender.type = sender;
    ais_msg->sender.pid = local_pid;
    ais_msg->sender.size = 0;
    memset(ais_msg->sender.uname, 0, MAX_NAME);
    ais_msg->sender.id = 0;
    
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

  retry:
    errno = 0;
    rc = saSendReceiveReply(ais_fd_sync, ais_msg, ais_msg->header.size,
			    &header, sizeof (mar_res_header_t));
    if(rc == SA_AIS_OK) {
	CRM_CHECK(header.size == sizeof (mar_res_header_t),
		  crm_err("Odd message: id=%d, size=%d, error=%d",
			  header.id, header.size, header.error));
	CRM_CHECK(header.error == SA_AIS_OK, rc = header.error);
    }

    if(rc == SA_AIS_ERR_TRY_AGAIN && retries < 20) {
	retries++;
	crm_info("Peer overloaded: Re-sending message (Attempt %d of 20)", retries);
	mssleep(retries * 100); /* Proportional back off */
	goto retry;
    }

    if(rc != SA_AIS_OK) {    
	cl_perror("Sending message %d: FAILED (rc=%d): %s",
		  ais_msg->id, rc, ais_error2text(rc));
	ais_fd_async = -1;
    } else {
	crm_debug_4("Message %d: sent", ais_msg->id);
    }

    crm_free(ais_msg);
    return (rc == SA_AIS_OK);
}

gboolean
send_ais_message(xmlNode *msg, 
		 gboolean local, const char *node, enum crm_ais_msg_types dest)
{
    gboolean rc = TRUE;
    char *data = NULL;

    if(ais_fd_async < 0 || ais_source == NULL) {
	crm_err("Not connected to AIS");
	return FALSE;
    }

    data = dump_xml_unformatted(msg);
    rc = send_ais_text(0, data, local, node, dest);
    crm_free(data);
    return rc;
}

void terminate_ais_connection(void) 
{
    close(ais_fd_sync);
    close(ais_fd_async);
    crm_notice("Disconnected from AIS");
/*     G_main_del_fd(ais_source); */
/*     G_main_del_fd(ais_source_sync);     */
}

int ais_membership_timer = 0;
gboolean ais_membership_force = FALSE;

static gboolean ais_membership_dampen(gpointer data)
{
    crm_debug_2("Requesting cluster membership after stabilization delay");
    send_ais_text(crm_class_members, __FUNCTION__, TRUE, NULL, crm_msg_ais);
    ais_membership_force = TRUE;
    ais_membership_timer = 0;
    return FALSE; /* never repeat automatically */
}


static gboolean ais_dispatch(int sender, gpointer user_data)
{
    char *data = NULL;
    char *uncompressed = NULL;

    AIS_Message *msg = NULL;
    SaAisErrorT rc = SA_AIS_OK;
    mar_res_header_t *header = NULL;
    static int header_len = sizeof(mar_res_header_t);
    gboolean (*dispatch)(AIS_Message*,char*,int) = user_data;

    crm_malloc0(header, header_len);
    
    errno = 0;
    rc = saRecvRetry(sender, header, header_len);
    if (rc != SA_AIS_OK) {
	cl_perror("Receiving message header failed: (%d) %s", rc, ais_error2text(rc));
	goto bail;

    } else if(header->size == header_len) {
	crm_err("Empty message: id=%d, size=%d, error=%d, header_len=%d",
		header->id, header->size, header->error, header_len);
	goto done;
	
    } else if(header->size == 0 || header->size < header_len) {
	crm_err("Mangled header: size=%d, header=%d, error=%d",
		header->size, header_len, header->error);
	goto done;
	
    } else if(header->error != 0) {
	crm_err("Header contined error: %d", header->error);
    }
    
    crm_debug_2("Looking for %d (%d - %d) more bytes",
		header->size - header_len, header->size, header_len);

    crm_realloc(header, header->size);
    /* Use a char* so we can store the remainder into an offset */
    data = (char*)header;

    errno = 0;
    rc = saRecvRetry(sender, data+header_len, header->size - header_len);
    msg = (AIS_Message*)data;

    if (rc != SA_AIS_OK) {
	cl_perror("Receiving message body failed: (%d) %s", rc, ais_error2text(rc));
	goto bail;
    }
    
    crm_debug_3("Got new%s message (size=%d, %d, %d)",
		msg->is_compressed?" compressed":"",
		ais_data_len(msg), msg->size, msg->compressed_size);
    
    data = msg->data;
    if(msg->is_compressed && msg->size > 0) {
	int rc = BZ_OK;
	unsigned int new_size = msg->size;

	if(check_message_sanity(msg, NULL) == FALSE) {
	    goto badmsg;
	}

	crm_debug_5("Decompressing message data");
	crm_malloc0(uncompressed, new_size);
	rc = BZ2_bzBuffToBuffDecompress(
	    uncompressed, &new_size, data, msg->compressed_size, 1, 0);

	if(rc != BZ_OK) {
	    crm_err("Decompression failed: %d", rc);
	    crm_free(uncompressed);
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

    if(msg->header.id == crm_class_members) {
	xmlNode *xml = string2xml(data);

	if(xml != NULL) {
	    gboolean do_ask = FALSE;
	    gboolean do_process = TRUE;
	    
	    int seq = 0;
	    int new_size = 0;
	    int current_size = crm_active_members();

	    const char *reason = "unknown";

	    crm_element_value_int(xml, "id", &seq);
	    crm_debug_2("Received membership %d", seq);

	    xml_child_iter(xml, node,
			   const char *state = crm_element_value(node, "state");
			   if(safe_str_eq(state, CRM_NODE_MEMBER)) {
			       new_size++;
			   }
		);

	    if(ais_membership_force) {
		/* always process */
		crm_debug_2("Processing delayed membership change");
		
	    } else if(current_size == 0 && new_size == 1) {
		do_ask = TRUE;
		do_process = FALSE;
		reason = "We've come up alone";

	    } else if(new_size < (current_size/2)) {
		do_process = FALSE;
		reason = "We've lost more than half our peers";

		if(ais_membership_timer == 0) {
		    reason = "We've lost more than half our peers";
		    crm_log_xml_debug(xml, __PRETTY_FUNCTION__);
		    do_ask = TRUE;
		}		
	    }
	    
	    if(do_process) {
		crm_info("Processing membership %d", seq);

/*		crm_log_xml_debug(xml, __PRETTY_FUNCTION__); */
		if(ais_membership_force) {
		    ais_membership_force = FALSE;
		}

		/* if there is a timer running - let it run
		 * there is no harm in getting an extra membership message
		 */
		
		xml_child_iter(xml, node, crm_update_ais_node(node, seq));
		crm_calculate_quorum();

	    } else if(do_ask) {
		dispatch = NULL;
		crm_warn("Pausing to allow membership stability (size %d -> %d): %s",
			 current_size, new_size, reason);
		ais_membership_timer = Gmain_timeout_add(2*1000, ais_membership_dampen, NULL);

	    } else {
		dispatch = NULL;
		crm_warn("Membership is still unstable (size %d -> %d): %s",
			current_size, new_size, reason);
	    }
	    
	} else {
	    crm_warn("Invalid peer update: %s", data);
	}

	free_xml(xml);
    }

    if(dispatch != NULL) {
	dispatch(msg, data, sender);
    }
    
  done:
    crm_free(uncompressed);
    crm_free(msg);
    return TRUE;

  badmsg:
    crm_err("Invalid message (id=%d, dest=%s:%s, from=%s:%s.%d):"
	    " min=%d, total=%d, size=%d, bz2_size=%d",
	    msg->id, ais_dest(&(msg->host)), msg_type2text(msg->host.type),
	    ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
	    msg->sender.pid, (int)sizeof(AIS_Message),
	    msg->header.size, msg->size, msg->compressed_size);
    goto done;
    
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

gboolean init_ais_connection(
    gboolean (*dispatch)(AIS_Message*,char*,int),
    void (*destroy)(gpointer), char **our_uuid, char **our_uname)
{
    int retries = 0;
    int rc = SA_AIS_OK;
    struct utsname name;

    if(our_uname != NULL) {
	if(uname(&name) < 0) {
	    cl_perror("uname(2) call failed");
	    exit(100);
	}
	*our_uname = crm_strdup(name.nodename);
	crm_notice("Local node name: %s", *our_uname);
    }
    
    if(our_uuid != NULL) {
	*our_uuid = crm_strdup(name.nodename);
    }

    /* 16 := CRM_SERVICE */
  retry:
    crm_info("Creating connection to our AIS plugin");
    rc = saServiceConnect (&ais_fd_sync, &ais_fd_async, 16);
    if (rc != SA_AIS_OK) {
	crm_info("Connection to our AIS plugin failed: %s (%d)", ais_error2text(rc), rc);
    }

    switch(rc) {
	case SA_AIS_OK:
	    break;
	case SA_AIS_ERR_TRY_AGAIN:
	    if(retries < 30) {
		sleep(1);
		retries++;
		goto retry;
	    }
	    crm_err("Retry count exceeded");
	    return FALSE;
	default:
	    return FALSE;
    }

    if(destroy == NULL) {
	crm_debug("Using the default destroy handler");
	destroy = ais_destroy;
    } 
   
    crm_info("AIS connection established");

#if 0
    ais_source_sync = G_main_add_fd(
	G_PRIORITY_HIGH, ais_fd_sync, FALSE, ais_dispatch, dispatch, destroy);
#endif
    {
	int pid = getpid();
	char *pid_s = crm_itoa(pid);
	send_ais_text(0, pid_s, TRUE, NULL, crm_msg_ais);
	crm_free(pid_s);
    }

    ais_source = G_main_add_fd(
 	G_PRIORITY_HIGH, ais_fd_async, FALSE, ais_dispatch, dispatch, destroy);
    return TRUE;
}

gboolean check_message_sanity(AIS_Message *msg, char *data) 
{
    gboolean sane = TRUE;
    gboolean repaired = FALSE;
    int dest = msg->host.type;
    int tmp_size = msg->header.size - sizeof(AIS_Message);

    if(sane && msg->header.size == 0) {
	crm_warn("Message with no size");
	sane = FALSE;
    }

    if(sane && msg->header.error != 0) {
	crm_warn("Message header contains an error: %d", msg->header.error);
	sane = FALSE;
    }

    if(sane && ais_data_len(msg) != tmp_size) {
	int cur_size = ais_data_len(msg);

	repaired = TRUE;
	if(msg->is_compressed) {
	    msg->compressed_size = tmp_size;
	    
	} else {
	    msg->size = tmp_size;
	}
	
	crm_warn("Repaired message payload size %d -> %d", cur_size, tmp_size);
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

