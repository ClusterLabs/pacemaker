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

#include <crm/ais.h>
#include <openais/saAis.h>
/* #include <openais/ipc_gen.h> */
#include <openais/ipc_util.h>

int ais_fd_in = -1;
int ais_fd_out = -1;
GFDSource *ais_source = NULL;

enum crm_ais_msg_types text2msg_type(const char *text) 
{
	int type = -1;

	CRM_CHECK(text != NULL, return type);
	if(safe_str_eq(text, "ais")) {
		type = crm_msg_ais;
	} else if(safe_str_eq(text, CRM_SYSTEM_CIB)) {
		type = crm_msg_cib;
	} else if(safe_str_eq(text, CRM_SYSTEM_CRMD)) {
		type = crm_msg_crmd;
	} else if(safe_str_eq(text, CRM_SYSTEM_TENGINE)) {
		type = crm_msg_te;
	} else if(safe_str_eq(text, CRM_SYSTEM_PENGINE)) {
		type = crm_msg_pe;
	} else if(safe_str_eq(text, CRM_SYSTEM_LRMD)) {
		type = crm_msg_lrmd;
	} else {
		crm_err("Unknown message type: %s", text);
	}
	return type;
}

const char *msg_type2text(enum crm_ais_msg_types type) 
{
	const char *text = "<unknown>";
	switch(type) {
		case crm_msg_ais:
			text = "ais";
			break;
		case crm_msg_cib:
			text = CRM_SYSTEM_CIB;
			break;
		case crm_msg_crmd:
			text = CRM_SYSTEM_CRMD;
			break;
		case crm_msg_pe:
			text = CRM_SYSTEM_PENGINE;
			break;
		case crm_msg_te:
			text = CRM_SYSTEM_TENGINE;
			break;
		case crm_msg_lrmd:
			text = CRM_SYSTEM_LRMD;
			break;
		default:
			crm_err("Unknown message type: %d", type);
			break;
	}
	return text;
}

static gboolean ais_dispatch(int sender, gpointer user_data)
{
    /* Grab the header */
    char *header = NULL;
    char *data = NULL;
    AIS_Message *msg = NULL;
    SaAisErrorT rc = SA_AIS_OK;
    static int header_len = sizeof(AIS_Message);

    crm_err("Got a message: %d", header_len);
    crm_malloc0(header, header_len);
    
    rc = saRecvRetry(sender, header, header_len);
    if (rc != SA_AIS_OK) {
	crm_err("Receiving message header failed");
	goto bail;
    }

    msg = (void*)header;
    do_crm_log(LOG_NOTICE, "Msg[%d] (dest=%s:%s, from=%s:%s, size=%d, total=%d)",
	       msg->id,
	       msg->host.uname?msg->host.uname:"<all>",
	       msg_type2text(msg->host.type),
	       msg->sender.uname, msg_type2text(msg->sender.type),
	       msg->size, msg->header.size);
    
/*     crm_realloc(msg, msg->header.size+10); */
    crm_malloc0(data, msg->size+1);
    rc = saRecvRetry(sender, data, msg->size+1);
    if (rc != SA_AIS_OK) {
	crm_err("Receiving message body failed");
	goto bail;
    }

    crm_notice("Message received: '%.50s'", data);

    return TRUE;
    
  bail:
    crm_err("AIS connection failed");
    return FALSE;
}

static void
ais_destroy(gpointer user_data)
{
    crm_err("AIS connection terminated");
    ais_fd_in = -1;
    exit(1);
}

gboolean
send_ais_message(crm_data_t *msg, enum crm_ais_msg_types sender,
		 const char *node, enum crm_ais_msg_types dest)
{
    static int msg_id = 0;

    int rc = SA_AIS_OK;
    AIS_Message *ais_msg = NULL;
    char *data = dump_xml_unformatted(msg);
    int data_len = strlen(data);

    if(ais_source == NULL && init_ais_connection() == FALSE) {
	crm_err("Cannot connect to AIS");
	return FALSE;
    }
    
    if(ais_fd_out < 0) {
	crm_err("Not connected to AIS");
	return FALSE;
    }
    
    crm_malloc0(ais_msg, sizeof(AIS_Message) + data_len + 1);
    
    ais_msg->id = msg_id++;
    ais_msg->header.size = sizeof (AIS_Message);
    ais_msg->header.id = 0;
    
    ais_msg->size = data_len;
    memcpy(ais_msg->data, data, ais_msg->size);
    
    ais_msg->host.type = dest;
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
    ais_msg->sender.size = 0;
    memset(ais_msg->sender.uname, 0, MAX_NAME);
    ais_msg->sender.id = 0;
    
    crm_notice("Sending message %d", ais_msg->id);

    rc = saSendRetry (ais_fd_out, ais_msg, sizeof(AIS_Message) + data_len + 1);
    if(rc != SA_AIS_OK) {    
	crm_err("Sending message %d: FAILED", ais_msg->id);
	ais_fd_out = -1;
    }
    
    crm_notice("Message %d: sent", ais_msg->id);
    return (rc == SA_AIS_OK);
}


gboolean init_ais_connection(void) 
{
    int rc = SA_AIS_OK;
    crm_notice("Creating connection to our AIS plugin");

    /* 16 := CRM_SERVICE */
    rc = saServiceConnect (&ais_fd_in, &ais_fd_out, 16);
    if (rc != SA_AIS_OK) {
	crm_err("Connection to our AIS plugin failed!");
	return FALSE;
    }

    crm_notice("AIS connection established");
    ais_source = G_main_add_fd(
	G_PRIORITY_HIGH, ais_fd_in, FALSE, ais_dispatch, NULL, ais_destroy);
    ais_source = G_main_add_fd(
	G_PRIORITY_HIGH, ais_fd_out, FALSE, ais_dispatch, NULL, ais_destroy);
    return TRUE;
}
