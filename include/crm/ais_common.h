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

#ifndef CRM_AIS_COMMON__H
#define CRM_AIS_COMMON__H

#include <glib.h>
#include <string.h>
#include <sys/uio.h>

#if SUPPORT_AIS
#  ifdef AIS_WHITETANK 
/* cheap hacks for building against the stable series of openais */

#    include <openais/saAis.h>

enum service_types {
	EVS_SERVICE = 0,
	CLM_SERVICE = 1,
	AMF_SERVICE = 2,
	CKPT_SERVICE = 3,
	EVT_SERVICE = 4,
	LCK_SERVICE = 5,
	MSG_SERVICE = 6,
	CFG_SERVICE = 7,
	CPG_SERVICE = 8
};

typedef struct {
	int size; __attribute__((aligned(8))) 
	int id __attribute__((aligned(8)));
	SaAisErrorT error __attribute__((aligned(8)));
} mar_res_header_t __attribute__((aligned(8)));

typedef struct {
	int size __attribute__((aligned(8)));
	int id __attribute__((aligned(8)));
} mar_req_header_t __attribute__((aligned(8)));

#    ifdef TRADITIONAL_AIS_IPC
extern SaAisErrorT saSendReceiveReply (
    int s, void *requestMessage, int requestLen, void *responseMessage, int responseLen);
extern SaAisErrorT saRecvRetry (int s, void *msg, size_t len);
extern SaAisErrorT saServiceConnect (int *responseOut, int *callbackOut, enum service_types service);
#else
extern SaAisErrorT
openais_service_connect (
	enum service_types service,
	void **ipc_context);

extern SaAisErrorT
openais_service_disconnect (
	void *ipc_context);

extern int
openais_dispatch_recv (
	void *ipc_context,
	void *buf,
	int timeout);

extern SaAisErrorT
openais_msg_send_reply_receive (
	void *ipc_context,
	struct iovec *iov,
	int iov_len,
	void *res_msg,
	int res_len);

extern int openais_fd_get(void *ipc_context);
#endif

static inline const char *ais_error2text(int error) 
{
	const char *text = "unknown";
	switch(error) {
	    case SA_AIS_OK:
		text = "None";
		break;
	    case SA_AIS_ERR_LIBRARY:
		text = "Library error";
		break;
	    case SA_AIS_ERR_VERSION:
		text = "Version error";
		break;
	    case SA_AIS_ERR_INIT:
		text = "Initialization error";
		break;
	    case SA_AIS_ERR_TIMEOUT:
		text = "Timeout";
		break;
	    case SA_AIS_ERR_TRY_AGAIN:
		text = "Try again";
		break;
	    case SA_AIS_ERR_INVALID_PARAM:
		text = "Invalid parameter";
		break;
	    case SA_AIS_ERR_NO_MEMORY:
		text = "No memory";
		break;
	    case SA_AIS_ERR_BAD_HANDLE:
		text = "Bad handle";
		break;
	    case SA_AIS_ERR_BUSY:
		text = "Busy";
		break;
	    case SA_AIS_ERR_ACCESS:
		text = "Access error";
		break;
	    case SA_AIS_ERR_NOT_EXIST:
		text = "Doesn't exist";
		break;
	    case SA_AIS_ERR_NAME_TOO_LONG:
		text = "Name too long";
		break;
	    case SA_AIS_ERR_EXIST:
		text = "Exists";
		break;
	    case SA_AIS_ERR_NO_SPACE:
		text = "No space";
		break;
	    case SA_AIS_ERR_INTERRUPT:
		text = "Interrupt";
		break;
	    case SA_AIS_ERR_NAME_NOT_FOUND:
		text = "Name not found";
		break;
	    case SA_AIS_ERR_NO_RESOURCES:
		text = "No resources";
		break;
	    case SA_AIS_ERR_NOT_SUPPORTED:
		text = "Not supported";
		break;
	    case SA_AIS_ERR_BAD_OPERATION:
		text = "Bad operation";
		break;
	    case SA_AIS_ERR_FAILED_OPERATION:
		text = "Failed operation";
		break;
	    case SA_AIS_ERR_MESSAGE_ERROR:
		text = "Message error";
		break;
	    case SA_AIS_ERR_QUEUE_FULL:
		text = "Queue full";
		break;
	    case SA_AIS_ERR_QUEUE_NOT_AVAILABLE:
		text = "Queue not available";
		break;
	    case SA_AIS_ERR_BAD_FLAGS:
		text = "Bad flags";
		break;
	    case SA_AIS_ERR_TOO_BIG:
		text = "To big";
		break;
	    case SA_AIS_ERR_NO_SECTIONS:
		text = "No sections";
		break;
	}
	return text;
}

#  endif
#  ifdef AIS_COROSYNC
#    include <corosync/ais_util.h>
#    include <corosync/ipc_gen.h>

#define SA_AIS_OK CS_OK
#define SA_AIS_ERR_TRY_AGAIN CS_ERR_TRY_AGAIN
#define SA_AIS_OK CS_OK

static inline const char *ais_error2text(int error) 
{
	const char *text = "unknown";
	switch(error) {
	    case CS_OK:
		text = "None";
		break;
	    case CS_ERR_LIBRARY:
		text = "Library error";
		break;
	    case CS_ERR_VERSION:
		text = "Version error";
		break;
	    case CS_ERR_INIT:
		text = "Initialization error";
		break;
	    case CS_ERR_TIMEOUT:
		text = "Timeout";
		break;
	    case CS_ERR_TRY_AGAIN:
		text = "Try again";
		break;
	    case CS_ERR_INVALID_PARAM:
		text = "Invalid parameter";
		break;
	    case CS_ERR_NO_MEMORY:
		text = "No memory";
		break;
	    case CS_ERR_BAD_HANDLE:
		text = "Bad handle";
		break;
	    case CS_ERR_BUSY:
		text = "Busy";
		break;
	    case CS_ERR_ACCESS:
		text = "Access error";
		break;
	    case CS_ERR_NOT_EXIST:
		text = "Doesn't exist";
		break;
	    case CS_ERR_NAME_TOO_LONG:
		text = "Name too long";
		break;
	    case CS_ERR_EXIST:
		text = "Exists";
		break;
	    case CS_ERR_NO_SPACE:
		text = "No space";
		break;
	    case CS_ERR_INTERRUPT:
		text = "Interrupt";
		break;
	    case CS_ERR_NAME_NOT_FOUND:
		text = "Name not found";
		break;
	    case CS_ERR_NO_RESOURCES:
		text = "No resources";
		break;
	    case CS_ERR_NOT_SUPPORTED:
		text = "Not supported";
		break;
	    case CS_ERR_BAD_OPERATION:
		text = "Bad operation";
		break;
	    case CS_ERR_FAILED_OPERATION:
		text = "Failed operation";
		break;
	    case CS_ERR_MESSAGE_ERROR:
		text = "Message error";
		break;
	    case CS_ERR_QUEUE_FULL:
		text = "Queue full";
		break;
	    case CS_ERR_QUEUE_NOT_AVAILABLE:
		text = "Queue not available";
		break;
	    case CS_ERR_BAD_FLAGS:
		text = "Bad flags";
		break;
	    case CS_ERR_TOO_BIG:
		text = "To big";
		break;
	    case CS_ERR_NO_SECTIONS:
		text = "No sections";
		break;
	}
	return text;
}

#  endif
#else
typedef struct {
	int size __attribute__((aligned(8)));
	int id __attribute__((aligned(8)));
} mar_req_header_t __attribute__((aligned(8)));

typedef struct {
	int size; __attribute__((aligned(8))) 
	int id __attribute__((aligned(8)));
	int error __attribute__((aligned(8)));
} mar_res_header_t __attribute__((aligned(8)));
#endif

#define CRM_SERVICE             9
#define CRM_MESSAGE_IPC_ACK     0

#define MAX_NAME	256
#define AIS_IPC_NAME  "ais-crm-ipc"

#define CRM_NODE_LOST      "lost"
#define CRM_NODE_MEMBER    "member"
#define CRM_NODE_ACTIVE    CRM_NODE_MEMBER
#define CRM_NODE_INACTIVE  CRM_NODE_LOST
#define CRM_NODE_EVICTED   "evicted"

typedef struct crm_ais_host_s AIS_Host;
typedef struct crm_ais_msg_s AIS_Message;

enum crm_ais_msg_class {
    crm_class_cluster = 0,
    crm_class_members = 1,
    crm_class_notify  = 2,
    crm_class_nodeid  = 3,
    crm_class_rmpeer  = 4,
};

/* order here matters - its used to index into the crm_children array */
enum crm_ais_msg_types {
    crm_msg_none     = 0,
    crm_msg_ais      = 1,
    crm_msg_lrmd     = 2,
    crm_msg_cib      = 3,
    crm_msg_crmd     = 4,
    crm_msg_attrd    = 5,
    crm_msg_stonithd = 6,
    crm_msg_te       = 7,
    crm_msg_pe       = 8,
};

enum crm_proc_flag {
    crm_proc_none    = 0x00000001,
    crm_proc_ais     = 0x00000002,
    crm_proc_lrmd    = 0x00000010,
    crm_proc_cib     = 0x00000100,
    crm_proc_crmd    = 0x00000200,
    crm_proc_attrd   = 0x00001000,
    crm_proc_stonithd = 0x00002000,
    crm_proc_pe      = 0x00010000,
    crm_proc_te      = 0x00020000,
    crm_proc_mgmtd   = 0x00040000,
};

typedef struct crm_peer_node_s 
{
	uint32_t id;
	uint64_t born;
	uint64_t last_seen;

	int32_t votes;
	uint32_t processes;

	char *uname;
	char *state;
	char *uuid;
	char *addr;
	char *version;
} crm_node_t;

struct crm_ais_host_s
{
	uint32_t		id;
	uint32_t		pid;
	gboolean		local;
	enum crm_ais_msg_types	type;
	uint32_t		size;
	char			uname[256];

} __attribute__((packed));

struct crm_ais_msg_s
{
	mar_res_header_t	header __attribute__((aligned(8)));
	uint32_t		id;
	gboolean		is_compressed;
	
	AIS_Host		host;
	AIS_Host		sender;
	
	uint32_t		size;
	uint32_t		compressed_size;
	/* 584 bytes */
	char			data[0];
	
} __attribute__((packed));

struct crm_ais_nodeid_resp_s
{
	mar_res_header_t	header __attribute__((aligned(8)));
	uint32_t		id;	
	uint32_t		counter;
	char			uname[256];
} __attribute__((packed));


static inline const char *msg_type2text(enum crm_ais_msg_types type) 
{
	const char *text = "unknown";
	switch(type) {
		case crm_msg_none:
			text = "unknown";
			break;
		case crm_msg_ais:
			text = "ais";
			break;
		case crm_msg_cib:
			text = "cib";
			break;
		case crm_msg_crmd:
			text = "crmd";
			break;
		case crm_msg_pe:
			text = "pengine";
			break;
		case crm_msg_te:
			text = "tengine";
			break;
		case crm_msg_lrmd:
			text = "lrmd";
			break;
		case crm_msg_attrd:
			text = "attrd";
			break;
		case crm_msg_stonithd:
			text = "stonithd";
			break;
	}
	return text;
}

static inline const char *peer2text(enum crm_proc_flag proc) 
{
	const char *text = "unknown";
	switch(proc) {
		case crm_proc_none:
			text = "unknown";
			break;
		case crm_proc_ais:
			text = "ais";
			break;
		case crm_proc_cib:
			text = "cib";
			break;
		case crm_proc_crmd:
			text = "crmd";
			break;
		case crm_proc_pe:
			text = "pengine";
			break;
		case crm_proc_te:
			text = "tengine";
			break;
		case crm_proc_lrmd:
			text = "lrmd";
			break;
		case crm_proc_attrd:
			text = "attrd";
			break;	
		case crm_proc_stonithd:
			text = "stonithd";
			break;
		case crm_proc_mgmtd:
			text = "mgmtd";
			break;
	}
	return text;
}

static inline const char *ais_dest(struct crm_ais_host_s *host) 
{
    if(host->local) {
	return "local";
    } else if(host->size > 0) {
	return host->uname;
    } else {
	return "<all>";
    }
}

#define ais_data_len(msg) (msg->is_compressed?msg->compressed_size:msg->size)

#endif
