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

#ifndef AIS_CRM_UTILS__H
#define AIS_CRM_UTILS__H

#include <syslog.h>
static inline int libais_connection_active(void *conn) {
    if(conn != NULL) { return TRUE; }
    return FALSE;
}
    
#ifdef AIS_WHITETANK
#  include <openais/service/objdb.h>
#  include <openais/service/print.h>

#  define OPENAIS_EXTERNAL_SERVICE insane_ais_header_hack_in__totem_h
#  include <openais/saAis.h>
#  include <openais/service/swab.h>
#  include <openais/totem/totempg.h>
#  include <openais/service/service.h>
#  include <openais/lcr/lcr_comp.h>
#  include <openais/lcr/lcr_ifact.h>
#  include <openais/service/config.h>
#  define COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED OPENAIS_FLOW_CONTROL_NOT_REQUIRED 

typedef struct objdb_iface_ver0 plugin_init_type;
typedef struct openais_lib_handler plugin_lib_handler;
typedef struct openais_exec_handler plugin_exec_handler;
typedef struct openais_service_handler plugin_service_handler;
typedef unsigned int hdb_handle_t;
extern int openais_response_send (void *conn, void *msg, int mlen);
extern int openais_dispatch_send (void *conn, void *msg, int mlen);

#endif

#ifdef AIS_COROSYNC
#  include <corosync/engine/objdb.h>
#  include <corosync/engine/logsys.h>
#  include <corosync/swab.h>
#  include <corosync/corodefs.h>
#  include <corosync/coroipc_types.h>
#  include <corosync/mar_gen.h>
#  include <corosync/engine/coroapi.h>
#  include <corosync/lcr/lcr_comp.h>
#  include <corosync/lcr/lcr_ifact.h>

typedef struct corosync_api_v1 plugin_init_type;
typedef struct corosync_lib_handler plugin_lib_handler;
typedef struct corosync_exec_handler plugin_exec_handler;
typedef struct corosync_service_engine plugin_service_handler;
LOGSYS_DECLARE_SUBSYS("crm");

#endif

/* #include "plugin.h" */
#define 	SIZEOF(a)   (sizeof(a) / sizeof(a[0]))

typedef struct crm_child_s {
	int pid;
	long flag;
	long flags;
	int start_seq;
	int respawn_count;
	gboolean respawn;
	const char *name;
	const char *uid;
	const char *command;
	void *conn;
	void *async_conn;
    
} crm_child_t;

extern void destroy_ais_node(gpointer data);
extern void delete_member(uint32_t id, const char *uname);
extern int update_member(
    unsigned int id, uint64_t born, uint64_t seq, int32_t votes,
    uint32_t procs, const char *uname, const char *state, const char *version);

extern const char *member_uname(uint32_t id);
extern char *append_member(char *data, crm_node_t *node);
extern void member_loop_fn(gpointer key, gpointer value, gpointer user_data);

extern gboolean stop_child(crm_child_t *child, int signal);
extern gboolean spawn_child(crm_child_t *child);

extern void swap_sender(AIS_Message *msg);
extern char *get_ais_data(const AIS_Message *msg);

extern gboolean route_ais_message(const AIS_Message *msg, gboolean local);
extern gboolean process_ais_message(const AIS_Message *msg);

extern int send_cluster_msg(
    enum crm_ais_msg_types type, const char *host, const char *data);
extern int send_client_msg(void *conn, enum crm_ais_msg_class class,
			   enum crm_ais_msg_types type, const char *data);
extern void send_member_notification(void);
extern void log_ais_message(int level, const AIS_Message *msg);

extern hdb_handle_t config_find_init(plugin_init_type *config, char *name);
extern hdb_handle_t config_find_next(plugin_init_type *config, char *name, hdb_handle_t top_handle);
extern void config_find_done(plugin_init_type *config, hdb_handle_t local_handle);
extern int get_config_opt(plugin_init_type *config,
			  hdb_handle_t object_service_handle,
			  char *key, char **value, const char *fallback);

extern int ais_get_boolean(const char *s);
extern long long ais_get_int(const char *text, char **end_text);
extern char *ais_concat(const char *prefix, const char *suffix, char join);
extern int send_client_ipc(void *conn, const AIS_Message *ais_msg);

extern GHashTable *membership_list;
extern pthread_t crm_wait_thread;
extern int plugin_log_level;
extern char *local_uname;
extern int local_uname_len;
extern unsigned int local_nodeid;
extern int in_shutdown;

static inline const char *level2char(int level)
{
    switch(level) {
	case LOG_CRIT: return "CRIT";
	case LOG_ERR: return "ERROR";
	case LOG_WARNING: return "WARN";
	case LOG_NOTICE: return "notice";
	case LOG_INFO: return "info";
    }
    return "debug";
}

#define do_ais_log(level, fmt, args...) do {				\
	if(plugin_log_level < (level)) {				\
	    continue;							\
	} else if((level) > LOG_DEBUG) {				\
	    log_printf(LOG_DEBUG, "debug%d: %s: " fmt,			\
		       level-LOG_INFO, __PRETTY_FUNCTION__ , ##args);	\
	} else {							\
	    log_printf(level, "%s: %s: " fmt, level2char(level),	\
		       __PRETTY_FUNCTION__ , ##args);			\
	}								\
    } while(0)

#define ais_perror(fmt, args...) log_printf(				\
	LOG_ERR, "%s: " fmt ": (%d) %s",				\
	__PRETTY_FUNCTION__ , ##args, errno, strerror(errno))

#define ais_crit(fmt, args...)    do_ais_log(LOG_CRIT,    fmt , ##args)
#define ais_err(fmt, args...)     do_ais_log(LOG_ERR,     fmt , ##args)
#define ais_warn(fmt, args...)    do_ais_log(LOG_WARNING, fmt , ##args)
#define ais_notice(fmt, args...)  do_ais_log(LOG_NOTICE,  fmt , ##args)
#define ais_info(fmt, args...)    do_ais_log(LOG_INFO,    fmt , ##args)
#define ais_debug(fmt, args...)   do_ais_log(LOG_DEBUG,   fmt , ##args)
#define ais_debug_2(fmt, args...) do_ais_log(LOG_DEBUG+1, fmt , ##args)
#define ais_debug_3(fmt, args...) do_ais_log(LOG_DEBUG+2, fmt , ##args)
#define ais_debug_4(fmt, args...) do_ais_log(LOG_DEBUG+3, fmt , ##args)
#define ais_debug_5(fmt, args...) do_ais_log(LOG_DEBUG+4, fmt , ##args)
#define ais_debug_6(fmt, args...) do_ais_log(LOG_DEBUG+5, fmt , ##args)

#define ais_malloc0(malloc_obj, length) do {				\
	malloc_obj = malloc(length);					\
	if(malloc_obj == NULL) {					\
	    abort();							\
	}								\
	memset(malloc_obj, 0, length);					\
    } while(0)

#define ais_free(obj) do {			\
	if(obj) {				\
	    free(obj);				\
	    obj = NULL;				\
	}					\
    } while(0)

#define AIS_ASSERT(expr) if((expr) == FALSE) {				\
	ais_crit("Assertion failure line %d: %s", __LINE__, #expr);	\
	abort();							\
    }

#define AIS_CHECK(expr, failure_action) if((expr) == FALSE) {		\
	int p = fork();							\
	if(p == 0) { abort(); }						\
	ais_err("Child %d spawned to record non-fatal assertion failure line %d: %s", p, __LINE__, #expr); \
	failure_action;							\
    }

static inline char *ais_strdup(const char *src)
{
	char *dup = NULL;
	if(src == NULL) {
	    return NULL;
	}
	ais_malloc0(dup, strlen(src) + 1);
	return strcpy(dup, src);
}

static inline gboolean ais_str_eq(const char *a, const char *b) 
{
    if(a == NULL || b == NULL) {
	return FALSE;
	
    } else if(a == b) {
	return TRUE;
	
    } else if(strcasecmp(a, b) == 0) {
	return TRUE;
    }
    return FALSE;
}

#endif
