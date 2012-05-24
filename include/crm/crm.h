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
#ifndef CRM__H
#  define CRM__H

#  include <crm_config.h>
#  include <stdlib.h>
#  include <glib.h>
#  include <stdbool.h>
#  include <assert.h>

#  undef MIN
#  undef MAX
#  include <string.h>

#  if LIBQB_LOGGING
#    include <qb/qblog.h>
#  else
#    include <clplumbing/cl_log.h>
#  endif

#  include <libxml/tree.h>

int log_data_element(int log_level, const char *file, const char *function, int line,
                            const char *prefix, xmlNode * data, int depth, gboolean formatted);

#  define CRM_FEATURE_SET		"3.0.6"
#  define MINIMUM_SCHEMA_VERSION	"pacemaker-1.0"
#  define LATEST_SCHEMA_VERSION	"pacemaker-"CRM_DTD_VERSION

#  define EOS		'\0'
#  define DIMOF(a)	((int) (sizeof(a)/sizeof(a[0])) )

#  ifndef __GNUC__
#    define __builtin_expect(expr, result) (expr)
#  endif

/* Some handy macros used by the Linux kernel */
#  define __likely(expr) __builtin_expect(expr, 1)
#  define __unlikely(expr) __builtin_expect(expr, 0)

#  define CRM_DEPRECATED_SINCE_2_0_1 0
#  define CRM_DEPRECATED_SINCE_2_0_2 0
#  define CRM_DEPRECATED_SINCE_2_0_3 0
#  define CRM_DEPRECATED_SINCE_2_0_4 0
#  define CRM_DEPRECATED_SINCE_2_0_5 0
#  define CRM_DEPRECATED_SINCE_2_0_6 1
#  define CRM_DEPRECATED_SINCE_2_0_7 1
#  define CRM_DEPRECATED_SINCE_2_0_8 1
#  define CRM_DEPRECATED_SINCE_2_1_0 1

#  define CRM_META			"CRM_meta"

#  define CRM_ASSERT(expr) do {						\
	if(__unlikely((expr) == FALSE)) {				\
	    crm_abort(__FILE__, __PRETTY_FUNCTION__, __LINE__, #expr, TRUE, FALSE); \
	}								\
    } while(0)

extern const char *crm_system_name;

/* *INDENT-OFF* */

/* Clean these up at some point, some probably should be runtime options */
#  define SOCKET_LEN	1024
#  define APPNAME_LEN	256
#  define MAX_IPC_FAIL	5
#  define MAX_IPC_DELAY   120

#  define MSG_LOG			1
#  define DOT_FSA_ACTIONS		1
#  define DOT_ALL_FSA_INPUTS	1
/* #define FSA_TRACE		1 */

#  define INFINITY_S        "INFINITY"
#  define MINUS_INFINITY_S "-INFINITY"

#  define INFINITY        1000000

/* Sub-systems */
#  define CRM_SYSTEM_DC		"dc"
#  define CRM_SYSTEM_DCIB		"dcib"
                                        /*  The master CIB */
#  define CRM_SYSTEM_CIB		"cib"
#  define CRM_SYSTEM_CRMD		"crmd"
#  define CRM_SYSTEM_LRMD		"lrmd"
#  define CRM_SYSTEM_PENGINE	"pengine"
#  define CRM_SYSTEM_TENGINE	"tengine"
#  define CRM_SYSTEM_STONITHD	"stonithd"
#  define CRM_SYSTEM_MCP	"pacemakerd"

/* Valid operations */
#  define CRM_OP_NOOP		"noop"

#  define CRM_OP_JOIN_ANNOUNCE	"join_announce"
#  define CRM_OP_JOIN_OFFER	"join_offer"
#  define CRM_OP_JOIN_REQUEST	"join_request"
#  define CRM_OP_JOIN_ACKNAK	"join_ack_nack"
#  define CRM_OP_JOIN_CONFIRM	"join_confirm"

#  define CRM_OP_DIE		"die_no_respawn"
#  define CRM_OP_RETRIVE_CIB	"retrieve_cib"
#  define CRM_OP_PING		"ping"
#  define CRM_OP_VOTE		"vote"
#  define CRM_OP_NOVOTE		"no-vote"
#  define CRM_OP_HELLO		"hello"
#  define CRM_OP_HBEAT		"dc_beat"
#  define CRM_OP_PECALC		"pe_calc"
#  define CRM_OP_ABORT		"abort"
#  define CRM_OP_QUIT		"quit"
#  define CRM_OP_LOCAL_SHUTDOWN 	"start_shutdown"
#  define CRM_OP_SHUTDOWN_REQ	"req_shutdown"
#  define CRM_OP_SHUTDOWN 	"do_shutdown"
#  define CRM_OP_FENCE	 	"stonith"
#  define CRM_OP_EVENTCC		"event_cc"
#  define CRM_OP_TEABORT		"te_abort"
#  define CRM_OP_TEABORTED	"te_abort_confirmed"    /* we asked */
#  define CRM_OP_TE_HALT		"te_halt"
#  define CRM_OP_TECOMPLETE	"te_complete"
#  define CRM_OP_TETIMEOUT	"te_timeout"
#  define CRM_OP_TRANSITION	"transition"
#  define CRM_OP_REGISTER		"register"
#  define CRM_OP_DEBUG_UP		"debug_inc"
#  define CRM_OP_DEBUG_DOWN	"debug_dec"
#  define CRM_OP_INVOKE_LRM	"lrm_invoke"
#  define CRM_OP_LRM_REFRESH	"lrm_refresh"
#  define CRM_OP_LRM_QUERY	"lrm_query"
#  define CRM_OP_LRM_DELETE	"lrm_delete"
#  define CRM_OP_LRM_FAIL		"lrm_fail"
#  define CRM_OP_PROBED		"probe_complete"
#  define CRM_OP_REPROBE		"probe_again"
#  define CRM_OP_CLEAR_FAILCOUNT  "clear_failcount"
#  define CRM_OP_RELAXED_SET  "one-or-more"

#  define CRMD_STATE_ACTIVE	"member"
#  define CRMD_STATE_INACTIVE	"down"

#  define CRMD_JOINSTATE_DOWN	CRMD_STATE_INACTIVE
#  define CRMD_JOINSTATE_PENDING	"pending"
#  define CRMD_JOINSTATE_MEMBER	CRMD_STATE_ACTIVE
#  define CRMD_JOINSTATE_NACK	"banned"

#  define CRMD_ACTION_DELETE		"delete"
#  define CRMD_ACTION_CANCEL		"cancel"

#  define CRMD_ACTION_MIGRATE		"migrate_to"
#  define CRMD_ACTION_MIGRATED		"migrate_from"

#  define CRMD_ACTION_START		"start"
#  define CRMD_ACTION_STARTED		"running"

#  define CRMD_ACTION_STOP		"stop"
#  define CRMD_ACTION_STOPPED		"stopped"

#  define CRMD_ACTION_PROMOTE		"promote"
#  define CRMD_ACTION_PROMOTED		"promoted"
#  define CRMD_ACTION_DEMOTE		"demote"
#  define CRMD_ACTION_DEMOTED		"demoted"

#  define CRMD_ACTION_NOTIFY		"notify"
#  define CRMD_ACTION_NOTIFIED		"notified"

#  define CRMD_ACTION_STATUS		"monitor"

/* short names */
#  define RSC_DELETE	CRMD_ACTION_DELETE
#  define RSC_CANCEL	CRMD_ACTION_CANCEL

#  define RSC_MIGRATE	CRMD_ACTION_MIGRATE
#  define RSC_MIGRATED	CRMD_ACTION_MIGRATED

#  define RSC_START	CRMD_ACTION_START
#  define RSC_STARTED	CRMD_ACTION_STARTED

#  define RSC_STOP	CRMD_ACTION_STOP
#  define RSC_STOPPED	CRMD_ACTION_STOPPED

#  define RSC_PROMOTE	CRMD_ACTION_PROMOTE
#  define RSC_PROMOTED	CRMD_ACTION_PROMOTED
#  define RSC_DEMOTE	CRMD_ACTION_DEMOTE
#  define RSC_DEMOTED	CRMD_ACTION_DEMOTED

#  define RSC_NOTIFY	CRMD_ACTION_NOTIFY
#  define RSC_NOTIFIED	CRMD_ACTION_NOTIFIED

#  define RSC_STATUS	CRMD_ACTION_STATUS
/* *INDENT-ON* */

typedef GList *GListPtr;

/* LOG_DEBUG = 7, make LOG_TRACE ::= -VVVVV */
#  ifdef LOG_TRACE
#    undef LOG_TRACE
#  endif

#  ifndef LOG_TRACE
#    define LOG_TRACE    12
#  endif
#  define LOG_DEBUG_2  LOG_TRACE
#  define LOG_DEBUG_3  LOG_TRACE
#  define LOG_DEBUG_4  LOG_TRACE
#  define LOG_DEBUG_5  LOG_TRACE
#  define LOG_DEBUG_6  LOG_TRACE

#  define LOG_MSG  LOG_TRACE

/*
 * Throughout the macros below, note the leading, pre-comma, space in the
 * various ' , ##args' occurences to aid portability across versions of 'gcc'.
 *	http://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html#Variadic-Macros
 */
#    define CRM_TRACE_INIT_DATA(name) QB_LOG_INIT_DATA(name)

#    define do_crm_log(level, fmt, args...) do {                        \
        qb_log_from_external_source( __func__, __FILE__, fmt, level, __LINE__, 0, ##args); \
    } while(0)

/* level /MUST/ be a constant or compilation will fail */
#    define do_crm_log_unlikely(level, fmt, args...) do {               \
        static struct qb_log_callsite *trace_cs = NULL;                 \
        if(trace_cs == NULL) {                                          \
            trace_cs = qb_log_callsite_get(__func__, __FILE__, fmt, level, __LINE__, 0); \
        }                                                               \
        if (trace_cs && trace_cs->targets) {                            \
            qb_log_from_external_source(                                \
                __func__, __FILE__, fmt, level, __LINE__, 0,  ##args);  \
        }                                                               \
    } while(0)

#    define CRM_LOG_ASSERT(expr) do {					\
        if(__unlikely((expr) == FALSE)) {				\
            static struct qb_log_callsite *core_cs = NULL;              \
            if(core_cs == NULL) {                                       \
                core_cs = qb_log_callsite_get(__func__, __FILE__, "log-assert", LOG_TRACE, __LINE__, 0); \
            }                                                           \
            crm_abort(__FILE__, __PRETTY_FUNCTION__, __LINE__, #expr,   \
                      core_cs?core_cs->targets:FALSE, TRUE);            \
        }                                                               \
    } while(0)

#    define CRM_CHECK(expr, failure_action) do {				\
	if(__unlikely((expr) == FALSE)) {				\
            static struct qb_log_callsite *core_cs = NULL;              \
            if(core_cs == NULL) {                                       \
                core_cs = qb_log_callsite_get(__func__, __FILE__, "check-assert", LOG_TRACE, __LINE__, 0); \
            }                                                           \
	    crm_abort(__FILE__, __PRETTY_FUNCTION__, __LINE__, #expr,	\
		      core_cs?core_cs->targets:FALSE, TRUE);            \
	    failure_action;						\
	}								\
    } while(0)

#    define do_crm_log_xml(level, text, xml) do {                       \
        static struct qb_log_callsite *xml_cs = NULL;                   \
        if(xml_cs == NULL) {                                            \
            xml_cs = qb_log_callsite_get(__func__, __FILE__, "xml-blog", level, __LINE__, 0); \
        }                                                               \
        if (xml_cs && xml_cs->targets) {                              \
            log_data_element(level, __FILE__, __PRETTY_FUNCTION__, __LINE__, text, xml, 0, TRUE); \
        }                                                               \
    } while(0)

#    define do_crm_log_alias(level, file, function, line, fmt, args...) do { \
	qb_log_from_external_source(function, file, fmt, level, line, 0,  ##args); \
    } while(0)

#    define do_crm_log_always(level, fmt, args...) qb_log(level, "%s: " fmt, __PRETTY_FUNCTION__ , ##args)

#  define crm_perror(level, fmt, args...) do {				\
	const char *err = strerror(errno);				\
	fprintf(stderr, fmt ": %s (%d)\n", ##args, err, errno);		\
	do_crm_log(level, fmt ": %s (%d)", ##args, err, errno);		\
    } while(0)

#    define crm_crit(fmt, args...)    qb_logt(LOG_CRIT,    0, fmt , ##args)
#    define crm_err(fmt, args...)     qb_logt(LOG_ERR,     0, fmt , ##args)
#    define crm_warn(fmt, args...)    qb_logt(LOG_WARNING, 0, fmt , ##args)
#    define crm_notice(fmt, args...)  qb_logt(LOG_NOTICE,  0, fmt , ##args)
#    define crm_info(fmt, args...)    qb_logt(LOG_INFO,    0, fmt , ##args)
#    define crm_debug(fmt, args...)   do_crm_log_unlikely(LOG_DEBUG, fmt , ##args)
#    define crm_trace(fmt, args...)   do_crm_log_unlikely(LOG_TRACE, fmt , ##args)

#  include <crm/common/util.h>

#  define crm_log_xml_crit(xml, text)    do_crm_log_xml(LOG_CRIT,    text, xml)
#  define crm_log_xml_err(xml, text)     do_crm_log_xml(LOG_ERR,     text, xml)
#  define crm_log_xml_warn(xml, text)    do_crm_log_xml(LOG_WARNING, text, xml)
#  define crm_log_xml_notice(xml, text)  do_crm_log_xml(LOG_NOTICE,  text, xml)
#  define crm_log_xml_info(xml, text)    do_crm_log_xml(LOG_INFO,    text, xml)
#  define crm_log_xml_debug(xml, text)   do_crm_log_xml(LOG_DEBUG,   text, xml)
#  define crm_log_xml_trace(xml, text)   do_crm_log_xml(LOG_TRACE,   text, xml)

#  define crm_str(x)    (const char*)(x?x:"<null>")

#  define crm_malloc0(malloc_obj, length) do {				\
	malloc_obj = malloc(length);					\
	if(malloc_obj == NULL) {					\
	    crm_err("Failed allocation of %lu bytes", (unsigned long)length); \
	    CRM_ASSERT(malloc_obj != NULL);				\
	}								\
	memset(malloc_obj, 0, length);					\
    } while(0)

#  define crm_malloc(malloc_obj, length) do {				\
	malloc_obj = malloc(length);					\
	if(malloc_obj == NULL) {					\
	    crm_err("Failed allocation of %lu bytes", (unsigned long)length); \
	    CRM_ASSERT(malloc_obj != NULL);				\
	}								\
    } while(0)

#  define crm_realloc(realloc_obj, length) do {				\
	realloc_obj = realloc(realloc_obj, length);			\
	CRM_ASSERT(realloc_obj != NULL);				\
    } while(0)

#  define crm_free(free_obj) do { free(free_obj); free_obj=NULL; } while(0)
#  define crm_strdup(str) crm_strdup_fn(str, __FILE__, __PRETTY_FUNCTION__, __LINE__)

#  define crm_str_hash g_str_hash_traditional
guint g_str_hash_traditional(gconstpointer v);

void update_all_trace_data(void);

static inline void
slist_basic_destroy(GListPtr list)
{
    GListPtr gIter = NULL;

    for (gIter = list; gIter != NULL; gIter = gIter->next) {
        free(gIter->data);
    }
    g_list_free(list);
}

/* These two macros are no longer to be used
 * They exist for compatability reasons and will be removed in a
 * future release
 * Use something like this instead:

    GListPtr gIter = rsc->children;
    for(; gIter != NULL; gIter = gIter->next) {
	resource_t *child_rsc = (resource_t*)gIter->data;
	...
    }
 *
 */
#  define slist_destroy(child_type, child, parent, a) do {		\
	GListPtr __crm_iter_head = parent;				\
	child_type *child = NULL;					\
	while(__crm_iter_head != NULL) {				\
	    child = (child_type *) __crm_iter_head->data;		\
	    __crm_iter_head = __crm_iter_head->next;			\
	    { a; }							\
	}								\
	g_list_free(parent);						\
    } while(0)

#endif
