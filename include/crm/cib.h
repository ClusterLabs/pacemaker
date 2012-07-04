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
#ifndef CIB__H
#  define CIB__H

#  include <crm/common/ipc.h>
#  include <crm/common/xml.h>

#  define CIB_FEATURE_SET "2.0"
#  define USE_PESKY_FRAGMENTS 1

/* use compare_version() for doing comparisons */

enum cib_variant {
    cib_undefined,
    cib_native,
    cib_file,
    cib_remote,
    cib_database,
    cib_edir
};

enum cib_state {
    cib_connected_command,
    cib_connected_query,
    cib_disconnected
};

enum cib_conn_type {
    cib_command,
    cib_query,
    cib_no_connection,
    cib_command_nonblocking,
};

/* *INDENT-OFF* */
enum cib_call_options {
	cib_none            = 0x00000000,
	cib_verbose         = 0x00000001,
	cib_xpath           = 0x00000002,
	cib_multiple        = 0x00000004,
	cib_can_create      = 0x00000008,
	cib_discard_reply   = 0x00000010,
	cib_no_children     = 0x00000020,
	cib_scope_local     = 0x00000100,
	cib_dryrun    	    = 0x00000200,
	cib_sync_call       = 0x00001000,
	cib_inhibit_notify  = 0x00010000,
 	cib_quorum_override = 0x00100000,
	cib_inhibit_bcast   = 0x01000000,
	cib_force_diff	    = 0x10000000
};

#define cib_default_options = cib_none

/* *INDENT-ON* */

enum cib_update_op {
    CIB_UPDATE_OP_NONE = 0,
    CIB_UPDATE_OP_ADD,
    CIB_UPDATE_OP_MODIFY,
    CIB_UPDATE_OP_DELETE,
    CIB_UPDATE_OP_MAX
};

enum cib_section {
    cib_section_none,
    cib_section_all,
    cib_section_nodes,
    cib_section_constraints,
    cib_section_resources,
    cib_section_crmconfig,
    cib_section_status
};

#  define CIB_OP_SLAVE	"cib_slave"
#  define CIB_OP_SLAVEALL	"cib_slave_all"
#  define CIB_OP_MASTER	"cib_master"
#  define CIB_OP_SYNC	"cib_sync"
#  define CIB_OP_SYNC_ONE	"cib_sync_one"
#  define CIB_OP_ISMASTER	"cib_ismaster"
#  define CIB_OP_BUMP	"cib_bump"
#  define CIB_OP_QUERY	"cib_query"
#  define CIB_OP_CREATE	"cib_create"
#  define CIB_OP_UPDATE	"cib_update"
#  define CIB_OP_MODIFY	"cib_modify"
#  define CIB_OP_DELETE	"cib_delete"
#  define CIB_OP_ERASE	"cib_erase"
#  define CIB_OP_REPLACE	"cib_replace"
#  define CIB_OP_NOTIFY	"cib_notify"
#  define CIB_OP_APPLY_DIFF "cib_apply_diff"
#  define CIB_OP_UPGRADE    "cib_upgrade"
#  define CIB_OP_DELETE_ALT	"cib_delete_alt"

#  define F_CIB_CLIENTID  "cib_clientid"
#  define F_CIB_CALLOPTS  "cib_callopt"
#  define F_CIB_CALLID    "cib_callid"
#  define F_CIB_CALLDATA  "cib_calldata"
#  define F_CIB_OPERATION "cib_op"
#  define F_CIB_ISREPLY   "cib_isreplyto"
#  define F_CIB_SECTION   "cib_section"
#  define F_CIB_HOST	"cib_host"
#  define F_CIB_RC	"cib_rc"
#  define F_CIB_DELEGATED	"cib_delegated_from"
#  define F_CIB_OBJID	"cib_object"
#  define F_CIB_OBJTYPE	"cib_object_type"
#  define F_CIB_EXISTING	"cib_existing_object"
#  define F_CIB_SEENCOUNT	"cib_seen"
#  define F_CIB_TIMEOUT	"cib_timeout"
#  define F_CIB_UPDATE	"cib_update"
#  define F_CIB_CALLBACK_TOKEN	"cib_async_id"
#  define F_CIB_GLOBAL_UPDATE	"cib_update"
#  define F_CIB_UPDATE_RESULT	"cib_update_result"
#  define F_CIB_CLIENTNAME	"cib_clientname"
#  define F_CIB_NOTIFY_TYPE	"cib_notify_type"
#  define F_CIB_NOTIFY_ACTIVATE	"cib_notify_activate"
#  define F_CIB_UPDATE_DIFF	"cib_update_diff"
#  define F_CIB_USER		"cib_user"
#  define F_CIB_LOCAL_NOTIFY_ID	"cib_local_notify_id"

#  define T_CIB			"cib"
#  define T_CIB_NOTIFY		"cib_notify"
/* notify sub-types */
#  define T_CIB_PRE_NOTIFY	"cib_pre_notify"
#  define T_CIB_POST_NOTIFY	"cib_post_notify"
#  define T_CIB_UPDATE_CONFIRM	"cib_update_confirmation"
#  define T_CIB_DIFF_NOTIFY	"cib_diff_notify"
#  define T_CIB_REPLACE_NOTIFY	"cib_refresh_notify"

#  define cib_channel_ro		"cib_ro"
#  define cib_channel_rw		"cib_rw"
#  define cib_channel_shm		"cib_shm"

typedef struct cib_s cib_t;

typedef struct cib_api_operations_s {
    int (*variant_op) (cib_t * cib, const char *op, const char *host,
                       const char *section, xmlNode * data,
                       xmlNode ** output_data, int call_options);

    int (*signon) (cib_t * cib, const char *name, enum cib_conn_type type);
    int (*signon_raw) (cib_t * cib, const char *name, enum cib_conn_type type, int *async_fd,
                       int *unused);
    int (*signoff) (cib_t * cib);
    int (*free) (cib_t * cib);

    int (*set_op_callback) (cib_t * cib, void (*callback) (const xmlNode * msg, int callid,
                                                           int rc, xmlNode * output));

    int (*add_notify_callback) (cib_t * cib, const char *event,
                                void (*callback) (const char *event, xmlNode * msg));

    int (*del_notify_callback) (cib_t * cib, const char *event,
                                void (*callback) (const char *event, xmlNode * msg));

    int (*set_connection_dnotify) (cib_t * cib, void (*dnotify) (gpointer user_data));

    int (*inputfd) (cib_t * cib);

    int (*noop) (cib_t * cib, int call_options);
    int (*ping) (cib_t * cib, xmlNode ** output_data, int call_options);

    int (*query) (cib_t * cib, const char *section, xmlNode ** output_data, int call_options);
    int (*query_from) (cib_t * cib, const char *host, const char *section,
                       xmlNode ** output_data, int call_options);

    int (*is_master) (cib_t * cib);
    int (*set_master) (cib_t * cib, int call_options);
    int (*set_slave) (cib_t * cib, int call_options);
    int (*set_slave_all) (cib_t * cib, int call_options);

    int (*sync) (cib_t * cib, const char *section, int call_options);
    int (*sync_from) (cib_t * cib, const char *host, const char *section, int call_options);

    int (*upgrade) (cib_t * cib, int call_options);
    int (*bump_epoch) (cib_t * cib, int call_options);

    int (*create) (cib_t * cib, const char *section, xmlNode * data, int call_options);
    int (*modify) (cib_t * cib, const char *section, xmlNode * data, int call_options);
    int (*update) (cib_t * cib, const char *section, xmlNode * data, int call_options);
    int (*replace) (cib_t * cib, const char *section, xmlNode * data, int call_options);
    int (*delete) (cib_t * cib, const char *section, xmlNode * data, int call_options);

    int (*erase) (cib_t * cib, xmlNode ** output_data, int call_options);
    int (*delete_absolute) (cib_t * cib, const char *section, xmlNode * data, int call_options);

    int (*quit) (cib_t * cib, int call_options);

    int (*register_notification) (cib_t * cib, const char *callback, int enabled);

     gboolean(*register_callback) (cib_t * cib, int call_id, int timeout, gboolean only_success,
                                   void *user_data, const char *callback_name,
                                   void (*callback) (xmlNode *, int, int, xmlNode *, void *));

    int (*delegated_variant_op) (cib_t * cib, const char *op, const char *host,
                                 const char *section, xmlNode * data,
                                 xmlNode ** output_data, int call_options, const char *user_name);

} cib_api_operations_t;

struct cib_s {
    enum cib_state state;
    enum cib_conn_type type;
    enum cib_variant variant;

    int call_id;
    int call_timeout;
    void *variant_opaque;

    GList *notify_list;
    void (*op_callback) (const xmlNode * msg, int call_id, int rc, xmlNode * output);

    cib_api_operations_t *cmds;
};

/* Core functions */
cib_t *cib_new(void);
cib_t *cib_native_new(void);
cib_t *cib_file_new(const char *filename);
cib_t *cib_remote_new(const char *server, const char *user, const char *passwd, int port,
                             gboolean encrypted);

cib_t *cib_new_no_shadow(void);
char *get_shadow_file(const char *name);
cib_t *cib_shadow_new(const char *name);

void cib_delete(cib_t * cib);

void cib_dump_pending_callbacks(void);
int num_cib_op_callbacks(void);
void remove_cib_op_callback(int call_id, gboolean all_callbacks);

#  define add_cib_op_callback(cib, id, flag, data, fn) cib->cmds->register_callback(cib, id, 120, flag, data, #fn, fn)

#  include <crm/cib/util.h>
#  include <crm/cib/ops.h>

#  define CIB_LIBRARY "libcib.so.1"

#endif
