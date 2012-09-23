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
#ifndef CIB_INTERNAL__H
#  define CIB_INTERNAL__H
#include <crm/cib.h>

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
#  define CIB_OP_APPLY_DIFF "cib_apply_diff"
#  define CIB_OP_UPGRADE    "cib_upgrade"
#  define CIB_OP_DELETE_ALT	"cib_delete_alt"
#  define CIB_OP_NOTIFY	      "cib_notify"

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
#  define T_CIB_REPLACE_NOTIFY	"cib_refresh_notify"

#  define cib_channel_ro		"cib_ro"
#  define cib_channel_rw		"cib_rw"
#  define cib_channel_shm		"cib_shm"

void fix_cib_diff(xmlNode * last, xmlNode * next, xmlNode * local_diff, gboolean changed);
gboolean cib_diff_version_details(xmlNode * diff, int *admin_epoch, int *epoch, int *updates,
                                  int *_admin_epoch, int *_epoch, int *_updates);

gboolean startCib(const char *filename);
int cib_compare_generation(xmlNode * left, xmlNode * right);
gboolean cib_read_config(GHashTable * options, xmlNode * current_cib);
void verify_cib_options(GHashTable * options);
gboolean cib_internal_config_changed(xmlNode * diff);

extern GHashTable *cib_op_callback_table;
typedef struct cib_notify_client_s {
    const char *event;
    const char *obj_id;         /* implement one day */
    const char *obj_type;       /* implement one day */
    void (*callback) (const char *event, xmlNode * msg);

} cib_notify_client_t;

typedef struct cib_callback_client_s {
    void (*callback) (xmlNode *, int, int, xmlNode *, void *);
    const char *id;
    void *user_data;
    gboolean only_success;
    struct timer_rec_s *timer;

} cib_callback_client_t;

struct timer_rec_s {
    int call_id;
    int timeout;
    guint ref;
    cib_t *cib;
};

typedef int (*cib_op_t) (const char *, int, const char *, xmlNode *,
                                     xmlNode *, xmlNode *, xmlNode **, xmlNode **);

cib_t *cib_new_variant(void);

int cib_perform_op(const char *op, int call_options, cib_op_t * fn, gboolean is_query,
                   const char *section, xmlNode * req, xmlNode * input,
                   gboolean manage_counters, gboolean * config_changed,
                   xmlNode * current_cib, xmlNode ** result_cib, xmlNode ** diff, xmlNode ** output);

xmlNode *cib_create_op(int call_id, const char *token, const char *op, const char *host,
                              const char *section, xmlNode * data, int call_options,
                              const char *user_name);

void cib_native_callback(cib_t * cib, xmlNode * msg, int call_id, int rc);
void cib_native_notify(gpointer data, gpointer user_data);
int cib_native_register_notification(cib_t * cib, const char *callback, int enabled);
gboolean cib_client_register_callback(cib_t * cib, int call_id, int timeout, gboolean only_success,
                                      void *user_data, const char *callback_name,
                                      void (*callback) (xmlNode *, int, int, xmlNode *, void *));

gboolean acl_enabled(GHashTable * config_hash);
gboolean acl_filter_cib(xmlNode * request, xmlNode * current_cib, xmlNode * orig_cib, xmlNode ** filtered_cib);
gboolean acl_check_diff(xmlNode * request, xmlNode * current_cib, xmlNode * result_cib, xmlNode * diff);

int cib_process_query(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                      xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

int cib_process_erase(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                      xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

int cib_process_bump(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                     xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

int cib_process_replace(const char *op, int options, const char *section, xmlNode * req,
                        xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                        xmlNode ** answer);

int cib_process_create(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                       xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

int cib_process_modify(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                       xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

int cib_process_delete(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                       xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

int cib_process_diff(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                     xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

int cib_process_upgrade(const char *op, int options, const char *section, xmlNode * req,
                        xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                        xmlNode ** answer);

int cib_process_xpath(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                      xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer);

gboolean cib_config_changed(xmlNode * last, xmlNode * next, xmlNode ** diff);
gboolean update_results(xmlNode * failed, xmlNode * target, const char *operation,
                               int return_code);
int cib_update_counter(xmlNode * xml_obj, const char *field, gboolean reset);

int cib_internal_op(cib_t * cib, const char *op, const char *host,
                    const char *section, xmlNode * data,
                    xmlNode ** output_data, int call_options, const char *user_name);

#endif
