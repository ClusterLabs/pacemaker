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

/**
 * \file
 * \brief Cluster Configuration
 * \ingroup cib
 */

#ifndef CIB__H
#  define CIB__H

#  include <crm/common/ipc.h>
#  include <crm/common/xml.h>

#  define CIB_FEATURE_SET "2.0"

/* use compare_version() for doing comparisons */

enum cib_variant {
    cib_undefined,
    cib_native,
    cib_file,
    cib_remote,
    cib_database,
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
        cib_xpath_address   = 0x00000040,
        cib_mixed_update    = 0x00000080,
	cib_scope_local     = 0x00000100,
	cib_dryrun    	    = 0x00000200,
	cib_sync_call       = 0x00001000,
	cib_no_mtime        = 0x00002000,
	cib_inhibit_notify  = 0x00010000,
 	cib_quorum_override = 0x00100000,
	cib_inhibit_bcast   = 0x01000000,
	cib_force_diff	    = 0x10000000
};

#define cib_default_options = cib_none
#define T_CIB_DIFF_NOTIFY	"cib_diff_notify"

/* *INDENT-ON* */

typedef struct cib_s cib_t;

typedef struct cib_api_operations_s {
    int (*signon) (cib_t * cib, const char *name, enum cib_conn_type type);
    int (*signon_raw) (cib_t * cib, const char *name, enum cib_conn_type type, int *event_fd);
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

} cib_api_operations_t;

struct cib_s {
    enum cib_state state;
    enum cib_conn_type type;
    enum cib_variant variant;

    int call_id;
    int call_timeout;
    void *variant_opaque;
    void *delegate_fn;

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

/* Deprecated */
#  define add_cib_op_callback(cib, id, flag, data, fn) do {             \
        cib->cmds->register_callback(cib, id, 120, flag, data, #fn, fn); \
    } while(0)
#  include <crm/cib/util.h>

#  define CIB_LIBRARY "libcib.so.3"

#endif
