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

#include <crm/cib/internal.h>

extern xmlNode *cib_msg_copy(xmlNode * msg, gboolean with_data);
extern xmlNode *cib_construct_reply(xmlNode * request, xmlNode * output, int rc);
extern int cib_get_operation_id(const char *op, int *operation);

extern cib_op_t *cib_op_func(int call_type);

extern gboolean cib_op_modifies(int call_type);
extern int cib_op_prepare(int call_type, xmlNode * request, xmlNode ** input, const char **section);
extern int cib_op_cleanup(int call_type, int options, xmlNode ** input, xmlNode ** output);
extern int cib_op_can_run(int call_type, int call_options, gboolean privileged,
                          gboolean global_update);


extern GMainLoop *mainloop;
extern crm_cluster_t crm_cluster;
extern GHashTable *local_notify_queue;

extern gboolean legacy_mode;
extern gboolean stand_alone;
extern gboolean cib_shutdown_flag;
extern const char *cib_root;
extern char *cib_our_uname;

extern int cib_status;
extern unsigned long cib_num_ops, cib_num_local, cib_num_updates, cib_num_fail;
extern unsigned long cib_bad_connects, cib_num_timeouts;

