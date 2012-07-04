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
#ifndef PE_INTERNAL__H
#  define PE_INTERNAL__H
#  include <crm/common.h>

#  define pe_rsc_info(rsc, fmt, args...)  crm_log_tag(LOG_INFO,  rsc->id, fmt, ##args)
#  define pe_rsc_debug(rsc, fmt, args...) crm_log_tag(LOG_DEBUG, rsc->id, fmt, ##args)
#  define pe_rsc_trace(rsc, fmt, args...) crm_log_tag(LOG_TRACE, rsc->id, fmt, ##args)

#  define pe_err(fmt...) { was_processing_error = TRUE; crm_config_error = TRUE; crm_err(fmt); }
#  define pe_warn(fmt...) { was_processing_warning = TRUE; crm_config_warning = TRUE; crm_warn(fmt); }
#  define pe_proc_err(fmt...) { was_processing_error = TRUE; crm_err(fmt); }
#  define pe_proc_warn(fmt...) { was_processing_warning = TRUE; crm_warn(fmt); }
#  define pe_set_action_bit(action, bit) action->flags = crm_set_bit(__FUNCTION__, action->uuid, action->flags, bit)
#  define pe_clear_action_bit(action, bit) action->flags = crm_clear_bit(__FUNCTION__, action->uuid, action->flags, bit)

typedef struct notify_data_s {
    GHashTable *keys;

    const char *action;

    action_t *pre;
    action_t *post;
    action_t *pre_done;
    action_t *post_done;

    GListPtr active;            /* notify_entry_t*  */
    GListPtr inactive;          /* notify_entry_t*  */
    GListPtr start;             /* notify_entry_t*  */
    GListPtr stop;              /* notify_entry_t*  */
    GListPtr demote;            /* notify_entry_t*  */
    GListPtr promote;           /* notify_entry_t*  */
    GListPtr master;            /* notify_entry_t*  */
    GListPtr slave;             /* notify_entry_t*  */

} notify_data_t;

int merge_weights(int w1, int w2);
void add_hash_param(GHashTable * hash, const char *name, const char *value);
void append_hashtable(gpointer key, gpointer value, gpointer user_data);

char *native_parameter(resource_t * rsc, node_t * node, gboolean create, const char *name,
                              pe_working_set_t * data_set);
node_t *native_location(resource_t * rsc, GListPtr * list, gboolean current);

void pe_metadata(void);
void verify_pe_options(GHashTable * options);

void common_update_score(resource_t * rsc, const char *id, int score);
void native_add_running(resource_t * rsc, node_t * node, pe_working_set_t * data_set);
node_t *rsc_known_on(resource_t * rsc, GListPtr * list);

gboolean native_unpack(resource_t * rsc, pe_working_set_t * data_set);
gboolean group_unpack(resource_t * rsc, pe_working_set_t * data_set);
gboolean clone_unpack(resource_t * rsc, pe_working_set_t * data_set);
gboolean master_unpack(resource_t * rsc, pe_working_set_t * data_set);

resource_t *native_find_rsc(resource_t * rsc, const char *id, node_t * node, int flags);

gboolean native_active(resource_t * rsc, gboolean all);
gboolean group_active(resource_t * rsc, gboolean all);
gboolean clone_active(resource_t * rsc, gboolean all);
gboolean master_active(resource_t * rsc, gboolean all);

void native_print(resource_t * rsc, const char *pre_text, long options, void *print_data);
void group_print(resource_t * rsc, const char *pre_text, long options, void *print_data);
void clone_print(resource_t * rsc, const char *pre_text, long options, void *print_data);
void master_print(resource_t * rsc, const char *pre_text, long options, void *print_data);

void native_free(resource_t * rsc);
void group_free(resource_t * rsc);
void clone_free(resource_t * rsc);
void master_free(resource_t * rsc);

enum rsc_role_e native_resource_state(const resource_t * rsc, gboolean current);
enum rsc_role_e group_resource_state(const resource_t * rsc, gboolean current);
enum rsc_role_e clone_resource_state(const resource_t * rsc, gboolean current);
enum rsc_role_e master_resource_state(const resource_t * rsc, gboolean current);

gboolean common_unpack(
    xmlNode * xml_obj, resource_t ** rsc, resource_t * parent, pe_working_set_t * data_set);
void common_print(resource_t * rsc, const char *pre_text, long options, void *print_data);
void common_free(resource_t * rsc);

#endif
