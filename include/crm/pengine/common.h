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
#ifndef PE_COMMON__H
#  define PE_COMMON__H
#  include <glib.h>

extern gboolean was_processing_error;
extern gboolean was_processing_warning;

/* order is significant here
 * items listed in order of accending severeness
 * more severe actions take precedent over lower ones
 */
enum action_fail_response {
    action_fail_ignore,
    action_fail_recover,
    action_fail_migrate,        /* recover by moving it somewhere else */
    action_fail_block,
    action_fail_stop,
    action_fail_standby,
    action_fail_fence,
    action_fail_restart_container
};

/* the "done" action must be the "pre" action +1 */
enum action_tasks {
    no_action,
    monitor_rsc,
    stop_rsc,
    stopped_rsc,
    start_rsc,
    started_rsc,
    action_notify,
    action_notified,
    action_promote,
    action_promoted,
    action_demote,
    action_demoted,
    shutdown_crm,
    stonith_node
};

enum rsc_recovery_type {
    recovery_stop_start,
    recovery_stop_only,
    recovery_block
};

enum rsc_start_requirement {
    rsc_req_nothing,            /* Allowed by custom_action() */
    rsc_req_quorum,             /* Enforced by custom_action() */
    rsc_req_stonith             /* Enforced by native_start_constraints() */
};

enum rsc_role_e {
    RSC_ROLE_UNKNOWN,
    RSC_ROLE_STOPPED,
    RSC_ROLE_STARTED,
    RSC_ROLE_SLAVE,
    RSC_ROLE_MASTER,
};

#  define RSC_ROLE_MAX  RSC_ROLE_MASTER+1

#  define	RSC_ROLE_UNKNOWN_S "Unknown"
#  define	RSC_ROLE_STOPPED_S "Stopped"
#  define	RSC_ROLE_STARTED_S "Started"
#  define	RSC_ROLE_SLAVE_S   "Slave"
#  define	RSC_ROLE_MASTER_S  "Master"

/* *INDENT-OFF* */
enum pe_print_options {

	pe_print_log		= 0x0001,
	pe_print_html		= 0x0002,
	pe_print_ncurses	= 0x0004,
	pe_print_printf		= 0x0008,
	pe_print_dev		= 0x0010,
	pe_print_details	= 0x0020,
	pe_print_max_details	= 0x0040,
	pe_print_rsconly	= 0x0080,
	pe_print_ops		= 0x0100,
	pe_print_suppres_nl	= 0x0200,
	pe_print_xml		= 0x0400,
	pe_print_brief		= 0x0800,
	pe_print_pending	= 0x1000,
        pe_print_clone_details  = 0x2000,
};
/* *INDENT-ON* */

const char *task2text(enum action_tasks task);
enum action_tasks text2task(const char *task);
enum rsc_role_e text2role(const char *role);
const char *role2text(enum rsc_role_e role);
const char *fail2text(enum action_fail_response fail);

const char *pe_pref(GHashTable * options, const char *name);
void calculate_active_ops(GList * sorted_op_list, int *start_index, int *stop_index);

static inline const char *
recovery2text(enum rsc_recovery_type type)
{
    switch (type) {
        case recovery_stop_only:
            return "shutting it down";
        case recovery_stop_start:
            return "attempting recovery";
        case recovery_block:
            return "waiting for an administrator";
    }
    return "Unknown";
}

#endif
