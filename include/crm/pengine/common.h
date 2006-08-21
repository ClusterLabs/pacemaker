/* $Id: common.h,v 1.4 2006/08/14 09:06:31 andrew Exp $ */
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
#ifndef PE_COMMON__H
#define PE_COMMON__H

/*
 * The man pages for both curses and ncurses suggest inclusion of "curses.h".
 * We believe the following to be acceptable and portable.
 */

#if defined(HAVE_LIBNCURSES) || defined(HAVE_LIBCURSES)
#if defined(HAVE_NCURSES_H) && !defined(HAVE_INCOMPATIBLE_PRINTW)
#  include <ncurses.h>
#  define CURSES_ENABLED 1
#elif defined(HAVE_NCURSES_NCURSES_H) && !defined(HAVE_INCOMPATIBLE_PRINTW)
#  include <ncurses/ncurses.h>
#  define CURSES_ENABLED 1
#elif defined(HAVE_CURSES_H) && !defined(HAVE_INCOMPATIBLE_PRINTW)
#  include <curses.h>
#  define CURSES_ENABLED 1
#elif defined(HAVE_CURSES_CURSES_H) && !defined(HAVE_INCOMPATIBLE_PRINTW)
#  include <curses/curses.h>
#  define CURSES_ENABLED 1
#else
#  define CURSES_ENABLED 0
#endif
#else
#  define CURSES_ENABLED 0
#endif

extern gboolean was_processing_error;
extern gboolean was_processing_warning;
extern unsigned int pengine_input_loglevel;

/* order is significant here
 * items listed in order of accending severeness
 * more severe actions take precedent over lower ones
 */
enum action_fail_response {
	action_fail_ignore,
	action_fail_recover,
	action_fail_migrate,
	action_fail_block,
/* 	action_fail_stop, */
	action_fail_fence
};

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
	rsc_req_nothing,
	rsc_req_quorum,
	rsc_req_stonith
};

enum pe_ordering {
	pe_ordering_manditory,
	pe_ordering_restart,
	pe_ordering_recover,
	pe_ordering_postnotify,
	pe_ordering_optional
};

enum rsc_role_e {
	RSC_ROLE_UNKNOWN,
	RSC_ROLE_STOPPED,
	RSC_ROLE_STARTED,
	RSC_ROLE_SLAVE,
	RSC_ROLE_MASTER,
};
#define RSC_ROLE_MAX  RSC_ROLE_MASTER+1

#define	RSC_ROLE_UNKNOWN_S "Unknown"
#define	RSC_ROLE_STOPPED_S "Stopped"
#define	RSC_ROLE_STARTED_S "Started"
#define	RSC_ROLE_SLAVE_S   "Slave"
#define	RSC_ROLE_MASTER_S  "Master"

enum pe_print_options {

	pe_print_log     = 0x0001,
	pe_print_html    = 0x0002,
	pe_print_ncurses = 0x0004,
	pe_print_printf  = 0x0008,
	pe_print_dev     = 0x0010,
	pe_print_details = 0x0020,
	pe_print_max_details = 0x0040,
	pe_print_rsconly = 0x0080,
};

extern int merge_weights(int w1, int w2);

extern const char *task2text(enum action_tasks task);
extern enum action_tasks text2task(const char *task);

extern enum rsc_role_e text2role(const char *role);
extern const char *role2text(enum rsc_role_e role);

extern const char *fail2text(enum action_fail_response fail);

extern int char2score(const char *score);
extern char *score2char(int score);

extern void add_hash_param(GHashTable *hash, const char *name, const char *value);
extern void pe_metadata(void);
extern void verify_pe_options(GHashTable *options);
extern const char *pe_pref(GHashTable *options, const char *name);


/* Helper macros to avoid NULL pointers */
#define safe_val3(def, t,u,v)       (t?t->u?t->u->v:def:def)
#define safe_val5(def, t,u,v,w,x)   (t?t->u?t->u->v?t->u->v->w?t->u->v->w->x:def:def:def:def)

#define pe_err(fmt...) { was_processing_error = TRUE; crm_config_error = TRUE; crm_err(fmt); }
#define pe_warn(fmt...) { was_processing_warning = TRUE; crm_config_warning = TRUE; crm_warn(fmt); }
#define pe_proc_err(fmt...) { was_processing_error = TRUE; crm_err(fmt); }
#define pe_proc_warn(fmt...) { was_processing_warning = TRUE; crm_warn(fmt); }

#endif
