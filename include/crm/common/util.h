/* $Id: util.h,v 1.34 2006/04/18 11:23:45 andrew Exp $ */
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
#ifndef CRM_COMMON_UTIL__H
#define CRM_COMMON_UTIL__H

#include <signal.h>
#include <crm/common/xml.h>
#include <hb_api.h>
#include <ocf/oc_event.h>
#include <lrm/lrm_api.h>

#define DEBUG_INC SIGUSR1
#define DEBUG_DEC SIGUSR2

extern unsigned int crm_log_level;

extern gboolean crm_log_init(const char *entity);

extern void do_crm_log(int log_level, const char *file, const char *function,
		       const char *format, ...) G_GNUC_PRINTF(4,5);

/* returns the old value */
extern unsigned int set_crm_log_level(unsigned int level);

extern unsigned int get_crm_log_level(void);

extern char *crm_itoa(int an_int);

extern char *crm_strdup(const char *a);

extern char *generate_hash_key(const char *crm_msg_reference, const char *sys);

extern char *generate_hash_value(const char *src_node, const char *src_subsys);

extern gboolean decode_hash_value(gpointer value, char **node, char **subsys);

extern gboolean decodeNVpair(const char *srcstring,
			     char separator, char **name, char **value);

extern int compare_version(const char *version1, const char *version2);


extern char *generateReference(const char *custom1, const char *custom2);

extern void alter_debug(int nsig);

extern void g_hash_destroy_str(gpointer data);

extern const char *get_uuid(ll_cluster_t *hb, const char *uname);
extern const char *get_uname(ll_cluster_t *hb, const char *uuid);
extern void unget_uuid(const char *uname);

extern void set_uuid(
	ll_cluster_t* hb, crm_data_t *node, const char *attr, const char *uname);

extern gboolean crm_is_true(const char * s);

extern int crm_str_to_boolean(const char * s, int * ret);

extern long crm_get_msec(const char * input);

extern gboolean ccm_have_quorum(oc_ed_t event);

extern const char *ccm_event_name(oc_ed_t event);

extern const char *op_status2text(op_status_t status);

extern char *generate_op_key(
	const char *rsc_id, const char *op_type, int interval);

extern gboolean parse_op_key(
	const char *key, char **rsc_id, char **op_type, int *interval);

extern char *generate_notify_key(
	const char *rsc_id, const char *notify_type, const char *op_type);

extern gboolean crm_mem_stats(volatile cl_mem_stats_t *mem_stats);

extern void crm_zero_mem_stats(volatile cl_mem_stats_t *stats);

extern char *generate_transition_magic_v202(
	const char *transition_key, int op_status);

extern char *generate_transition_magic(
	const char *transition_key, int op_status, int op_rc);

extern gboolean decode_transition_magic(
	const char *magic, char **uuid,
	int *transition_id, int *op_status, int *op_rc);

extern char *generate_transition_key(int transition_id, const char *node);

extern gboolean decode_transition_key(
	const char *key, char **uuid, int *transition_id);

extern char *crm_concat(const char *prefix, const char *suffix, char join);

extern gboolean decode_op_key(
	const char *key, char **rsc_id, char **op_type, int *interval);

extern void filter_action_parameters(crm_data_t *param_set);

extern gboolean safe_str_eq(const char *a, const char *b);
extern gboolean safe_str_neq(const char *a, const char *b);
extern int crm_parse_int(const char *text, const char *default_text);
extern int crm_int_helper(const char *text, char **end_text);
#define crm_atoi(text, default_text) crm_parse_int(text, default_text)

extern void crm_abort(const char *file, const char *function, int line,
		      const char *condition, gboolean do_fork);

extern char *generate_series_filename(
	const char *directory, const char *series, int sequence, gboolean bzip);

extern int get_last_sequence(const char *directory, const char *series);

extern void write_last_sequence(
	const char *directory, const char *series, int sequence, int max);

extern void crm_make_daemon(
	const char *name, gboolean daemonize, const char *pidfile);

#endif
