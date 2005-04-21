/* $Id: util.h,v 1.15 2005/04/21 15:16:40 andrew Exp $ */
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

extern void do_crm_log(int log_level, const char *function,
		       const char *alt_debugfile, const char *format, ...) G_GNUC_PRINTF(4,5);

/* returns the old value */
extern unsigned int set_crm_log_level(unsigned int level);

extern unsigned int get_crm_log_level(void);

extern char *crm_itoa(int an_int);

extern char *crm_strdup(const char *a);

extern char *generate_hash_key(const char *crm_msg_reference,
			       const char *sys);

extern char *generate_hash_value(const char *src_node,
				 const char *src_subsys);

extern gboolean decode_hash_value(gpointer value,
				  char **node,
				  char **subsys);

extern gboolean decodeNVpair(const char *srcstring,
		      char separator,
		      char **name,
		      char **value);

extern int compare_version(const char *version1, const char *version2);


extern char *generateReference(const char *custom1, const char *custom2);

extern void alter_debug(int nsig);

extern void g_hash_destroy_str(gpointer data);

extern void set_uuid(
	ll_cluster_t* hb, crm_data_t *node, const char *attr, const char *uname);

extern void crm_set_ha_options(ll_cluster_t *hb_cluster);

extern gboolean crm_is_true(const char * s);

extern int crm_str_to_boolean(const char * s, int * ret);

extern long crm_get_msec(const char * input);

extern gboolean ccm_have_quorum(oc_ed_t event);

extern const char *ccm_event_name(oc_ed_t event);

extern const char *op_status2text(op_status_t status);

#endif
