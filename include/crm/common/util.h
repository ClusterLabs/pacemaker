/* $Id: util.h,v 1.4 2004/07/27 11:43:21 andrew Exp $ */
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

extern unsigned int crm_log_level;

extern void do_crm_log(int log_level, const char *function,
		       const char *format, ...) G_GNUC_PRINTF(3,4);

/* returns the old value */
extern unsigned int set_crm_log_level(unsigned int level);

extern unsigned int get_crm_log_level(void);

extern char *crm_itoa(int an_int);

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


extern const char *generateReference(const char *custom1, const char *custom2);

#endif
