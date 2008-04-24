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
#ifndef CIB_PRIVATE__H
#define CIB_PRIVATE__H

#include <glib.h>

extern GHashTable *cib_op_callback_table;
typedef struct cib_notify_client_s 
{
	const char *event;
	const char *obj_id;   /* implement one day */
	const char *obj_type; /* implement one day */
	void (*callback)(const char *event, xmlNode *msg);
	
} cib_notify_client_t;

typedef struct cib_callback_client_s 
{
		void (*callback)(xmlNode*, int, int, xmlNode*, void*);
		void *user_data;
		gboolean only_success;
		struct timer_rec_s *timer;
	
} cib_callback_client_t;

struct timer_rec_s 
{
	int call_id;
	int timeout;
	guint ref;	
};

typedef enum cib_errors (*cib_op_t)(const char *, int, const char *, xmlNode *,
				    xmlNode*, xmlNode*, xmlNode**, xmlNode**);

extern cib_t *cib_new_variant(void);

enum cib_errors
cib_perform_op(const char *op, int call_options, cib_op_t *fn, gboolean is_query,
	       const char *section, xmlNode *req, xmlNode *input,
	       gboolean manage_counters, gboolean *config_changed,
	       xmlNode *current_cib, xmlNode **result_cib, xmlNode **output);


#endif
