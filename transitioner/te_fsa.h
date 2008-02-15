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
#include <tengine.h>

extern GListPtr input_queue;

typedef struct te_input_s te_input_t;

enum te_data_type
{
	te_data_cib,
	te_data_complete,
	te_data_command,
	te_data_null
};

typedef struct te_data_operations_s
{
		enum te_data_type(*type)(void);
		const char* (*name)(void);
		void  (*free)(te_input_t*);
		void  (*copy)(te_input_t*);
} te_data_op_t;

struct te_input_s 
{
		int id;
		char *origin;
		te_fsa_input_t input;

		te_data_op_t *ops;
		void *data;
};

struct te_data_command_s {
		xmlNode *msg;
		xmlNode *xml;
};

struct te_data_cib_s {
		xmlNode *msg;
		xmlNode *xml;
		int call_id;
		int rc;
		void *user_data; /* not copied or free'd */
};

struct te_data_complete_s {
		const char *text;
		xmlNode *xml;
		te_reason_t reason;		
};

extern void te_input_free(te_input_t *fsa_data);
extern te_input_t* te_input_copy(te_input_t *fsa_data);
extern te_input_t* te_input_new(enum te_data_type type, void *data);

extern te_input_t *new_input_command(xmlNode *msg, xmlNode *xml);

extern te_input_t *new_input_complete(const char *text, xmlNode *xml,
				      te_reason_t reason, te_fsa_input_t input);

extern te_input_t *new_input_cib(xmlNode *msg, xmlNode *xml,
				 int call_id, int rc, void *user_data);

extern te_input_t *new_input_null(void);

extern te_input_t *get_input(void);

