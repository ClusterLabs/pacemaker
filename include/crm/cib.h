/* $Id: cib.h,v 1.1 2004/03/24 09:45:10 andrew Exp $ */
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
#ifndef CIB__H
#define CIB__H

enum cib_op {
	CIB_OP_NONE = 0,
	CIB_OP_ADD,
	CIB_OP_MODIFY,
	CIB_OP_DELETE,
	CIB_OP_MAX
};

enum cib_result {
	CIBRES_MISSING_ID	= -1,
	CIBRES_MISSING_TYPE	= -2,
	CIBRES_MISSING_FIELD	= -3,
	CIBRES_OBJTYPE_MISMATCH	= -4,
	CIBRES_EXISTS		= -5,
	CIBRES_NOT_EXISTS	= -6,
	CIBRES_CORRUPT		= -7,
	CIBRES_OTHER		= -8,
	CIBRES_OK = 0,
	CIBRES_FAILED,
	CIBRES_FAILED_OLDUPDATE,
	CIBRES_FAILED_ACTIVATION,
	CIBRES_FAILED_NOSECTION,
	CIBRES_FAILED_NOTSUPPORTED,
};


/* Core functions */
extern gboolean   startCib(const char *filename);
extern xmlNodePtr get_cib_copy(void);
extern xmlNodePtr process_cib_message(xmlNodePtr message, gboolean auto_reply);
extern xmlNodePtr process_cib_request(const char *op,
				      const xmlNodePtr options,
				      const xmlNodePtr fragment);

/* Utility functions */
extern xmlNodePtr get_object_root(const char *object_type,xmlNodePtr the_root);
extern xmlNodePtr create_cib_fragment(xmlNodePtr update, const char *section);
extern char      *pluralSection(const char *a_section);

/* Error Interpretation*/
extern const char *cib_error2string(enum cib_result);
extern const char *cib_op2string(enum cib_op);

#endif
