/* $Id: cib.h,v 1.5 2004/09/21 19:11:22 andrew Exp $ */
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

#include <libxml/tree.h> 

enum cib_op {
	CIB_OP_NONE = 0,
	CIB_OP_ADD,
	CIB_OP_MODIFY,
	CIB_OP_DELETE,
	CIB_OP_MAX
};

enum cib_result {
	CIBRES_OK = 0,
	CIBRES_MISSING_ID,
	CIBRES_MISSING_TYPE,
	CIBRES_MISSING_FIELD,
	CIBRES_OBJTYPE_MISMATCH,
	CIBRES_CORRUPT,
	CIBRES_OTHER,
	CIBRES_FAILED,
	CIBRES_FAILED_STALE,
	CIBRES_FAILED_EXISTS,
	CIBRES_FAILED_NOTEXISTS,
	CIBRES_FAILED_ACTIVATION,
	CIBRES_FAILED_NOSECTION,
	CIBRES_FAILED_NOOBJECT,
	CIBRES_FAILED_NOPARENT,
	CIBRES_FAILED_NODECOPY,
	CIBRES_FAILED_NOTSUPPORTED,
};


/* Core functions */
extern gboolean   startCib(const char *filename);
extern xmlNodePtr get_cib_copy(void);
extern xmlNodePtr cib_get_generation(void);
extern int compare_cib_generation(xmlNodePtr left, xmlNodePtr right);
extern xmlNodePtr process_cib_message(xmlNodePtr message, gboolean auto_reply);
extern xmlNodePtr process_cib_request(const char *op,
				      const xmlNodePtr options,
				      const xmlNodePtr fragment);

/* Utility functions */
extern xmlNodePtr get_object_root(const char *object_type,xmlNodePtr the_root);
extern xmlNodePtr create_cib_fragment_adv(
			xmlNodePtr update, const char *section, const char *source);
extern char      *pluralSection(const char *a_section);

/* Error Interpretation*/
extern const char *cib_error2string(enum cib_result);
extern const char *cib_op2string(enum cib_op);

#define create_cib_fragment(x,y) create_cib_fragment_adv(x, y, __FUNCTION__)


#endif
