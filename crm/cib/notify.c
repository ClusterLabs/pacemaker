/* $Id: notify.c,v 1.1 2004/12/05 16:14:07 andrew Exp $ */
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

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <clplumbing/cl_log.h>

#include <time.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/msg.h>
#include <crm/common/xml.h>
#include <cibio.h>
#include <notify.h>

#include <crm/dmalloc_wrapper.h>

FILE *msg_cib_strm = NULL;

void
cib_pre_notify(
	const char *op,  const char *type, const char *id, xmlNodePtr update) 
{
	char *xml_text = NULL;

	if(update == NULL) {
		crm_verbose("Performing oeration %s (on section=%s)", op, type);

	} else {
		crm_verbose("Performing %s on <%s %s%s>",
			    op, type, id?"id=":"", id);
	}
	
	if(msg_cib_strm == NULL) {
		msg_cib_strm = fopen(DEVEL_DIR"/cib.log", "w");
	}

	xml_text = dump_xml_formatted(update);
	fprintf(msg_cib_strm, "[Request (%s : %s : %s)]\t%s\n",
		op, crm_str(type), crm_str(id), xml_text);
	crm_free(xml_text);

	xml_text = dump_xml_formatted(get_the_CIB());
	fprintf(msg_cib_strm, "[CIB before %s]\t%s\n", op, xml_text);
	crm_free(xml_text);

	fflush(msg_cib_strm);
}

void
cib_post_notify(
	const char *op,  const char *type, const char *id, xmlNodePtr update,
	enum cib_errors result, xmlNodePtr new_obj) 
{
	char *xml_text = NULL;

	if(update == NULL) {
		if(result == cib_ok) {
			crm_verbose("Operation %s (on section=%s) completed",
				    op, type);
			
		} else {
			crm_warn("Operation %s (on section=%s) FAILED: (%d) %s",
				 op, type, result, cib_error2string(result));
		}
		
	} else {
		if(result == cib_ok) {
			crm_verbose("Completed %s of <%s %s%s>",
				    op, type, id?"id=":"", id);
			
		} else {
			crm_warn("%s of <%s %s%s> FAILED: %s", op, type,
				 id?"id=":"", id, cib_error2string(result));
		}
	}
	
	if(msg_cib_strm == NULL) {
		msg_cib_strm = fopen(DEVEL_DIR"/cib.log", "w");
	}

	if(new_obj != NULL) {
		xml_text = dump_xml_formatted(new_obj);
	}
	
	fprintf(msg_cib_strm, "[Response (%s : %s : %s)]\t%s\n%s\n",
		op, crm_str(type), crm_str(id),
		cib_error2string(result), xml_text);
	crm_free(xml_text);

	fflush(msg_cib_strm);
}
