/* $Id: cib.c,v 1.23 2004/03/26 13:38:25 andrew Exp $ */
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


#include <crm/crm.h>

#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <clplumbing/cl_log.h>
#include <libxml/tree.h>

#include <crm/msg_xml.h>

#include <crm/common/xmlutils.h>
#include <crm/common/msgutils.h>
#include <crm/cib.h>
#include <cibio.h>
#include <cibmessages.h>

#include <crm/dmalloc_wrapper.h>

gboolean
startCib(const char *filename)
{
	xmlNodePtr cib = readCibXmlFile(filename);
	if (initializeCib(cib)) {
		cl_log(LOG_INFO,
		       "CIB Initialization completed successfully");
	} else { 
		free_xml(cib);
		cl_log(LOG_WARNING,
		       "CIB Initialization failed, "
		       "starting with an empty default.");
		activateCibXml(createEmptyCib(), filename);
	}
	return TRUE;
}


xmlNodePtr
get_cib_copy()
{
	return copy_xml_node_recursive(get_the_CIB(), 1);
}

/*
 * The caller should never free the return value
 */
xmlNodePtr
get_object_root(const char *object_type, xmlNodePtr the_root)
{
	const char *node_stack[2];
	xmlNodePtr tmp_node = NULL;
	FNIN();
	
	node_stack[0] = XML_CIB_TAG_CONFIGURATION;
	node_stack[1] = object_type;

	if(object_type == NULL || strlen(object_type) == 0) {
		FNRET(the_root);
		/* get the whole cib */
	} else if(strcmp(object_type, XML_CIB_TAG_STATUS) == 0) {
		node_stack[0] = XML_CIB_TAG_STATUS;
		node_stack[1] = NULL;
		/* these live in a different place */
	}
	
	tmp_node = find_xml_node_nested(the_root, node_stack, 2);
	if (tmp_node == NULL) {
		cl_log(LOG_ERR,
		       "[cib] Section cib[%s[%s]] not present",
		       node_stack[0],
		       node_stack[1]);
	}
	FNRET(tmp_node);
}

FILE *msg_cib_strm = NULL;

xmlNodePtr
process_cib_message(xmlNodePtr message, gboolean auto_reply)
{
	enum cib_result result = CIBRES_OK;
	xmlNodePtr fragment = find_xml_node(message, XML_TAG_FRAGMENT);
	xmlNodePtr options  = find_xml_node(message, XML_TAG_OPTIONS);
	const char *op      = get_xml_attr(options, NULL, XML_ATTR_OP, TRUE);

#ifdef MSG_LOG
	if(msg_cib_strm == NULL) {
		msg_cib_strm = fopen("/tmp/cib.log", "w");
	}
	fprintf(msg_cib_strm, "[Input ]\t%s\n", dump_xml_node(message, FALSE));
	fflush(msg_cib_strm);
#endif
	
	xmlNodePtr data = cib_process_request(op, options, fragment, &result);

	CRM_DEBUG2("[cib] operation returned result %d", result);

	if(auto_reply) {

		xmlNodePtr reply = create_reply(message, data);
		free_xml(data);

#ifdef MSG_LOG
		fprintf(msg_cib_strm, "[Reply ]\t%s\n",
			dump_xml_node(reply, FALSE));
		fflush(msg_cib_strm);
#endif
		set_xml_attr(reply, XML_TAG_OPTIONS,
			     XML_ATTR_RESULT, "ok", TRUE); // put real result in here
		
		return reply;

	}
	
#ifdef MSG_LOG
	fprintf(msg_cib_strm, "[Output]\t%s\n", dump_xml_node(data, FALSE));
	fflush(msg_cib_strm);
#endif
	return data;
}

xmlNodePtr
process_cib_request(const char *op,
		    const xmlNodePtr options,
		    const xmlNodePtr fragment)
{
	enum cib_result result = CIBRES_OK;

	return cib_process_request(op, fragment, options, &result);
}


xmlNodePtr
create_cib_fragment(xmlNodePtr update, const char *section)
{
	gboolean whole_cib = FALSE;
	xmlNodePtr fragment = create_xml_node(NULL, XML_TAG_FRAGMENT);
	xmlNodePtr cib = NULL;
	char *auto_section = pluralSection(update->name);
	
	if(update == NULL) {
		cl_log(LOG_ERR, "No update to create a fragment for");
		ha_free(auto_section);
		return NULL;
		
	} else if(section == NULL) {
		section = auto_section;

	} else if(strcmp(auto_section, section) != 0) {
		cl_log(LOG_ERR,
		       "Values for update (tag=%s) and section (%s)"
		       " were not consistent", update->name, section);
		ha_free(auto_section);
		return NULL;
		
	}

	if(strcmp(section, "all")==0 && strcmp(update->name, XML_TAG_CIB)==0) {
		whole_cib = TRUE;
	}
	
	
	set_xml_property_copy(fragment, XML_ATTR_SECTION, section);

	if(whole_cib == FALSE) {
		cib = createEmptyCib();
		xmlNodePtr object_root = get_object_root(section, cib);
		xmlAddChild(object_root, update);
	} else {
		cib = update;
	}
	
	xmlAddChild(fragment, cib);
	CRM_DEBUG("Fragment created");

	ha_free(auto_section);
	return fragment;
}


char *
pluralSection(const char *a_section)
{
	char *a_section_parent = NULL;
	if (a_section == NULL) {
		a_section_parent = ha_strdup("all");

	} else if(strcmp(a_section, XML_TAG_CIB) == 0) {
		a_section_parent = ha_strdup("all");

	} else if(strcmp(a_section, "node") == 0) {
		a_section_parent = ha_strdup("nodes");

	} else if(strcmp(a_section, "state") == 0) {
		a_section_parent = ha_strdup("status");

	} else if(strcmp(a_section, "constraint") == 0) {
		a_section_parent = ha_strdup("constraints");
		
	} else if(strcmp(a_section, "resource") == 0) {
		a_section_parent = ha_strdup("resources");

	} else {
		cl_log(LOG_ERR, "Unknown section %s", a_section);
		a_section_parent = ha_strdup("all");
	}
	
	CRM_DEBUG2("Plural is %s", a_section_parent);
	return a_section_parent;
}

const char *
cib_error2string(enum cib_result return_code)
{
	const char *error_msg = NULL;
	switch(return_code) {
		case CIBRES_MISSING_ID:
			error_msg = "The id field is missing";
			break;
		case CIBRES_MISSING_TYPE:
			error_msg = "The type field is missing";
			break;
		case CIBRES_MISSING_FIELD:
			error_msg = "A required field is missing";
			break;
		case CIBRES_OBJTYPE_MISMATCH:
			error_msg = "CIBRES_OBJTYPE_MISMATCH";
			break;
		case CIBRES_FAILED_EXISTS:
			error_msg = "The object already exists";
			break;
		case CIBRES_FAILED_NOTEXISTS:
			error_msg = "The object does not exist";
			break;
		case CIBRES_CORRUPT:
			error_msg = "The CIB is corrupt";
			break;
		case CIBRES_FAILED_NOOBJECT:
			error_msg = "The update was empty";
			break;
		case CIBRES_FAILED_NOPARENT:
			error_msg = "The parent object does not exist";
			break;
		case CIBRES_FAILED_NODECOPY:
			error_msg = "Failed while copying update";
			break;
		case CIBRES_OTHER:
			error_msg = "CIBRES_OTHER";
			break;
		case CIBRES_OK:
			error_msg = "ok";
			break;
		case CIBRES_FAILED:
			error_msg = "Failed";
			break;
		case CIBRES_FAILED_STALE:
			error_msg = "Discarded old update";
			break;
		case CIBRES_FAILED_ACTIVATION:
			error_msg = "Activation Failed";
			break;
		case CIBRES_FAILED_NOSECTION:
			error_msg = "Required section was missing";
			break;
		case CIBRES_FAILED_NOTSUPPORTED:
			error_msg = "Supplied information is not supported";
			break;
	}
			
	if(error_msg == NULL) {
		cl_log(LOG_ERR, "Unknown CIB Error %d", return_code);
		error_msg = "<unknown error>";
	}
	
	return error_msg;
}

const char *
cib_op2string(enum cib_op operation)
{
	const char *operation_msg = NULL;
	switch(operation) {
		case 0:
			operation_msg = "none";
			break;
		case 1:
			operation_msg = "add";
			break;
		case 2:
			operation_msg = "modify";
			break;
		case 3:
			operation_msg = "delete";
			break;
		case CIB_OP_MAX:
			operation_msg = "invalid operation";
			break;
			
	}

	if(operation_msg == NULL) {
		cl_log(LOG_ERR, "Unknown CIB operation %d", operation);
		operation_msg = "<unknown operation>";
	}
	
	return operation_msg;
}
