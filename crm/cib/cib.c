/* $Id: cib.c,v 1.50 2004/09/04 10:41:55 andrew Exp $ */
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

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <cibio.h>
#include <cibmessages.h>

#include <crm/dmalloc_wrapper.h>

gboolean
startCib(const char *filename)
{
	xmlNodePtr cib = readCibXmlFile(filename);
	if (initializeCib(cib)) {
		crm_info("CIB Initialization completed successfully");
	} else { 
		/* free_xml(cib); */
		crm_warn("CIB Initialization failed, "
			 "starting with an empty default.");
		activateCibXml(createEmptyCib(), filename);
	}
	return TRUE;
}


xmlNodePtr
get_cib_copy()
{
	return copy_xml_node_recursive(get_the_CIB());
}

/*
 * The caller should never free the return value
 */
xmlNodePtr
get_object_root(const char *object_type, xmlNodePtr the_root)
{
	const char *node_stack[2];
	xmlNodePtr tmp_node = NULL;
	
	if(the_root == NULL) {
		crm_err("CIB root object was NULL");
		return NULL;
	}
	
	node_stack[0] = XML_CIB_TAG_CONFIGURATION;
	node_stack[1] = object_type;

	if(object_type == NULL
	   || strlen(object_type) == 0
	   || safe_str_eq("all", object_type)) {
		return the_root;
		/* get the whole cib */

	} else if(strcmp(object_type, XML_CIB_TAG_STATUS) == 0) {
		/* these live in a different place */
		tmp_node = find_xml_node(the_root, XML_CIB_TAG_STATUS);

		node_stack[0] = XML_CIB_TAG_STATUS;
		node_stack[1] = NULL;

	} else if(strcmp(object_type, XML_CIB_TAG_CRMCONFIG) == 0) {
		/* these live in a different place too */
		tmp_node = find_xml_node(the_root, XML_CIB_TAG_CRMCONFIG);

		node_stack[0] = XML_CIB_TAG_CRMCONFIG;
		node_stack[1] = NULL;

	} else {
		tmp_node = find_xml_node_nested(the_root, node_stack, 2);
	}

	if (tmp_node == NULL) {
		crm_err("[cib] Section %s [%s [%s]] not present",
			the_root->name,
			node_stack[0],
			node_stack[1]?node_stack[1]:"");
	}
	return tmp_node;
}

xmlNodePtr
process_cib_message(xmlNodePtr message, gboolean auto_reply)
{
	xmlNodePtr data;
	xmlNodePtr reply;
	enum cib_result result = CIBRES_OK;
	xmlNodePtr fragment = find_xml_node(message, XML_TAG_FRAGMENT);
	xmlNodePtr options  = find_xml_node(message, XML_TAG_OPTIONS);
	const char *section = xmlGetProp(fragment, XML_ATTR_SECTION);
	const char *op      = xmlGetProp(options , XML_ATTR_OP);

	if(section != NULL) {
		set_xml_property_copy(
			options, XML_ATTR_FILTER_TYPE, section);
	}
	
	data = cib_process_request(op, options, fragment, &result);

	crm_info("[cib] operation returned result %d", result);
	crm_debug("[CIB post-op]\t%s\n\n", dump_xml_formatted(message));

	if(auto_reply) {
		reply = create_reply(message, data);
		free_xml(data);

		set_xml_attr(reply, XML_TAG_OPTIONS,
			     XML_ATTR_RESULT, cib_error2string(result), TRUE);

		return reply;
	}
	
	return data;
}

xmlNodePtr
process_cib_request(const char *op,
		    const xmlNodePtr options,
		    const xmlNodePtr fragment)
{
	enum cib_result result = CIBRES_OK;

	const char *section = xmlGetProp(fragment, XML_ATTR_SECTION);

	if(section != NULL) {
		set_xml_property_copy(
			options, XML_ATTR_FILTER_TYPE, section);
	}

	return cib_process_request(op, options, fragment, &result);
}


xmlNodePtr
create_cib_fragment_adv(xmlNodePtr update, const char *section, const char *source)
{
	gboolean whole_cib = FALSE;
	xmlNodePtr fragment = create_xml_node(NULL, XML_TAG_FRAGMENT);
	xmlNodePtr cib = NULL;
	xmlNodePtr object_root  = NULL;
	char *auto_section = pluralSection(update?update->name:NULL);
	
	if(update == NULL) {
		crm_err("No update to create a fragment for");
		crm_free(auto_section);
		return NULL;
		
	} else if(section == NULL) {
		section = auto_section;

	} else if(strcmp(auto_section, section) != 0) {
		crm_err("Values for update (tag=%s) and section (%s)"
			" were not consistent", update->name, section);
		crm_free(auto_section);
		return NULL;
		
	}

	if(strcmp(section, "all")==0 && strcmp(update->name, XML_TAG_CIB)==0) {
		whole_cib = TRUE;
	}
	
	set_xml_property_copy(fragment, XML_ATTR_SECTION, section);

	if(whole_cib == FALSE) {
		cib = createEmptyCib();
		object_root = get_object_root(section, cib);
		xmlAddChildList(object_root, xmlCopyNodeList(update));

	} else {
		cib = xmlCopyNodeList(update);
	}
	
	xmlAddChild(fragment, cib);
	set_xml_property_copy(cib, "debug_source", source);
	
	crm_free(auto_section);

	crm_debug("Verifying created fragment");
	if(verifyCibXml(cib) == FALSE) {
		crm_err("Fragment creation failed");
		crm_err("[src] %s", dump_xml_formatted(update));
		crm_err("[created] %s", dump_xml_formatted(fragment));
		free_xml(fragment);
		fragment = NULL;
	}
	
	

	return fragment;
}


char *
pluralSection(const char *a_section)
{
	char *a_section_parent = NULL;
	if (a_section == NULL) {
		a_section_parent = crm_strdup("all");

	} else if(strcmp(a_section, XML_TAG_CIB) == 0) {
		a_section_parent = crm_strdup("all");

	} else if(strcmp(a_section, XML_CIB_TAG_NODE) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_NODES);

	} else if(strcmp(a_section, XML_CIB_TAG_STATE) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_STATUS);

	} else if(strcmp(a_section, XML_CIB_TAG_CONSTRAINT) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_CONSTRAINTS);
		
	} else if(strcmp(a_section, "rsc_location") == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_CONSTRAINTS);
		
	} else if(strcmp(a_section, "rsc_to_rsc") == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_CONSTRAINTS);
		
	} else if(strcmp(a_section, XML_CIB_TAG_RESOURCE) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_RESOURCES);

	} else if(strcmp(a_section, XML_CIB_TAG_NVPAIR) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_CRMCONFIG);

	} else {
		crm_err("Unknown section %s", a_section);
		a_section_parent = crm_strdup("all");
	}
	
	crm_verbose("Plural is %s", a_section_parent);
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
		crm_err("Unknown CIB Error %d", return_code);
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
		crm_err("Unknown CIB operation %d", operation);
		operation_msg = "<unknown operation>";
	}
	
	return operation_msg;
}
